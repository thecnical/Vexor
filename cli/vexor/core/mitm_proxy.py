"""
Vexor MITM Proxy — Full HTTPS Interception
Generates a local CA certificate, signs per-host certificates on-the-fly,
wraps CONNECT tunnels in TLS, and feeds decrypted traffic to the main proxy
engine for match/replace, history, passive scanning, and intercept mode.

Install CA cert in your browser/OS to avoid certificate warnings:
  ~/.vexor/ca/vexor_ca.crt

Requires: cryptography>=41.0
"""
import asyncio
import ssl
import socket
import datetime
import ipaddress
import os
import collections
from pathlib import Path
from typing import Optional, Dict, Callable

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from vexor.config import HOME_DIR

CA_DIR  = HOME_DIR / "ca"
CA_KEY  = CA_DIR / "vexor_ca.key"
CA_CERT = CA_DIR / "vexor_ca.crt"
CERT_CACHE_DIR = CA_DIR / "hosts"


# ─── CA Generation ────────────────────────────────────────────────────────────

def generate_ca() -> None:
    """Generate a local CA key + self-signed certificate (done once)."""
    if not HAS_CRYPTO:
        raise RuntimeError(
            "HTTPS MITM requires the 'cryptography' package. "
            "Run: pip install cryptography"
        )

    CA_DIR.mkdir(parents=True, exist_ok=True)
    CERT_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Self-signed CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vexor Security Toolkit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Vexor Local CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Write to disk
    CA_KEY.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CA_CERT.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))


def _get_or_create_host_cert(host: str) -> tuple[Path, Path]:
    """
    Return (cert_path, key_path) for a given hostname.
    Issues a new cert signed by the Vexor CA if one doesn't exist.
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required for MITM")

    safe = host.replace("*", "_wildcard_").replace(":", "_")
    cert_path = CERT_CACHE_DIR / f"{safe}.crt"
    key_path  = CERT_CACHE_DIR / f"{safe}.key"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    # Load CA
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    ca_key_obj  = load_pem_private_key(CA_KEY.read_bytes(), password=None, backend=default_backend())
    ca_cert_obj = x509.load_pem_x509_certificate(CA_CERT.read_bytes(), default_backend())

    # Generate host key
    host_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
    ])

    # Build SAN
    san_entries = [x509.DNSName(host)]
    if not host.startswith("*"):
        san_entries.append(x509.DNSName(f"*.{host}"))
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        pass

    host_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert_obj.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key_obj, hashes.SHA256(), default_backend())
    )

    cert_path.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        host_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    return cert_path, key_path


def _build_server_ssl_ctx(host: str) -> ssl.SSLContext:
    """Build an SSLContext with a host-specific cert signed by the Vexor CA."""
    cert_path, key_path = _get_or_create_host_cert(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def _build_client_ssl_ctx() -> ssl.SSLContext:
    """Build an SSLContext for outbound connections (verify real server cert)."""
    ctx = ssl.create_default_context()
    return ctx


# ─── MITM Proxy Handler ───────────────────────────────────────────────────────

class VexorMITMProxy:
    """
    Full HTTPS MITM Proxy Engine.
    Intercepts CONNECT tunnels, presents a per-host TLS certificate to the
    client, connects to the real server with TLS, and passes decrypted
    HTTP traffic through the Vexor proxy engine for analysis.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None,
    ):
        if not HAS_CRYPTO:
            raise RuntimeError(
                "HTTPS MITM requires 'cryptography' package. "
                "Run: pip install cryptography>=41.0"
            )

        self.host = host
        self.port = port
        self.on_request  = on_request
        self.on_response = on_response

        # Ensure CA exists
        if not CA_CERT.exists() or not CA_KEY.exists():
            generate_ca()

        self._running = False
        self._server  = None
        self._counter = 0
        self._history: collections.deque = collections.deque(maxlen=10000)

        # Import proxy engine for traffic processing
        from vexor.core.proxy import VexorProxy, RequestData, RequestHistory
        self._proxy_engine = VexorProxy(
            host=host,
            port=port,
            on_request=on_request,
        )

    @property
    def ca_cert_path(self) -> Path:
        return CA_CERT

    @property
    def history(self):
        return self._proxy_engine.history

    @property
    def intercept_enabled(self) -> bool:
        return self._proxy_engine.intercept_enabled

    @intercept_enabled.setter
    def intercept_enabled(self, value: bool):
        self._proxy_engine.intercept_enabled = value

    def forward(self, req_id: int) -> None:
        self._proxy_engine.forward(req_id)

    def drop(self, req_id: int) -> None:
        self._proxy_engine.drop(req_id)

    async def start(self) -> None:
        """Start the MITM proxy server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )
        self._running = True

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False

    def is_running(self) -> bool:
        return self._running

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming proxy connection."""
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not first_line:
                return

            request_text = first_line.decode("utf-8", errors="replace")
            parts = request_text.strip().split(" ")
            if len(parts) < 2:
                return

            method  = parts[0].upper()
            target  = parts[1]

            # Read headers
            headers_raw = b""
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                headers_raw += line
                if line in (b"\r\n", b"\n", b""):
                    break

            headers = self._parse_headers(headers_raw.decode("utf-8", errors="replace"))

            if method == "CONNECT":
                # HTTPS: do MITM
                await self._handle_mitm_connect(target, reader, writer, headers)
            else:
                # Plain HTTP: forward to proxy engine
                body = b""
                content_length = int(headers.get("Content-Length", headers.get("content-length", 0)))
                if content_length > 0:
                    body = await asyncio.wait_for(reader.read(content_length), timeout=15)

                await self._proxy_engine._handle_http(
                    method, target, headers, body, reader, writer
                )

        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_mitm_connect(
        self,
        host_port: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: dict,
    ) -> None:
        """
        Full HTTPS MITM:
        1. Acknowledge CONNECT
        2. Wrap client connection in TLS with per-host cert
        3. Open TLS connection to real server
        4. Relay decrypted HTTP through proxy engine
        """
        # Parse host:port
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 443

        # Step 1: Acknowledge the CONNECT
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Step 2: Wrap client connection with our spoofed TLS cert
        try:
            server_ctx = _build_server_ssl_ctx(host)
            tls_writer, tls_reader = None, None

            # Upgrade existing stream to TLS
            loop = asyncio.get_event_loop()
            transport = writer.transport
            protocol  = writer.protocol

            # Use asyncio SSL upgrade
            ssl_transport, ssl_protocol = await loop.create_connection(
                lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader()),
                sock=transport.get_extra_info("socket").dup(),
                ssl=server_ctx,
                server_side=True,
            )
            tls_reader = ssl_protocol._stream_reader
            tls_writer = asyncio.StreamWriter(ssl_transport, ssl_protocol, tls_reader, loop)

        except Exception:
            # Fallback: transparent tunnel if MITM fails (e.g., non-HTTP protocol)
            await self._transparent_tunnel(host, port, reader, writer)
            return

        # Step 3: Connect to real server with TLS
        try:
            client_ctx = _build_client_ssl_ctx()
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=client_ctx, server_hostname=host),
                timeout=15,
            )
        except Exception:
            return

        # Step 4: Read decrypted HTTP from client, process via proxy engine, forward
        try:
            while True:
                first_line = await asyncio.wait_for(tls_reader.readline(), timeout=30)
                if not first_line:
                    break

                req_parts = first_line.decode("utf-8", errors="replace").strip().split(" ")
                if len(req_parts) < 2:
                    break

                method = req_parts[0]
                path   = req_parts[1]

                headers_raw = b""
                while True:
                    line = await asyncio.wait_for(tls_reader.readline(), timeout=5)
                    headers_raw += line
                    if line in (b"\r\n", b"\n", b""):
                        break

                hdrs = self._parse_headers(headers_raw.decode("utf-8", errors="replace"))
                hdrs["Host"] = hdrs.get("Host", host)

                content_length = int(hdrs.get("Content-Length", hdrs.get("content-length", 0)))
                body = b""
                if content_length > 0:
                    body = await asyncio.wait_for(tls_reader.read(content_length), timeout=30)

                # Record and analyze via proxy engine
                self._counter += 1
                import time
                from vexor.core.proxy import RequestData
                req_data = RequestData(
                    id=self._counter,
                    method=method,
                    host=host,
                    path=path,
                    url=f"https://{host}{path}",
                    headers=hdrs,
                    body=body,
                    timestamp=time.strftime("%H:%M:%S"),
                    body_format=self._proxy_engine._detect_body_format(hdrs, body),
                    interesting_params=self._proxy_engine._find_interesting_params(path, body, hdrs),
                    auth_tokens=self._proxy_engine._find_auth_tokens(hdrs, body),
                )

                # Apply match & replace rules
                self._proxy_engine.apply_request_rules(req_data.raw_request())

                # Intercept if enabled
                if self.intercept_enabled:
                    loop = asyncio.get_event_loop()
                    future = loop.create_future()
                    self._proxy_engine._intercept_decisions[self._counter] = future
                    await self._proxy_engine._intercept_queue.put(req_data)
                    try:
                        action = await asyncio.wait_for(future, timeout=300)
                    except asyncio.TimeoutError:
                        action = "forward"
                    finally:
                        self._proxy_engine._intercept_decisions.pop(self._counter, None)

                    if action == "drop":
                        self._proxy_engine.history.add(req_data)
                        continue

                # Forward to real server
                req_line = f"{method} {path} HTTP/1.1\r\n"
                hdr_str  = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
                remote_writer.write((req_line + hdr_str + "\r\n").encode() + body)
                await remote_writer.drain()

                # Read response
                status_line = await asyncio.wait_for(remote_reader.readline(), timeout=15)
                status_parts = status_line.decode("utf-8", errors="replace").strip().split(" ", 2)
                status_code  = int(status_parts[1]) if len(status_parts) > 1 else 200

                resp_headers = {}
                while True:
                    h_line = await asyncio.wait_for(remote_reader.readline(), timeout=5)
                    if h_line in (b"\r\n", b"\n", b""):
                        break
                    if b":" in h_line:
                        k, v = h_line.decode("utf-8", errors="replace").split(":", 1)
                        resp_headers[k.strip()] = v.strip()

                resp_body = await asyncio.wait_for(remote_reader.read(4 * 1024 * 1024), timeout=30)

                # Apply match & replace to response
                resp_text    = resp_body.decode("utf-8", errors="replace")
                modified_resp = self._proxy_engine.apply_response_rules(resp_text)
                resp_body_out = modified_resp.encode("utf-8", errors="replace")

                # Update request record with response data
                req_data.status_code     = status_code
                req_data.response_headers = resp_headers
                req_data.response_body   = resp_body
                req_data.response_length = len(resp_body)
                req_data.mime_type = resp_headers.get("Content-Type", "").split(";")[0]

                self._proxy_engine.history.add(req_data)

                # Passive scan for interesting findings
                if self.on_response:
                    try:
                        self.on_response(req_data)
                    except Exception:
                        pass

                if self.on_request:
                    try:
                        self.on_request(req_data.to_dict())
                    except Exception:
                        pass

                # Send response back to client via TLS
                resp_line = f"HTTP/1.1 {status_code} OK\r\n"
                resp_hdr  = "".join(f"{k}: {v}\r\n" for k, v in resp_headers.items())
                tls_writer.write((resp_line + resp_hdr + "\r\n").encode() + resp_body_out)
                await tls_writer.drain()

        except Exception:
            pass
        finally:
            try:
                remote_writer.close()
            except Exception:
                pass

    async def _transparent_tunnel(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Fallback transparent CONNECT tunnel when MITM is not possible."""
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15
            )

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(r.read(4096), timeout=30)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass

            await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
            remote_writer.close()
        except Exception:
            pass

    @staticmethod
    def _parse_headers(raw: str) -> dict:
        headers = {}
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers


# ─── Quick install helper ──────────────────────────────────────────────────────

def install_ca_instructions() -> str:
    """Return OS-specific instructions for trusting the Vexor CA cert."""
    import platform
    system = platform.system()
    cert = str(CA_CERT)
    if system == "Darwin":
        return (
            f"macOS: sudo security add-trusted-cert -d -r trustRoot "
            f"-k /Library/Keychains/System.keychain {cert}"
        )
    elif system == "Linux":
        return (
            f"Linux (Debian/Ubuntu): sudo cp {cert} /usr/local/share/ca-certificates/vexor_ca.crt "
            f"&& sudo update-ca-certificates\n"
            f"Linux (RHEL/Fedora): sudo cp {cert} /etc/pki/ca-trust/source/anchors/ "
            f"&& sudo update-ca-trust"
        )
    elif system == "Windows":
        return f"Windows: certutil -addstore -f Root {cert}"
    return f"Import {cert} into your browser/OS trust store as a CA certificate."