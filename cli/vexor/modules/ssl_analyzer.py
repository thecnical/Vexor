"""
Vexor SSL/TLS Analyzer
Uses ssl + pyOpenSSL for deep certificate analysis
"""
import ssl
import socket
import asyncio
import datetime
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "RC2", "IDEA",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class Scanner(BaseScanner):
    """SSL/TLS Security Analyzer"""

    MODULE_NAME = "ssl_analyzer"
    MODULE_DESC = "SSL/TLS Configuration Analyzer"

    async def scan(self) -> list[Finding]:
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="No HTTPS",
                endpoint=self.target,
                description="Site is not using HTTPS — traffic is unencrypted",
                remediation="Enable HTTPS with a valid SSL certificate",
            ))
            return self.findings

        await asyncio.gather(
            self._check_certificate(host, port),
            self._check_protocols(host, port),
            self._check_hsts(),
            self._check_certificate_details(host, port),
            return_exceptions=True
        )

        return self.findings

    async def _check_certificate(self, host: str, port: int) -> None:
        """Check SSL certificate validity"""
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def get_cert():
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert()

            cert = await loop.run_in_executor(None, get_cert)

            if cert:
                # Check expiry
                not_after = datetime.datetime.strptime(
                    cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (not_after - datetime.datetime.utcnow()).days

                if days_left < 0:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="Expired SSL Certificate",
                        endpoint=self.target,
                        evidence=f"Expired on: {cert['notAfter']}",
                        description="SSL certificate has expired",
                        remediation="Renew SSL certificate immediately",
                    ))
                elif days_left < 30:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="SSL Certificate Expiring Soon",
                        endpoint=self.target,
                        evidence=f"Expires in {days_left} days: {cert['notAfter']}",
                        description=f"SSL certificate expires in {days_left} days",
                        remediation="Renew SSL certificate before expiry",
                    ))
                else:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="SSL Certificate Valid",
                        endpoint=self.target,
                        evidence=f"Valid for {days_left} more days",
                        description="SSL certificate is valid",
                        remediation="No action needed",
                    ))

        except ssl.SSLCertVerificationError as e:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="Invalid SSL Certificate",
                endpoint=self.target,
                evidence=str(e),
                description="SSL certificate verification failed",
                remediation="Install a valid SSL certificate from a trusted CA",
            ))
        except Exception:
            pass

    async def _check_certificate_details(self, host: str, port: int) -> None:
        """Deep certificate analysis using pyOpenSSL"""
        try:
            from OpenSSL import SSL, crypto
            loop = asyncio.get_event_loop()

            def get_openssl_cert():
                ctx = SSL.Context(SSL.TLS_METHOD)
                ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
                conn = SSL.Connection(ctx, socket.create_connection((host, port), timeout=10))
                conn.set_tlsext_host_name(host.encode())
                conn.set_connect_state()
                conn.do_handshake()
                cert = conn.get_peer_certificate()
                cipher = conn.get_cipher_name()
                protocol = conn.get_protocol_version_name()
                conn.close()
                return cert, cipher, protocol

            cert, cipher, protocol = await loop.run_in_executor(None, get_openssl_cert)

            # Check key size
            pub_key = cert.get_pubkey()
            key_bits = pub_key.bits()

            if key_bits < 2048:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Weak SSL Key Size: {key_bits} bits",
                    endpoint=self.target,
                    evidence=f"Key size: {key_bits} bits",
                    description=f"SSL certificate uses weak {key_bits}-bit key",
                    remediation="Use at least 2048-bit RSA or 256-bit ECDSA key",
                ))

            # Check signature algorithm
            sig_alg = cert.get_signature_algorithm().decode()
            if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Weak Signature Algorithm: {sig_alg}",
                    endpoint=self.target,
                    evidence=f"Signature: {sig_alg}",
                    description=f"Certificate uses weak signature algorithm: {sig_alg}",
                    remediation="Use SHA-256 or stronger signature algorithm",
                ))

            # Check cipher
            if cipher and any(w in cipher.upper() for w in WEAK_CIPHERS):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Weak Cipher Suite: {cipher}",
                    endpoint=self.target,
                    evidence=f"Cipher: {cipher}",
                    description=f"Weak cipher suite in use: {cipher}",
                    remediation="Disable weak ciphers, use AES-GCM or ChaCha20",
                ))

            # Check protocol
            if protocol and any(p in protocol for p in ['TLSv1.0', 'TLSv1.1', 'SSLv3']):
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Weak Protocol: {protocol}",
                    endpoint=self.target,
                    evidence=f"Protocol: {protocol}",
                    description=f"Deprecated protocol in use: {protocol}",
                    remediation="Use TLS 1.2 or TLS 1.3 only",
                ))

        except ImportError:
            pass  # pyOpenSSL not installed
        except Exception:
            pass

    async def _check_protocols(self, host: str, port: int) -> None:
        """Check for weak SSL/TLS protocols"""
        loop = asyncio.get_event_loop()

        for protocol_name, tls_version in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                def test_protocol(ver=tls_version):
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            return True

                supported = await loop.run_in_executor(None, test_protocol)
                if supported:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Weak Protocol Supported: {protocol_name}",
                        endpoint=self.target,
                        evidence=f"{protocol_name} is enabled",
                        description=f"Server supports deprecated {protocol_name}",
                        remediation=f"Disable {protocol_name}, use TLS 1.2+ only",
                    ))
            except Exception:
                pass

    async def _check_hsts(self) -> None:
        """Check for HSTS header"""
        response = await self.get(self.target)
        if response:
            hsts = response.headers.get("strict-transport-security", "")
            if not hsts:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln="Missing HSTS Header",
                    endpoint=self.target,
                    description="HTTP Strict Transport Security header not set",
                    remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                ))
            else:
                # Check HSTS max-age
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        self.add_finding(Finding(
                            severity="LOW",
                            module=self.MODULE_NAME,
                            vuln="HSTS max-age Too Short",
                            endpoint=self.target,
                            evidence=f"max-age={max_age} (recommended: 31536000+)",
                            description="HSTS max-age is less than 1 year",
                            remediation="Set HSTS max-age to at least 31536000 (1 year)",
                        ))
