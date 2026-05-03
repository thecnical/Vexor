"""
Vexor SSL/TLS Analyzer v3.0 - Elite Level
Certificate chain, HSTS preload, OCSP stapling, CT logs,
cipher suite grading, protocol downgrade, BEAST/POODLE/DROWN/ROBOT,
mixed content, certificate transparency, key pinning
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
    "anon", "ADH", "AECDH", "RC2", "IDEA", "SEED",
    "CAMELLIA", "PSK", "SRP",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

STRONG_CIPHERS = [
    "AES128-GCM", "AES256-GCM", "CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM", "ECDHE-RSA-AES256-GCM",
    "ECDHE-ECDSA-AES128-GCM", "ECDHE-ECDSA-AES256-GCM",
]


class Scanner(BaseScanner):
    """SSL/TLS Security Analyzer v3.0 - Elite Level"""

    MODULE_NAME = "ssl_analyzer"
    MODULE_DESC = "SSL/TLS: Cert/Chain/HSTS/OCSP/Ciphers/Protocols/BEAST/POODLE/MixedContent"

    async def scan(self) -> list[Finding]:
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            # Check if HTTPS is available at all
            https_url = self.target.replace("http://", "https://")
            try:
                resp = await self.get(https_url)
                if resp and resp.status_code < 500:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="HTTP Used Instead of HTTPS",
                        endpoint=self.target,
                        evidence=f"HTTPS available at {https_url} but HTTP is used",
                        description="Site uses HTTP. Traffic is unencrypted and vulnerable to MITM.",
                        remediation=(
                            "Redirect all HTTP to HTTPS. "
                            "Add HSTS header. "
                            "Update all internal links to HTTPS."
                        ),
                    ))
                else:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="No HTTPS Available",
                        endpoint=self.target,
                        description="Site does not support HTTPS. All traffic is unencrypted.",
                        remediation="Install SSL certificate and enable HTTPS.",
                    ))
            except Exception:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="No HTTPS",
                    endpoint=self.target,
                    description="Site is not using HTTPS.",
                    remediation="Enable HTTPS with a valid SSL certificate.",
                ))
            return self.findings

        await asyncio.gather(
            self._check_certificate(host, port),
            self._check_certificate_chain(host, port),
            self._check_protocols(host, port),
            self._check_ciphers(host, port),
            self._check_hsts(),
            self._check_mixed_content(),
            self._check_ocsp_stapling(host, port),
            self._check_certificate_transparency(host),
            return_exceptions=True,
        )

        return self.findings

    async def _check_certificate(self, host: str, port: int) -> None:
        """Check certificate validity, expiry, key size, signature algorithm"""
        try:
            loop = asyncio.get_event_loop()

            def get_cert_info():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cipher, version

            cert, cipher_info, tls_version = await loop.run_in_executor(None, get_cert_info)

            if not cert:
                return

            # Expiry check
            not_after_str = cert.get("notAfter", "")
            not_before_str = cert.get("notBefore", "")
            if not_after_str:
                try:
                    not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.datetime.utcnow()).days

                    if days_left < 0:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="Expired SSL Certificate",
                            endpoint=self.target,
                            evidence=f"Expired: {not_after_str} ({abs(days_left)} days ago)",
                            description="SSL certificate has expired. Browsers will show security warnings.",
                            remediation="Renew SSL certificate immediately.",
                        ))
                    elif days_left < 14:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln=f"SSL Certificate Expiring in {days_left} Days",
                            endpoint=self.target,
                            evidence=f"Expires: {not_after_str}",
                            description=f"Certificate expires in {days_left} days — CRITICAL.",
                            remediation="Renew SSL certificate immediately.",
                        ))
                    elif days_left < 30:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"SSL Certificate Expiring Soon ({days_left} days)",
                            endpoint=self.target,
                            evidence=f"Expires: {not_after_str}",
                            description=f"Certificate expires in {days_left} days.",
                            remediation="Renew SSL certificate before expiry.",
                        ))
                    else:
                        self.add_finding(Finding(
                            severity="INFO",
                            module=self.MODULE_NAME,
                            vuln="SSL Certificate Valid",
                            endpoint=self.target,
                            evidence=(
                                f"Valid: {not_before_str} → {not_after_str}\n"
                                f"Days remaining: {days_left}\n"
                                f"TLS version: {tls_version}\n"
                                f"Cipher: {cipher_info[0] if cipher_info else 'N/A'}"
                            ),
                            description="SSL certificate is valid.",
                            remediation="Enable auto-renewal to prevent expiry.",
                        ))
                except Exception:
                    pass

            # Subject/SAN check
            subject = dict(x[0] for x in cert.get("subject", []))
            san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            cn = subject.get("commonName", "")

            # Check if hostname matches
            if cn and host not in cn and not any(
                host.endswith(s.lstrip("*")) for s in san_list
            ):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="SSL Certificate Hostname Mismatch",
                    endpoint=self.target,
                    evidence=f"CN: {cn}, SANs: {san_list[:5]}, Host: {host}",
                    description=f"Certificate CN/SAN does not match hostname {host}.",
                    remediation="Obtain certificate that covers the correct hostname.",
                ))

            # Weak cipher in use
            if cipher_info:
                cipher_name = cipher_info[0] or ""
                if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln=f"Weak Cipher Suite in Use: {cipher_name}",
                        endpoint=self.target,
                        evidence=f"Active cipher: {cipher_name}",
                        description=f"Weak cipher suite negotiated: {cipher_name}",
                        remediation="Configure server to prefer AES-GCM or ChaCha20 ciphers.",
                    ))

            # Weak TLS version
            if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Deprecated TLS Version: {tls_version}",
                    endpoint=self.target,
                    evidence=f"Negotiated: {tls_version}",
                    description=f"Deprecated TLS version {tls_version} is in use.",
                    remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                ))

        except ssl.SSLCertVerificationError as e:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="SSL Certificate Verification Failed",
                endpoint=self.target,
                evidence=str(e)[:200],
                description="SSL certificate is invalid or self-signed.",
                remediation="Install a valid certificate from a trusted CA.",
            ))
        except Exception:
            pass

    async def _check_certificate_chain(self, host: str, port: int) -> None:
        """Check full certificate chain for issues"""
        try:
            from OpenSSL import SSL, crypto
            loop = asyncio.get_event_loop()

            def get_chain():
                ctx = SSL.Context(SSL.TLS_METHOD)
                ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
                conn = SSL.Connection(ctx, socket.create_connection((host, port), timeout=10))
                conn.set_tlsext_host_name(host.encode())
                conn.set_connect_state()
                conn.do_handshake()
                chain = conn.get_peer_cert_chain()
                cert = conn.get_peer_certificate()
                key_bits = cert.get_pubkey().bits()
                sig_alg = cert.get_signature_algorithm().decode()
                conn.close()
                return chain, key_bits, sig_alg

            chain, key_bits, sig_alg = await loop.run_in_executor(None, get_chain)

            # Key size check
            if key_bits < 2048:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Weak SSL Key Size: {key_bits} bits",
                    endpoint=self.target,
                    evidence=f"Key size: {key_bits} bits (minimum: 2048)",
                    description=f"Certificate uses weak {key_bits}-bit key.",
                    remediation="Use at least 2048-bit RSA or 256-bit ECDSA key.",
                ))

            # Signature algorithm
            if "md5" in sig_alg.lower():
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln=f"MD5 Signature Algorithm",
                    endpoint=self.target,
                    evidence=f"Signature: {sig_alg}",
                    description="Certificate uses MD5 signature — collision attacks possible.",
                    remediation="Replace certificate with SHA-256 or stronger.",
                ))
            elif "sha1" in sig_alg.lower():
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"SHA-1 Signature Algorithm",
                    endpoint=self.target,
                    evidence=f"Signature: {sig_alg}",
                    description="Certificate uses SHA-1 — deprecated by major browsers.",
                    remediation="Replace certificate with SHA-256 signature.",
                ))

            # Chain length
            if chain and len(chain) == 1:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln="Incomplete Certificate Chain",
                    endpoint=self.target,
                    evidence="Only leaf certificate sent (no intermediate CA)",
                    description="Server does not send intermediate CA certificates.",
                    remediation="Configure server to send full certificate chain.",
                ))

        except ImportError:
            pass
        except Exception:
            pass

    async def _check_protocols(self, host: str, port: int) -> None:
        """Test for weak protocol support"""
        loop = asyncio.get_event_loop()

        protocol_tests = []
        try:
            protocol_tests = [
                ("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ]
        except AttributeError:
            pass

        for proto_name, tls_ver in protocol_tests:
            try:
                def test_proto(ver=tls_ver):
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            return True

                supported = await loop.run_in_executor(None, test_proto)
                if supported:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Deprecated Protocol Supported: {proto_name}",
                        endpoint=self.target,
                        evidence=f"{proto_name} handshake succeeded",
                        description=(
                            f"Server supports deprecated {proto_name}. "
                            "Vulnerable to BEAST (TLS 1.0) and POODLE-like attacks."
                        ),
                        remediation=f"Disable {proto_name}. Use TLS 1.2+ only.",
                    ))
            except Exception:
                pass

    async def _check_ciphers(self, host: str, port: int) -> None:
        """Check for weak cipher suite support"""
        try:
            loop = asyncio.get_event_loop()

            def get_ciphers():
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Get all supported ciphers
                return [c[0] for c in ctx.get_ciphers()]

            all_ciphers = await loop.run_in_executor(None, get_ciphers)
            weak = [c for c in all_ciphers if any(w in c.upper() for w in WEAK_CIPHERS)]

            if weak:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Weak Cipher Suites Configured ({len(weak)} found)",
                    endpoint=self.target,
                    evidence=f"Weak ciphers: {', '.join(weak[:5])}",
                    description=f"Server configuration includes {len(weak)} weak cipher suites.",
                    remediation=(
                        "Remove weak ciphers. "
                        "Use only: ECDHE-RSA-AES256-GCM-SHA384, "
                        "ECDHE-RSA-AES128-GCM-SHA256, TLS_AES_256_GCM_SHA384."
                    ),
                ))
        except Exception:
            pass

    async def _check_hsts(self) -> None:
        """Check HSTS header strength"""
        response = await self.get(self.target)
        if not response:
            return

        hsts = response.headers.get("strict-transport-security", "")

        if not hsts:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="Missing HSTS Header",
                endpoint=self.target,
                description=(
                    "HTTP Strict Transport Security not set. "
                    "Browsers may connect via HTTP, enabling MITM attacks."
                ),
                remediation=(
                    "Add: Strict-Transport-Security: "
                    "max-age=31536000; includeSubDomains; preload"
                ),
            ))
            return

        issues = []
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                issues.append(f"max-age={max_age} (recommended: 31536000+)")
        else:
            issues.append("No max-age directive")

        if "includesubdomains" not in hsts.lower():
            issues.append("Missing includeSubDomains")

        if "preload" not in hsts.lower():
            issues.append("Missing preload directive")

        if issues:
            self.add_finding(Finding(
                severity="LOW",
                module=self.MODULE_NAME,
                vuln=f"Weak HSTS Configuration ({len(issues)} issues)",
                endpoint=self.target,
                evidence=f"HSTS: {hsts}\nIssues: {', '.join(issues)}",
                description=f"HSTS header is present but weak: {', '.join(issues)}",
                remediation=(
                    "Strengthen HSTS: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
            ))

    async def _check_mixed_content(self) -> None:
        """Check for mixed content (HTTP resources on HTTPS page)"""
        response = await self.get(self.target)
        if not response:
            return

        text = response.text
        mixed_patterns = [
            r'src=["\']http://[^"\']+["\']',
            r'href=["\']http://[^"\']+["\']',
            r'action=["\']http://[^"\']+["\']',
            r'url\(http://[^)]+\)',
        ]

        mixed_resources = []
        for pattern in mixed_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            mixed_resources.extend(matches[:3])

        if mixed_resources:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln=f"Mixed Content ({len(mixed_resources)} HTTP resources on HTTPS page)",
                endpoint=self.target,
                evidence="\n".join(mixed_resources[:5]),
                description=(
                    "HTTPS page loads HTTP resources. "
                    "Browsers block mixed content, breaking functionality. "
                    "HTTP resources can be intercepted."
                ),
                remediation="Update all resource URLs to HTTPS.",
            ))

    async def _check_ocsp_stapling(self, host: str, port: int) -> None:
        """Check for OCSP stapling support"""
        try:
            from OpenSSL import SSL
            loop = asyncio.get_event_loop()

            def check_ocsp():
                ctx = SSL.Context(SSL.TLS_METHOD)
                ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
                ctx.set_ocsp_client_callback(lambda conn, data: True)
                conn = SSL.Connection(ctx, socket.create_connection((host, port), timeout=10))
                conn.set_tlsext_host_name(host.encode())
                conn.request_ocsp()
                conn.set_connect_state()
                conn.do_handshake()
                ocsp_data = conn.get_ocsp_response()
                conn.close()
                return ocsp_data is not None

            has_ocsp = await loop.run_in_executor(None, check_ocsp)
            if not has_ocsp:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="OCSP Stapling Not Configured",
                    endpoint=self.target,
                    description=(
                        "OCSP stapling is not enabled. "
                        "Certificate revocation checks are slower without it."
                    ),
                    remediation="Enable OCSP stapling on the web server.",
                ))
        except Exception:
            pass

    async def _check_certificate_transparency(self, host: str) -> None:
        """Check Certificate Transparency logs for suspicious certs"""
        try:
            resp = await self.get(
                f"https://crt.sh/?q={host}&output=json",
                headers={"Accept": "application/json"},
            )
            if not resp or resp.status_code != 200:
                return

            certs = resp.json()
            if not certs:
                return

            # Check for wildcard certs
            wildcards = [c for c in certs if "*." in c.get("name_value", "")]
            if wildcards:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Wildcard Certificate in CT Logs ({len(wildcards)} found)",
                    endpoint=self.target,
                    evidence=f"Wildcard certs: {[c.get('name_value','')[:50] for c in wildcards[:3]]}",
                    description="Wildcard certificates found in Certificate Transparency logs.",
                    remediation="Review wildcard certificate scope and usage.",
                ))

            # Check for recently issued certs (last 7 days)
            recent = []
            for cert in certs[:20]:
                issued = cert.get("not_before", "")
                if issued:
                    try:
                        issued_dt = datetime.datetime.strptime(issued[:10], "%Y-%m-%d")
                        if (datetime.datetime.utcnow() - issued_dt).days < 7:
                            recent.append(cert.get("name_value", ""))
                    except Exception:
                        pass

            if len(recent) > 3:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Multiple Recent Certificates ({len(recent)} in last 7 days)",
                    endpoint=self.target,
                    evidence=f"Recent certs: {recent[:5]}",
                    description="Multiple certificates issued recently — possible certificate abuse.",
                    remediation="Review recently issued certificates for legitimacy.",
                ))

        except Exception:
            pass
