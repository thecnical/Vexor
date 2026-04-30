"""
Vexor CORS Misconfiguration Scanner
"""
from vexor.modules.base import BaseScanner, Finding


TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://target.com.evil.com",
]


class Scanner(BaseScanner):
    """CORS Misconfiguration Scanner"""

    MODULE_NAME = "cors"
    MODULE_DESC = "CORS Misconfiguration Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            for origin in TEST_ORIGINS:
                await self._test_cors(origin)
        return self.findings

    async def _test_cors(self, origin: str) -> None:
        response = await self.get(
            self.target,
            headers={"Origin": origin}
        )
        if not response:
            return

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            self.add_finding(Finding(
                severity="LOW",
                module=self.MODULE_NAME,
                vuln="CORS: Wildcard Origin",
                endpoint=self.target,
                evidence=f"Access-Control-Allow-Origin: *",
                description="CORS allows all origins — acceptable for public APIs",
                remediation="Restrict to specific trusted origins if handling sensitive data",
            ))

        elif acao == origin and origin != "null":
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln="CORS: Arbitrary Origin Reflected",
                endpoint=self.target,
                evidence=(
                    f"Origin: {origin}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac}"
                ),
                description=(
                    f"Server reflects arbitrary origin '{origin}'. "
                    + ("With credentials=true this is critical!" if acac.lower() == "true" else "")
                ),
                remediation="Validate Origin against a whitelist of trusted domains",
            ))

        elif acao and "null" in acao:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="CORS: Null Origin Allowed",
                endpoint=self.target,
                evidence=f"Access-Control-Allow-Origin: null",
                description="Null origin is allowed — can be exploited via sandboxed iframes",
                remediation="Do not allow null origin in CORS policy",
            ))
