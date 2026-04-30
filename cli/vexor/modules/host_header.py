"""
Vexor Host Header Injection Scanner
Detects: Password reset poisoning, cache poisoning via Host header
"""
import asyncio
import re
from vexor.modules.base import BaseScanner, Finding


EVIL_HOST = "evil-vexor-test.com"

TEST_HEADERS = [
    {"Host": EVIL_HOST},
    {"Host": f"target.com@{EVIL_HOST}"},
    {"Host": f"{EVIL_HOST}:80"},
    {"X-Forwarded-Host": EVIL_HOST},
    {"X-Host": EVIL_HOST},
    {"X-Forwarded-Server": EVIL_HOST},
    {"X-HTTP-Host-Override": EVIL_HOST},
    {"Forwarded": f"host={EVIL_HOST}"},
]


class Scanner(BaseScanner):
    """Host Header Injection Scanner"""

    MODULE_NAME = "host_header"
    MODULE_DESC = "Host Header Injection Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_host_injection(),
                self._test_password_reset_poisoning(),
                return_exceptions=True
            )
        return self.findings

    async def _test_host_injection(self) -> None:
        """Test if server reflects injected Host header"""
        for headers in TEST_HEADERS[:4]:
            resp = await self.get(self.target, headers=headers)
            if not resp:
                continue

            # Check if evil host appears in response
            if EVIL_HOST in resp.text:
                header_name = list(headers.keys())[0]
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Host Header Injection via {header_name}",
                    endpoint=self.target,
                    evidence=f"'{EVIL_HOST}' reflected in response via {header_name}",
                    description=(
                        f"Server reflects injected {header_name} header. "
                        "Can be used for password reset poisoning, cache poisoning."
                    ),
                    remediation=(
                        "Validate Host header against whitelist. "
                        "Use absolute URLs in password reset emails."
                    ),
                ))
                return

            # Check Location header for redirect
            location = resp.headers.get("location", "")
            if EVIL_HOST in location:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Host Header Injection — Open Redirect",
                    endpoint=self.target,
                    evidence=f"Redirects to {location}",
                    description="Host header injection causes redirect to attacker domain",
                    remediation="Validate Host header, use hardcoded base URL",
                ))
                return

    async def _test_password_reset_poisoning(self) -> None:
        """Test password reset endpoint for host header poisoning"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        reset_paths = [
            "/forgot-password", "/reset-password", "/password/reset",
            "/account/forgot", "/auth/forgot", "/api/auth/forgot",
        ]

        for path in reset_paths:
            url = base + path
            resp = await self.get(url)
            if resp and resp.status_code in [200, 405]:
                # Found a reset endpoint — test it
                test_resp = await self.post(
                    url,
                    data={"email": "test@test.com"},
                    headers={"Host": EVIL_HOST}
                )
                if test_resp and test_resp.status_code in [200, 302]:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Password Reset Poisoning Risk",
                        endpoint=url,
                        evidence=f"Reset endpoint accepts requests with injected Host: {EVIL_HOST}",
                        description="Password reset endpoint may be vulnerable to host header poisoning",
                        remediation="Hardcode base URL in password reset emails",
                    ))
                    break
