"""
Vexor Rate Limit Tester
"""
import asyncio
import time
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """Rate Limit Tester"""

    MODULE_NAME = "rate_limit"
    MODULE_DESC = "Rate Limiting Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_login_rate_limit(),
                self._test_api_rate_limit(),
                return_exceptions=True
            )
        return self.findings

    async def _test_login_rate_limit(self) -> None:
        """Test if login endpoint has rate limiting"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = ['/login', '/api/login', '/auth/login', '/signin', '/api/auth']

        for path in login_paths:
            url = base + path
            resp = await self.get(url)
            if not resp or resp.status_code not in [200, 405]:
                continue

            # Send 10 rapid requests
            statuses = []
            start = time.time()

            for i in range(10):
                r = await self.post(
                    url,
                    data={"username": f"test{i}", "password": "wrongpassword"},
                )
                if r:
                    statuses.append(r.status_code)
                await asyncio.sleep(0.1)

            elapsed = time.time() - start

            # Check if any rate limiting occurred
            rate_limited = any(s in [429, 503, 423] for s in statuses)
            all_same = len(set(statuses)) == 1 and statuses

            if not rate_limited and all_same and statuses[0] in [200, 401, 403]:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="No Rate Limiting on Login",
                    endpoint=url,
                    evidence=(
                        f"10 requests in {elapsed:.1f}s — "
                        f"all returned {statuses[0]} — no rate limiting detected"
                    ),
                    description="Login endpoint has no rate limiting — brute force possible",
                    remediation=(
                        "Implement rate limiting (e.g., 5 attempts per minute). "
                        "Add CAPTCHA after failed attempts. "
                        "Implement account lockout."
                    ),
                ))
                return

    async def _test_api_rate_limit(self) -> None:
        """Test API endpoint rate limiting"""
        statuses = []

        for i in range(20):
            resp = await self.get(self.target)
            if resp:
                statuses.append(resp.status_code)
            await asyncio.sleep(0.05)

        rate_limited = any(s == 429 for s in statuses)

        if not rate_limited:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="No API Rate Limiting Detected",
                endpoint=self.target,
                evidence=f"20 rapid requests — no 429 response received",
                description="API endpoint may lack rate limiting",
                remediation=(
                    "Implement rate limiting on all API endpoints. "
                    "Return 429 Too Many Requests when limit exceeded."
                ),
            ))
        else:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Rate Limiting Active",
                endpoint=self.target,
                evidence="429 response received — rate limiting is working",
                description="Rate limiting is properly implemented",
                remediation="No action needed",
            ))
