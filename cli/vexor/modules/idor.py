"""
Vexor IDOR Scanner
Insecure Direct Object Reference Detection
"""
import re
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """IDOR Scanner"""

    MODULE_NAME = "idor"
    MODULE_DESC = "Insecure Direct Object Reference Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._find_numeric_params(),
                self._check_uuid_params(),
                self._check_api_endpoints(),
                return_exceptions=True
            )
        return self.findings

    async def _find_numeric_params(self) -> None:
        """Find numeric parameters that might be IDORs"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        numeric_params = {
            k: v for k, v in params.items()
            if v and v[0].isdigit()
        }

        if not numeric_params:
            # Try common IDOR param names
            common_params = ['id', 'user_id', 'account', 'order', 'invoice',
                           'file', 'doc', 'record', 'item', 'product']
            for param in common_params:
                await self._test_idor_param(self.target, param, "1")
            return

        for param, values in numeric_params.items():
            original_val = values[0]
            await self._test_idor_param(self.target, param, original_val)

    async def _test_idor_param(self, url: str, param: str, original_val: str) -> None:
        """Test a parameter for IDOR"""
        # Get original response
        original_resp = await self.get(url)
        if not original_resp or original_resp.status_code not in [200, 201]:
            return

        original_len = len(original_resp.content)

        # Try adjacent IDs
        try:
            orig_int = int(original_val)
            test_vals = [
                str(orig_int + 1),
                str(orig_int - 1),
                str(orig_int + 100),
                "0",
                "-1",
                "99999",
            ]
        except ValueError:
            return

        for test_val in test_vals:
            test_url = self._inject_param(url, param, test_val)
            resp = await self.get(test_url)

            if not resp:
                continue

            # Different content = possible IDOR
            if (resp.status_code == 200 and
                    abs(len(resp.content) - original_len) > 50 and
                    len(resp.content) > 100):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Potential IDOR",
                    endpoint=url,
                    param=param,
                    payload=test_val,
                    evidence=(
                        f"Original ID={original_val} (len={original_len}) → "
                        f"ID={test_val} (len={len(resp.content)}, status={resp.status_code})"
                    ),
                    description=(
                        f"Parameter '{param}' may allow access to other users' data. "
                        f"Different response received for ID={test_val}"
                    ),
                    remediation=(
                        "Implement proper authorization checks. "
                        "Verify user owns the requested resource before returning data."
                    ),
                ))
                break  # One finding per param is enough

    async def _check_uuid_params(self) -> None:
        """Check UUID-based parameters"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )

        for param, values in params.items():
            if values and uuid_pattern.match(values[0]):
                # Test with a fake UUID
                fake_uuid = "00000000-0000-0000-0000-000000000001"
                test_url = self._inject_param(self.target, param, fake_uuid)
                resp = await self.get(test_url)

                if resp and resp.status_code == 200 and len(resp.content) > 100:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Potential UUID IDOR",
                        endpoint=self.target,
                        param=param,
                        payload=fake_uuid,
                        evidence=f"UUID param '{param}' returned 200 with fake UUID",
                        description=f"UUID parameter '{param}' may be vulnerable to IDOR",
                        remediation="Verify ownership of UUID-referenced resources",
                    ))

    async def _check_api_endpoints(self) -> None:
        """Check common API IDOR patterns — only report if auth-protected data leaks"""
        api_patterns = [
            "/api/users/1",
            "/api/users/2",
            "/api/account/1",
            "/api/orders/1",
            "/api/profile/1",
            "/user/1",
            "/account/1",
        ]

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for pattern in api_patterns:
            url = base + pattern
            resp = await self.get(url)
            if resp and resp.status_code == 200 and len(resp.content) > 100:
                # Must contain actual user data indicators — not just a 200 page
                content = resp.text.lower()
                data_indicators = [
                    '"id":', '"user":', '"email":', '"name":', '"account":',
                    '"username":', '"profile":', '"order":', '"data":',
                ]
                has_data = any(ind in content for ind in data_indicators)
                if not has_data:
                    continue

                # Try next ID
                next_url = base + pattern.replace("/1", "/2")
                next_resp = await self.get(next_url)
                if next_resp and next_resp.status_code == 200:
                    next_content = next_resp.text.lower()
                    next_has_data = any(ind in next_content for ind in data_indicators)
                    if next_has_data:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="API IDOR — Sequential IDs",
                            endpoint=url,
                            evidence=(
                                f"Both {url} and {next_url} return 200 with user data.\n"
                                f"Response preview: {resp.text[:200]}"
                            ),
                            description=(
                                "API endpoint uses sequential IDs without authorization. "
                                "Both ID=1 and ID=2 return user data — IDOR confirmed."
                            ),
                            remediation="Add authorization checks to all API endpoints",
                        ))
                        break

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
