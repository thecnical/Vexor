"""
Vexor IDOR Scanner v2.0
Insecure Direct Object Reference Detection
- Numeric param enumeration with data leakage verification
- UUID param testing
- API endpoint IDOR with JSON data validation
- Horizontal privilege escalation detection
"""
import re
import asyncio
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


# Data indicators that confirm actual user data is returned
DATA_INDICATORS = [
    '"id":', '"user":', '"email":', '"name":', '"account":',
    '"username":', '"profile":', '"order":', '"data":',
    '"phone":', '"address":', '"role":', '"permissions":',
    '"created_at":', '"updated_at":', '"token":',
]

# Sensitive data patterns that confirm IDOR is critical
SENSITIVE_PATTERNS = [
    r'"email"\s*:\s*"[^"]+@[^"]+"',
    r'"password"\s*:\s*"[^"]+"',
    r'"ssn"\s*:\s*"[^"]+"',
    r'"credit_card"\s*:\s*"[^"]+"',
    r'"phone"\s*:\s*"[^"]+"',
    r'"address"\s*:\s*"[^"]+"',
    r'"token"\s*:\s*"[^"]+"',
    r'"api_key"\s*:\s*"[^"]+"',
]


class Scanner(BaseScanner):
    """IDOR Scanner v2.0 — Real data leakage verification"""

    MODULE_NAME = "idor"
    MODULE_DESC = "Insecure Direct Object Reference Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._find_numeric_params(),
                self._check_uuid_params(),
                self._check_api_endpoints(),
                self._check_path_traversal_idor(),
                return_exceptions=True
            )
        return self.findings

    async def _find_numeric_params(self) -> None:
        """Find numeric parameters and test for IDOR"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        numeric_params = {
            k: v for k, v in params.items()
            if v and v[0].isdigit()
        }

        if not numeric_params:
            # Only test common params if URL has no params at all
            if not params:
                common_params = ['id', 'user_id', 'account', 'order', 'invoice',
                                 'file', 'doc', 'record', 'item', 'product']
                for param in common_params[:5]:
                    await self._test_idor_param(self.target, param, "1")
            return

        for param, values in numeric_params.items():
            await self._test_idor_param(self.target, param, values[0])

    async def _test_idor_param(self, url: str, param: str, original_val: str) -> None:
        """Test a parameter for IDOR with data leakage verification"""
        original_resp = await self.get(url)
        if not original_resp or original_resp.status_code not in [200, 201]:
            return

        original_body = original_resp.text
        original_len = len(original_resp.content)

        # Check if original response has actual data
        original_has_data = any(ind in original_body.lower() for ind in DATA_INDICATORS)

        try:
            orig_int = int(original_val)
        except ValueError:
            return

        test_vals = [
            str(orig_int + 1),
            str(orig_int - 1),
            str(orig_int + 100),
            "0",
            "-1",
            "99999",
        ]

        for test_val in test_vals:
            test_url = self._inject_param(url, param, test_val)
            resp = await self.get(test_url)

            if not resp or resp.status_code not in [200, 201]:
                continue

            resp_body = resp.text
            resp_len = len(resp.content)

            # Must have actual data in response
            resp_has_data = any(ind in resp_body.lower() for ind in DATA_INDICATORS)
            if not resp_has_data:
                continue

            # Response must be meaningfully different from original
            len_diff = abs(resp_len - original_len)
            if len_diff < 50:
                continue

            # Check for sensitive data exposure
            severity = "HIGH"
            sensitive_found = []
            for pattern in SENSITIVE_PATTERNS:
                match = re.search(pattern, resp_body, re.IGNORECASE)
                if match:
                    sensitive_found.append(match.group(0)[:50])
                    severity = "CRITICAL"

            evidence = (
                f"Original ID={original_val} (len={original_len}) → "
                f"ID={test_val} (len={resp_len}, diff={len_diff} bytes)\n"
                f"Data indicators found: {[i for i in DATA_INDICATORS if i in resp_body.lower()][:5]}"
            )
            if sensitive_found:
                evidence += f"\nSensitive data: {sensitive_found[:3]}"

            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"IDOR — Unauthorized Data Access (param: {param})",
                endpoint=url,
                param=param,
                payload=test_val,
                evidence=evidence,
                description=(
                    f"Parameter '{param}' allows access to other users' data. "
                    f"ID={test_val} returns {resp_len} bytes of user data "
                    f"(different from original ID={original_val})."
                ),
                remediation=(
                    "Implement server-side authorization checks. "
                    "Verify the authenticated user owns the requested resource. "
                    "Use indirect object references (UUIDs) instead of sequential IDs."
                ),
            ))
            return  # One finding per param

    async def _check_uuid_params(self) -> None:
        """Check UUID-based parameters for IDOR"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )

        for param, values in params.items():
            if not values:
                continue
            if not uuid_pattern.match(values[0]):
                continue

            # Test with a predictable fake UUID
            fake_uuid = "00000000-0000-0000-0000-000000000001"
            test_url = self._inject_param(self.target, param, fake_uuid)
            resp = await self.get(test_url)

            if not resp or resp.status_code not in [200, 201]:
                continue

            resp_body = resp.text
            has_data = any(ind in resp_body.lower() for ind in DATA_INDICATORS)

            if has_data:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"UUID IDOR — Predictable Object Reference (param: {param})",
                    endpoint=self.target,
                    param=param,
                    payload=fake_uuid,
                    evidence=(
                        f"UUID param '{param}' returned data for fake UUID: {fake_uuid}\n"
                        f"Response preview: {resp_body[:200]}"
                    ),
                    description=(
                        f"UUID parameter '{param}' returned user data for a fake UUID. "
                        "Server may not validate UUID ownership."
                    ),
                    remediation=(
                        "Verify the authenticated user owns the UUID-referenced resource. "
                        "UUIDs are not a security control — authorization must be enforced."
                    ),
                ))

    async def _check_api_endpoints(self) -> None:
        """Check common REST API IDOR patterns"""
        api_patterns = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/account/{id}",
            "/api/accounts/{id}",
            "/api/orders/{id}",
            "/api/order/{id}",
            "/api/profile/{id}",
            "/api/profiles/{id}",
            "/api/v1/users/{id}",
            "/api/v2/users/{id}",
            "/user/{id}",
            "/account/{id}",
            "/profile/{id}",
        ]

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for pattern in api_patterns:
            url1 = base + pattern.replace("{id}", "1")
            resp1 = await self.get(url1)

            if not resp1 or resp1.status_code not in [200, 201]:
                continue

            body1 = resp1.text.lower()
            has_data1 = any(ind in body1 for ind in DATA_INDICATORS)
            if not has_data1:
                continue

            # Try ID=2
            url2 = base + pattern.replace("{id}", "2")
            resp2 = await self.get(url2)

            if not resp2 or resp2.status_code not in [200, 201]:
                continue

            body2 = resp2.text.lower()
            has_data2 = any(ind in body2 for ind in DATA_INDICATORS)

            if not has_data2:
                continue

            # Both return data — check if they're different (different users)
            if resp1.text[:100] == resp2.text[:100]:
                continue  # Same response = probably same data

            # Check for sensitive data
            severity = "HIGH"
            for pattern_re in SENSITIVE_PATTERNS:
                if re.search(pattern_re, resp1.text, re.IGNORECASE):
                    severity = "CRITICAL"
                    break

            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"API IDOR — Sequential IDs Without Authorization",
                endpoint=url1,
                evidence=(
                    f"ID=1: {resp1.status_code} ({len(resp1.content)} bytes)\n"
                    f"ID=2: {resp2.status_code} ({len(resp2.content)} bytes)\n"
                    f"Both return different user data without authentication check.\n"
                    f"Preview ID=1: {resp1.text[:150]}"
                ),
                description=(
                    f"API endpoint {pattern} uses sequential integer IDs. "
                    "Both ID=1 and ID=2 return different user data, "
                    "indicating no authorization check is performed."
                ),
                remediation=(
                    "Add authentication and authorization to all API endpoints. "
                    "Verify the requesting user has permission to access the resource. "
                    "Consider using UUIDs instead of sequential IDs."
                ),
            ))
            break

    async def _check_path_traversal_idor(self) -> None:
        """Check for IDOR via path traversal in URL"""
        parsed = urlparse(self.target)
        path = parsed.path

        # Check if path contains numeric segments
        path_parts = path.strip("/").split("/")
        numeric_parts = [(i, p) for i, p in enumerate(path_parts) if p.isdigit()]

        if not numeric_parts:
            return

        base = f"{parsed.scheme}://{parsed.netloc}"

        for idx, original_id in numeric_parts:
            # Try adjacent IDs
            for test_id in [str(int(original_id) + 1), str(int(original_id) - 1)]:
                new_parts = list(path_parts)
                new_parts[idx] = test_id
                new_path = "/" + "/".join(new_parts)
                test_url = f"{base}{new_path}"
                if parsed.query:
                    test_url += f"?{parsed.query}"

                resp = await self.get(test_url)
                if not resp or resp.status_code not in [200, 201]:
                    continue

                body = resp.text.lower()
                has_data = any(ind in body for ind in DATA_INDICATORS)
                if not has_data:
                    continue

                # Compare with original
                orig_resp = await self.get(self.target)
                if not orig_resp:
                    continue

                if resp.text[:100] != orig_resp.text[:100]:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln=f"Path-Based IDOR — ID in URL Path",
                        endpoint=test_url,
                        payload=test_id,
                        evidence=(
                            f"Original path: {path} (ID={original_id})\n"
                            f"Test path: {new_path} (ID={test_id})\n"
                            f"Different data returned: {resp.text[:150]}"
                        ),
                        description=(
                            f"URL path contains numeric ID={original_id}. "
                            f"Changing to ID={test_id} returns different user data."
                        ),
                        remediation=(
                            "Implement authorization checks for all path-based resource IDs. "
                            "Verify the authenticated user owns the requested resource."
                        ),
                    ))
                    return

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
