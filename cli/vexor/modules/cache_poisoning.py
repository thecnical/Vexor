"""
Vexor Cache Poisoning Scanner
Detects web cache poisoning via unkeyed headers
"""
import asyncio
import re
import uuid
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """Cache Poisoning Scanner"""

    MODULE_NAME = "cache_poisoning"
    MODULE_DESC = "Web Cache Poisoning Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_cache_headers(),
                self._test_unkeyed_headers(),
                return_exceptions=True
            )
        return self.findings

    async def _test_cache_headers(self) -> None:
        """Check cache-related headers"""
        resp = await self.get(self.target)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check if caching is enabled
        cache_control = headers.get("cache-control", "")
        x_cache = headers.get("x-cache", "")
        cf_cache = headers.get("cf-cache-status", "")
        age = headers.get("age", "")

        is_cached = bool(x_cache or cf_cache or age)

        if is_cached:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Caching Detected — Test for Poisoning",
                endpoint=self.target,
                evidence=(
                    f"X-Cache: {x_cache} | "
                    f"CF-Cache: {cf_cache} | "
                    f"Age: {age}"
                ),
                description="Response is cached — test for cache poisoning",
                remediation="Ensure all user-controlled inputs are cache keys",
            ))

            # Test unkeyed header injection
            await self._test_unkeyed_headers()

    async def _test_unkeyed_headers(self) -> None:
        """Test if unkeyed headers can poison cache"""
        canary = f"vexor-{uuid.uuid4().hex[:8]}"

        unkeyed_headers = [
            {"X-Forwarded-Host": canary},
            {"X-Forwarded-Scheme": "nothttps"},
            {"X-Original-URL": f"/{canary}"},
            {"X-Rewrite-URL": f"/{canary}"},
        ]

        for headers in unkeyed_headers:
            resp = await self.get(self.target, headers=headers)
            if resp and canary in resp.text:
                header_name = list(headers.keys())[0]
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Cache Poisoning via {header_name}",
                    endpoint=self.target,
                    evidence=f"Canary '{canary}' reflected via unkeyed header {header_name}",
                    description=(
                        f"Unkeyed header {header_name} is reflected in cached response. "
                        "Attacker can poison cache for all users."
                    ),
                    remediation=(
                        "Add all user-controlled headers to cache key. "
                        "Use Vary header. Disable caching for dynamic content."
                    ),
                ))
                return
