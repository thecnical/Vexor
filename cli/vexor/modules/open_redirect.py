"""
Vexor Open Redirect Scanner
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "https://evil.com/",
    "https:evil.com",
    "https:\\\\evil.com",
    "/\\evil.com",
    "/%09/evil.com",
    "/%2F/evil.com",
    "https://evil%E3%80%82com",
    "https://evil。com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

REDIRECT_PARAMS = [
    'redirect', 'redirect_uri', 'redirect_url', 'return',
    'return_url', 'returnUrl', 'next', 'url', 'goto',
    'target', 'destination', 'dest', 'redir', 'r',
    'continue', 'forward', 'to', 'out', 'view',
    'callback', 'success_url', 'cancel_url',
]


class Scanner(BaseScanner):
    """Open Redirect Scanner"""

    MODULE_NAME = "open_redirect"
    MODULE_DESC = "Open Redirect Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_common_params(),
                return_exceptions=True
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        for param in params:
            if param.lower() in REDIRECT_PARAMS:
                await self._test_redirect(self.target, param)

    async def _scan_common_params(self) -> None:
        for param in REDIRECT_PARAMS[:8]:
            await self._test_redirect(self.target, param)

    async def _test_redirect(self, url: str, param: str) -> None:
        for payload in REDIRECT_PAYLOADS[:6]:
            test_url = self._inject_param(url, param, payload)

            # Don't follow redirects — check Location header
            try:
                import httpx
                async with httpx.AsyncClient(
                    verify=False, timeout=10, follow_redirects=False
                ) as client:
                    resp = await client.get(test_url)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('location', '')
                    if 'evil.com' in location or location.startswith('//evil'):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Open Redirect",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=f"Redirects to: {location}",
                            description=(
                                f"Open redirect in parameter '{param}'. "
                                f"Redirects to attacker-controlled URL."
                            ),
                            remediation=(
                                "Validate redirect URLs against a whitelist. "
                                "Use relative paths instead of full URLs. "
                                "Implement SSRF protection."
                            ),
                        ))
                        return
            except Exception:
                pass

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
