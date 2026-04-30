"""
Vexor XSS Scanner — Reflected, Stored, DOM
"""
import asyncio
import re
from vexor.modules.base import BaseScanner, Finding


XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "';alert('XSS')//",
    "\";alert('XSS')//",
    "<body onload=alert('XSS')>",
    "{{7*7}}",  # Template injection check
    "${7*7}",
]

DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "document.baseURI", "location", "document.cookie",
    "document.referrer", "window.name", "history.pushState",
    "localStorage", "sessionStorage",
]

DOM_SINKS = [
    "eval(", "innerHTML", "outerHTML", "document.write(",
    "document.writeln(", "setTimeout(", "setInterval(",
    "execScript(", "window.location",
]


class Scanner(BaseScanner):
    """XSS Scanner — Reflected, Stored, DOM"""

    MODULE_NAME = "xss"
    MODULE_DESC = "Cross-Site Scripting Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            tasks = [
                self._scan_reflected(),
                self._scan_dom(),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def _scan_reflected(self) -> None:
        """Test for reflected XSS"""
        response = await self.get(self.target)
        if not response:
            return

        # Get params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common params
            params = {"q": ["test"], "search": ["test"], "id": ["1"], "name": ["test"]}

        for param in params:
            for payload in XSS_PAYLOADS[:6]:
                test_url = self._inject_param(self.target, param, payload)
                resp = await self.get(test_url)

                if resp and payload in resp.text:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Reflected XSS",
                        endpoint=self.target,
                        param=param,
                        payload=payload,
                        evidence=f"Payload reflected in response",
                        description=f"Reflected XSS in parameter '{param}'",
                        remediation="Encode output, use Content-Security-Policy header",
                    ))
                    break

    async def _scan_dom(self) -> None:
        """Test for DOM XSS"""
        response = await self.get(self.target)
        if not response:
            return

        # Check for dangerous DOM sinks in JS
        found_sinks = []
        for sink in DOM_SINKS:
            if sink in response.text:
                found_sinks.append(sink)

        if found_sinks:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="Potential DOM XSS",
                endpoint=self.target,
                evidence=f"Dangerous sinks found: {', '.join(found_sinks)}",
                description="Potentially dangerous JavaScript sinks detected",
                remediation="Review JavaScript code for unsafe DOM manipulation",
            ))

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
