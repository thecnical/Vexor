"""
Vexor Security Headers Analyzer
"""
from vexor.modules.base import BaseScanner, Finding


REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "MEDIUM",
        "vuln": "Missing HSTS Header",
        "description": "HTTP Strict Transport Security not configured",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": "MEDIUM",
        "vuln": "Missing Content-Security-Policy",
        "description": "CSP header not set — XSS risk increased",
        "remediation": "Add Content-Security-Policy header with appropriate directives",
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "vuln": "Missing X-Frame-Options",
        "description": "Clickjacking protection not enabled",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "severity": "LOW",
        "vuln": "Missing X-Content-Type-Options",
        "description": "MIME sniffing not prevented",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "LOW",
        "vuln": "Missing Referrer-Policy",
        "description": "Referrer information may leak",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "LOW",
        "vuln": "Missing Permissions-Policy",
        "description": "Browser features not restricted",
        "remediation": "Add Permissions-Policy to restrict camera, microphone, etc.",
    },
    "x-xss-protection": {
        "severity": "LOW",
        "vuln": "Missing X-XSS-Protection",
        "description": "Legacy XSS filter not configured",
        "remediation": "Add: X-XSS-Protection: 1; mode=block",
    },
}

DANGEROUS_HEADERS = {
    "server": "Server version disclosure",
    "x-powered-by": "Technology stack disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
}


class Scanner(BaseScanner):
    """Security Headers Analyzer"""

    MODULE_NAME = "headers"
    MODULE_DESC = "HTTP Security Headers Check"

    async def scan(self) -> list[Finding]:
        async with self:
            response = await self.get(self.target)
            if not response:
                return self.findings

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check missing security headers
            for header, info in REQUIRED_HEADERS.items():
                if header not in headers:
                    self.add_finding(Finding(
                        severity=info["severity"],
                        module=self.MODULE_NAME,
                        vuln=info["vuln"],
                        endpoint=self.target,
                        description=info["description"],
                        remediation=info["remediation"],
                    ))

            # Check dangerous headers (info disclosure)
            for header, desc in DANGEROUS_HEADERS.items():
                if header in headers:
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln=f"Information Disclosure: {header}",
                        endpoint=self.target,
                        evidence=f"{header}: {headers[header]}",
                        description=desc,
                        remediation=f"Remove or obscure the '{header}' header",
                    ))

            # Check CSP quality if present
            csp = headers.get("content-security-policy", "")
            if csp:
                if "unsafe-inline" in csp:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Weak CSP: unsafe-inline",
                        endpoint=self.target,
                        evidence=f"CSP: {csp[:100]}",
                        description="CSP allows unsafe-inline which weakens XSS protection",
                        remediation="Remove 'unsafe-inline' from CSP directives",
                    ))
                if "unsafe-eval" in csp:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Weak CSP: unsafe-eval",
                        endpoint=self.target,
                        evidence=f"CSP: {csp[:100]}",
                        description="CSP allows unsafe-eval",
                        remediation="Remove 'unsafe-eval' from CSP directives",
                    ))

        return self.findings
