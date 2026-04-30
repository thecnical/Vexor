"""
Vexor Technology Fingerprinter
Detects frameworks, CMS, servers, languages
"""
import re
from vexor.modules.base import BaseScanner, Finding


SIGNATURES = {
    "WordPress": {
        "patterns": [
            r"wp-content", r"wp-includes", r"WordPress",
            r"/wp-json/", r"wp-login\.php",
        ],
        "headers": {"x-powered-by": r"WordPress"},
    },
    "Laravel": {
        "patterns": [r"laravel_session", r"XSRF-TOKEN"],
        "headers": {"x-powered-by": r"PHP"},
    },
    "Django": {
        "patterns": [r"csrfmiddlewaretoken", r"django"],
        "headers": {},
    },
    "React": {
        "patterns": [r"__REACT_DEVTOOLS", r"react-root", r"_reactFiber"],
        "headers": {},
    },
    "Angular": {
        "patterns": [r"ng-version", r"ng-app", r"\[ng-"],
        "headers": {},
    },
    "Vue.js": {
        "patterns": [r"__vue__", r"v-app", r"data-v-"],
        "headers": {},
    },
    "jQuery": {
        "patterns": [r"jquery\.min\.js", r"jquery-\d"],
        "headers": {},
    },
    "Bootstrap": {
        "patterns": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
        "headers": {},
    },
    "Apache": {
        "patterns": [],
        "headers": {"server": r"Apache"},
    },
    "Nginx": {
        "patterns": [],
        "headers": {"server": r"nginx"},
    },
    "IIS": {
        "patterns": [],
        "headers": {"server": r"IIS", "x-powered-by": r"ASP\.NET"},
    },
    "PHP": {
        "patterns": [r"\.php"],
        "headers": {"x-powered-by": r"PHP"},
    },
    "Node.js": {
        "patterns": [],
        "headers": {"x-powered-by": r"Express"},
    },
    "Cloudflare": {
        "patterns": [],
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
    },
}


class Scanner(BaseScanner):
    """Technology Fingerprinter"""

    MODULE_NAME = "fingerprint"
    MODULE_DESC = "Technology Stack Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            response = await self.get(self.target)
            if not response:
                return self.findings

            detected = []
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text

            for tech, sigs in SIGNATURES.items():
                found = False

                # Check body patterns
                for pattern in sigs.get("patterns", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        found = True
                        break

                # Check headers
                if not found:
                    for header, pattern in sigs.get("headers", {}).items():
                        if header in headers and re.search(pattern, headers[header], re.IGNORECASE):
                            found = True
                            break

                if found:
                    detected.append(tech)

            if detected:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="Technology Stack Detected",
                    endpoint=self.target,
                    evidence=f"Detected: {', '.join(detected)}",
                    description=f"Technologies identified: {', '.join(detected)}",
                    remediation="Review detected technologies for known CVEs",
                ))

                # Check for version disclosure
                server = headers.get("server", "")
                powered = headers.get("x-powered-by", "")

                if re.search(r"\d+\.\d+", server):
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln="Server Version Disclosure",
                        endpoint=self.target,
                        evidence=f"Server: {server}",
                        description="Server version exposed in headers",
                        remediation="Remove version from Server header",
                    ))

                if re.search(r"\d+\.\d+", powered):
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln="Technology Version Disclosure",
                        endpoint=self.target,
                        evidence=f"X-Powered-By: {powered}",
                        description="Technology version exposed",
                        remediation="Remove X-Powered-By header",
                    ))

        return self.findings
