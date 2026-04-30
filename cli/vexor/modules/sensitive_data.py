"""
Vexor Sensitive Data Exposure Scanner
Finds leaked API keys, passwords, tokens in responses
"""
import asyncio
import re
from vexor.modules.base import BaseScanner, Finding


# Regex patterns for sensitive data
SENSITIVE_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "GitHub Token": r'ghp_[0-9a-zA-Z]{36}',
    "GitHub OAuth": r'gho_[0-9a-zA-Z]{36}',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Stripe API Key": r'sk_live_[0-9a-zA-Z]{24}',
    "Stripe Publishable": r'pk_live_[0-9a-zA-Z]{24}',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Heroku API Key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "Private Key": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "Password in HTML": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{4,}[\'"]',
    "API Key Generic": r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
    "Secret Generic": r'(?i)(secret|secret_key)\s*[=:]\s*[\'"][a-zA-Z0-9]{8,}[\'"]',
    "Bearer Token": r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    "Basic Auth": r'Authorization:\s*Basic\s+[a-zA-Z0-9+/]+=*',
    "Database URL": r'(?i)(mysql|postgres|mongodb|redis)://[^\s\'"<>]+',
    "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "IP Address Internal": r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
    "Credit Card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "JWT Token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
    "Phone Number": r'\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
}

SEVERITY_MAP = {
    "AWS Access Key": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "Private Key": "CRITICAL",
    "Stripe API Key": "CRITICAL",
    "Database URL": "CRITICAL",
    "GitHub Token": "HIGH",
    "GitHub OAuth": "HIGH",
    "Google API Key": "HIGH",
    "Slack Token": "HIGH",
    "API Key Generic": "HIGH",
    "Secret Generic": "HIGH",
    "Bearer Token": "HIGH",
    "Basic Auth": "HIGH",
    "Password in HTML": "HIGH",
    "JWT Token": "MEDIUM",
    "Credit Card": "CRITICAL",
    "SSN": "CRITICAL",
    "Firebase URL": "MEDIUM",
    "Heroku API Key": "HIGH",
    "Stripe Publishable": "LOW",
    "Email Address": "LOW",
    "IP Address Internal": "LOW",
    "Phone Number": "LOW",
}

# Paths to check for sensitive data
SENSITIVE_PATHS = [
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/config.php', '/config.js', '/config.json', '/config.yml',
    '/wp-config.php', '/settings.py', '/database.yml',
    '/.git/config', '/.git/HEAD',
    '/composer.json', '/package.json',
    '/Dockerfile', '/docker-compose.yml',
    '/backup.sql', '/dump.sql', '/database.sql',
    '/phpinfo.php', '/info.php',
    '/server-status', '/server-info',
    '/actuator/env', '/actuator/configprops',
    '/api/config', '/api/settings',
]


class Scanner(BaseScanner):
    """Sensitive Data Exposure Scanner"""

    MODULE_NAME = "sensitive_data"
    MODULE_DESC = "Sensitive Data Exposure Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_main_page(),
                self._scan_sensitive_paths(),
                self._check_error_pages(),
                return_exceptions=True
            )
        return self.findings

    async def _scan_main_page(self) -> None:
        """Scan main page for sensitive data"""
        response = await self.get(self.target)
        if not response:
            return
        self._find_sensitive_data(response.text, self.target)

    async def _scan_sensitive_paths(self) -> None:
        """Check sensitive file paths"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        semaphore = asyncio.Semaphore(15)

        async def check(path: str):
            async with semaphore:
                url = base + path
                resp = await self.get(url)
                if resp and resp.status_code == 200 and len(resp.content) > 10:
                    # File is accessible
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln=f"Sensitive File Exposed: {path}",
                        endpoint=url,
                        evidence=f"HTTP 200, {len(resp.content)} bytes",
                        description=f"Sensitive file '{path}' is publicly accessible",
                        remediation=f"Remove or restrict access to '{path}'",
                    ))
                    # Also scan content for secrets
                    self._find_sensitive_data(resp.text, url)

        tasks = [check(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_error_pages(self) -> None:
        """Check error pages for info disclosure"""
        test_urls = [
            self.target + "/nonexistent_vexor_test_12345",
            self.target + "/'",
            self.target + "/../../etc/passwd",
        ]

        for url in test_urls:
            resp = await self.get(url)
            if not resp:
                continue

            # Check for stack traces
            stack_patterns = [
                r'Traceback \(most recent call last\)',
                r'at [a-zA-Z]+\.[a-zA-Z]+\([a-zA-Z]+\.java:\d+\)',
                r'System\.Web\.HttpException',
                r'Microsoft\.CSharp',
                r'Fatal error:.*in.*on line \d+',
                r'Warning:.*in.*on line \d+',
            ]

            for pattern in stack_patterns:
                if re.search(pattern, resp.text):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Stack Trace / Error Disclosure",
                        endpoint=url,
                        evidence=re.search(pattern, resp.text).group()[:200],
                        description="Application exposes stack traces in error responses",
                        remediation="Disable detailed error messages in production",
                    ))
                    break

    def _find_sensitive_data(self, text: str, url: str) -> None:
        """Find sensitive data patterns in text"""
        found_types = set()

        for data_type, pattern in SENSITIVE_PATTERNS.items():
            if data_type in found_types:
                continue

            matches = re.findall(pattern, text)
            if matches:
                # Avoid duplicate findings
                found_types.add(data_type)
                severity = SEVERITY_MAP.get(data_type, "MEDIUM")

                # Redact sensitive values
                evidence = str(matches[0])
                if len(evidence) > 20:
                    evidence = evidence[:10] + "..." + evidence[-4:]

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=f"Sensitive Data Exposed: {data_type}",
                    endpoint=url,
                    evidence=f"Found {len(matches)} instance(s): {evidence}",
                    description=f"{data_type} found in response",
                    remediation=f"Remove {data_type} from public responses immediately",
                ))
