"""
Vexor Sensitive Data Scanner v3.0 - Elite Level
50+ secret patterns, JS file scanning, API response scanning,
error page analysis, backup file detection, git exposure,
cloud metadata, debug endpoints, version disclosure
"""
import asyncio
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Sensitive Data Patterns ──────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    # Cloud Provider Keys
    "AWS Access Key":        (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret Key":        (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "AWS Session Token":     (r"(?i)aws.{0,20}session.{0,20}['\"][A-Za-z0-9/+=]{100,}['\"]", "CRITICAL"),
    "GCP Service Account":   (r'"type":\s*"service_account"', "CRITICAL"),
    "Azure Storage Key":     (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "CRITICAL"),
    # Source Control
    "GitHub PAT":            (r"ghp_[0-9a-zA-Z]{36}", "CRITICAL"),
    "GitHub OAuth":          (r"gho_[0-9a-zA-Z]{36}", "HIGH"),
    "GitHub App Token":      (r"ghs_[0-9a-zA-Z]{36}", "HIGH"),
    "GitLab PAT":            (r"glpat-[0-9a-zA-Z\-]{20}", "HIGH"),
    # Payment
    "Stripe Live Key":       (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    "Stripe Test Key":       (r"sk_test_[0-9a-zA-Z]{24}", "HIGH"),
    "Stripe Publishable":    (r"pk_live_[0-9a-zA-Z]{24}", "LOW"),
    "PayPal Client ID":      (r"(?i)paypal.{0,20}client.{0,20}['\"][A-Za-z0-9]{20,}['\"]", "HIGH"),
    "Braintree Token":       (r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "CRITICAL"),
    # Communication
    "Slack Token":           (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "HIGH"),
    "Slack Webhook":         (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "HIGH"),
    "Twilio SID":            (r"AC[a-z0-9]{32}", "HIGH"),
    "Twilio Token":          (r"(?i)twilio.{0,20}['\"][a-z0-9]{32}['\"]", "HIGH"),
    "SendGrid Key":          (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "HIGH"),
    "Mailgun Key":           (r"key-[0-9a-zA-Z]{32}", "HIGH"),
    # Search/Analytics
    "Google API Key":        (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Google OAuth":          (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "MEDIUM"),
    "Firebase URL":          (r"https://[a-z0-9-]+\.firebaseio\.com", "MEDIUM"),
    "Firebase Key":          (r"(?i)firebase.{0,20}['\"][A-Za-z0-9]{20,}['\"]", "HIGH"),
    "Algolia Key":           (r"(?i)algolia.{0,20}['\"][A-Za-z0-9]{32}['\"]", "HIGH"),
    # Infrastructure
    "Heroku API Key":        (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "HIGH"),
    "Cloudflare Key":        (r"(?i)cloudflare.{0,20}['\"][a-zA-Z0-9_-]{37}['\"]", "HIGH"),
    "DigitalOcean Token":    (r"(?i)digitalocean.{0,20}['\"][a-zA-Z0-9]{64}['\"]", "HIGH"),
    "NPM Token":             (r"npm_[A-Za-z0-9]{36}", "HIGH"),
    "Docker Hub Token":      (r"(?i)docker.{0,20}['\"][a-zA-Z0-9_-]{20,}['\"]", "MEDIUM"),
    # Crypto
    "Private Key":           (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    "PGP Private Key":       (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL"),
    "Certificate":           (r"-----BEGIN CERTIFICATE-----", "LOW"),
    # Auth
    "JWT Token":             (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "MEDIUM"),
    "Bearer Token":          (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "HIGH"),
    "Basic Auth":            (r"Authorization:\s*Basic\s+[a-zA-Z0-9+/]+=*", "HIGH"),
    "OAuth Token":           (r"(?i)oauth.{0,20}['\"][a-zA-Z0-9_-]{20,}['\"]", "HIGH"),
    # Database
    "Database URL":          (r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'\"<>]+", "CRITICAL"),
    "MongoDB URI":           (r"mongodb(\+srv)?://[^\s'\"<>]+", "CRITICAL"),
    "Redis URL":             (r"redis://[^\s'\"<>]+", "HIGH"),
    # App Secrets
    "Password in Code":      (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "HIGH"),
    "API Key Generic":       (r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}['\"]", "HIGH"),
    "Secret Generic":        (r"(?i)(secret|secret_key|signing_key)\s*[=:]\s*['\"][a-zA-Z0-9]{8,}['\"]", "HIGH"),
    "Token Generic":         (r"(?i)(access_token|auth_token|refresh_token)\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "HIGH"),
    # PII
    "Credit Card":           (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "CRITICAL"),
    "SSN":                   (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
    "Email Address":         (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "LOW"),
    "Phone Number":          (r"\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "LOW"),
    "IP Internal":           (r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "LOW"),
    # Version Disclosure
    "PHP Version":           (r"PHP/[0-9]+\.[0-9]+\.[0-9]+", "LOW"),
    "Apache Version":        (r"Apache/[0-9]+\.[0-9]+\.[0-9]+", "LOW"),
    "Nginx Version":         (r"nginx/[0-9]+\.[0-9]+\.[0-9]+", "LOW"),
    "OpenSSL Version":       (r"OpenSSL/[0-9]+\.[0-9]+\.[0-9]+", "LOW"),
}

# ─── Sensitive File Paths ─────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Environment files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.dev", "/.env.staging", "/.env.test",
    # Config files
    "/config.php", "/config.js", "/config.json", "/config.yml", "/config.yaml",
    "/wp-config.php", "/settings.py", "/database.yml", "/database.yaml",
    "/application.properties", "/application.yml", "/appsettings.json",
    "/web.config", "/app.config", "/local.xml",
    # Git
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.gitignore",
    # Backup files
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    "/index.php.bak", "/config.php.bak", "/wp-config.php.bak",
    # Debug/Info
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info", "/nginx_status",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/configprops",
    "/actuator/beans", "/actuator/mappings", "/actuator/health",
    "/actuator/info", "/actuator/logfile", "/actuator/heapdump",
    # Package files
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile",
    # Docker
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    # API docs
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
    # Logs
    "/logs/error.log", "/logs/access.log", "/error.log", "/access.log",
    "/var/log/apache2/error.log",
    # Other
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/security.txt", "/.well-known/security.txt",
]

# ─── Stack Trace Patterns ─────────────────────────────────────────────────────
STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [a-zA-Z]+\.[a-zA-Z]+\([a-zA-Z]+\.java:\d+\)",
    r"System\.Web\.HttpException",
    r"Microsoft\.CSharp",
    r"Fatal error:.*in.*on line \d+",
    r"Warning:.*in.*on line \d+",
    r"Parse error:.*in.*on line \d+",
    r"Uncaught [A-Za-z]+Error:",
    r"SyntaxError:",
    r"TypeError:",
    r"ReferenceError:",
    r"at Object\.<anonymous>",
    r"at Module\._compile",
    r"django\.core\.exceptions",
    r"ActiveRecord::",
    r"ActionController::",
    r"Errno::",
]


class Scanner(BaseScanner):
    """Sensitive Data Scanner v3.0 - Elite Level"""

    MODULE_NAME = "sensitive_data"
    MODULE_DESC = "Sensitive Data: 50+ Patterns/JS-Files/API-Responses/Errors/Backups/Git"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_main_page(),
                self._scan_js_files(),
                self._scan_sensitive_paths(),
                self._check_error_pages(),
                self._check_api_responses(),
                self._check_headers_disclosure(),
                return_exceptions=True,
            )
        return self.findings

    async def _scan_main_page(self) -> None:
        """Scan main page and linked pages"""
        response = await self.get(self.target)
        if not response:
            return
        self._find_sensitive_data(response.text, self.target)

    async def _scan_js_files(self) -> None:
        """Scan JavaScript files for secrets"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")
            js_urls = []

            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if src:
                    js_url = urljoin(self.target, src)
                    if urlparse(js_url).netloc == urlparse(self.target).netloc:
                        js_urls.append(js_url)

            # Also check inline scripts
            for script in soup.find_all("script"):
                if not script.get("src") and script.string:
                    self._find_sensitive_data(script.string, self.target + " (inline JS)")

            # Fetch and scan JS files
            semaphore = asyncio.Semaphore(5)

            async def scan_js(url: str) -> None:
                async with semaphore:
                    try:
                        resp = await self.get(url)
                        if resp and resp.status_code == 200:
                            self._find_sensitive_data(resp.text, url)
                    except Exception:
                        pass

            tasks = [scan_js(url) for url in js_urls[:10]]
            await asyncio.gather(*tasks, return_exceptions=True)

        except Exception:
            pass

    async def _scan_sensitive_paths(self) -> None:
        """Check sensitive file paths for exposure"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        semaphore = asyncio.Semaphore(15)

        async def check(path: str) -> None:
            async with semaphore:
                url = base + path
                try:
                    resp = await self.get(url)
                    if not resp or resp.status_code != 200:
                        return
                    if len(resp.content) < 10:
                        return

                    # Determine severity based on file type
                    if any(s in path for s in [".env", "config", "wp-config", "database", ".git"]):
                        severity = "CRITICAL"
                    elif any(s in path for s in ["backup", ".sql", "dump", "heapdump"]):
                        severity = "CRITICAL"
                    elif any(s in path for s in ["actuator", "phpinfo", "server-status"]):
                        severity = "HIGH"
                    else:
                        severity = "MEDIUM"

                    self.add_finding(Finding(
                        severity=severity,
                        module=self.MODULE_NAME,
                        vuln=f"Sensitive File Exposed: {path}",
                        endpoint=url,
                        evidence=f"HTTP 200, {len(resp.content)} bytes",
                        description=f"Sensitive file '{path}' is publicly accessible.",
                        remediation=f"Remove or restrict access to '{path}'.",
                    ))

                    # Scan content for secrets
                    self._find_sensitive_data(resp.text, url)

                except Exception:
                    pass

        tasks = [check(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_error_pages(self) -> None:
        """Check error pages for information disclosure"""
        test_urls = [
            self.target.rstrip("/") + "/nonexistent_vexor_test_xyz_12345",
            self.target.rstrip("/") + "/'",
            self.target.rstrip("/") + "/../../etc/passwd",
            self.target.rstrip("/") + "/<script>",
            self.target.rstrip("/") + "/undefined",
        ]

        for url in test_urls:
            try:
                resp = await self.get(url)
                if not resp:
                    continue

                # Stack trace detection
                for pattern in STACK_TRACE_PATTERNS:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Stack Trace / Error Disclosure",
                            endpoint=url,
                            evidence=match.group()[:200],
                            description=(
                                "Application exposes stack traces in error responses. "
                                "Reveals internal paths, framework, and code structure."
                            ),
                            remediation=(
                                "Disable detailed error messages in production. "
                                "Use generic error pages. Log errors server-side only."
                            ),
                        ))
                        break

                # Version disclosure in error
                version_patterns = [
                    r"PHP/[0-9]+\.[0-9]+",
                    r"Apache/[0-9]+\.[0-9]+",
                    r"nginx/[0-9]+\.[0-9]+",
                    r"Python [0-9]+\.[0-9]+",
                    r"Ruby [0-9]+\.[0-9]+",
                    r"Node\.js v[0-9]+\.[0-9]+",
                ]
                for vp in version_patterns:
                    vm = re.search(vp, resp.text)
                    if vm:
                        self.add_finding(Finding(
                            severity="LOW",
                            module=self.MODULE_NAME,
                            vuln=f"Version Disclosure in Error Page",
                            endpoint=url,
                            evidence=vm.group(),
                            description=f"Error page reveals version: {vm.group()}",
                            remediation="Remove version information from error pages.",
                        ))
                        break

            except Exception:
                continue

    async def _check_api_responses(self) -> None:
        """Check API endpoints for sensitive data in responses"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        api_paths = [
            "/api/", "/api/v1/", "/api/v2/",
            "/api/users", "/api/config", "/api/settings",
            "/api/debug", "/api/info", "/api/status",
        ]

        for path in api_paths:
            try:
                resp = await self.get(
                    base + path,
                    headers={"Accept": "application/json"},
                )
                if resp and resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type:
                        self._find_sensitive_data(resp.text, base + path)
            except Exception:
                continue

    async def _check_headers_disclosure(self) -> None:
        """Check response headers for version/technology disclosure"""
        response = await self.get(self.target)
        if not response:
            return

        disclosure_headers = {
            "server": "Web Server Version",
            "x-powered-by": "Backend Technology",
            "x-aspnet-version": "ASP.NET Version",
            "x-aspnetmvc-version": "ASP.NET MVC Version",
            "x-generator": "CMS/Framework",
            "x-drupal-cache": "Drupal CMS",
            "x-wordpress-cache": "WordPress CMS",
        }

        for header, desc in disclosure_headers.items():
            val = response.headers.get(header, "")
            if val:
                # Check if version number is present
                if re.search(r"[0-9]+\.[0-9]+", val):
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln=f"Version Disclosure in Header: {header}",
                        endpoint=self.target,
                        evidence=f"{header}: {val}",
                        description=f"{desc} disclosed: {val}",
                        remediation=f"Remove or obscure the {header} header.",
                    ))

    def _find_sensitive_data(self, text: str, url: str) -> None:
        """Find sensitive data patterns in text"""
        found_types = set()

        for data_type, (pattern, severity) in SENSITIVE_PATTERNS.items():
            if data_type in found_types:
                continue

            try:
                matches = re.findall(pattern, text)
                if not matches:
                    continue

                found_types.add(data_type)

                # Redact sensitive values for evidence
                evidence_val = str(matches[0])
                if len(evidence_val) > 20:
                    evidence_val = evidence_val[:8] + "..." + evidence_val[-4:]

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=f"Sensitive Data: {data_type}",
                    endpoint=url,
                    evidence=f"Found {len(matches)} instance(s): {evidence_val}",
                    description=f"{data_type} found in response at {url}.",
                    remediation=(
                        f"Remove {data_type} from public responses immediately. "
                        "Rotate/revoke the exposed credential."
                    ),
                ))
            except Exception:
                continue
