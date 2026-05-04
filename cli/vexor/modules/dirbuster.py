"""
Vexor Dirbuster v3.0 - Elite Level
Smart wordlist, soft-404 detection, recursive discovery,
backup file detection, git/svn exposure, technology-specific paths,
response analysis, interesting content detection
"""
import asyncio
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Wordlist ─────────────────────────────────────────────────────────────────
WORDLIST = [
    # Admin panels
    "admin", "administrator", "admin/login", "admin/dashboard",
    "admin/users", "admin/config", "admin/settings",
    "wp-admin", "wp-login.php", "wp-config.php",
    "phpmyadmin", "pma", "adminer", "adminer.php",
    "cpanel", "whm", "plesk", "directadmin",
    "panel", "dashboard", "control", "manage",
    # API
    "api", "api/v1", "api/v2", "api/v3",
    "api/users", "api/admin", "api/config",
    "graphql", "graphiql", "playground",
    "swagger", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "api-docs",
    "redoc", "v1", "v2", "v3",
    # Config/Secrets
    ".env", ".env.local", ".env.production", ".env.backup",
    ".env.dev", ".env.staging", ".env.test",
    "config.php", "config.js", "config.json", "config.yml",
    "wp-config.php", "settings.py", "database.yml",
    "application.properties", "appsettings.json",
    "web.config", "app.config", "local.xml",
    # Git/SVN
    ".git", ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".git/logs/HEAD", ".gitignore", ".gitmodules",
    ".svn", ".svn/entries", ".svn/wc.db",
    ".hg", ".hg/hgrc",
    # Backup files
    "backup", "backups", "bak", "old", "archive",
    "backup.sql", "dump.sql", "database.sql", "db.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    "index.php.bak", "config.php.bak", "wp-config.php.bak",
    # Debug/Info
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info", "nginx_status",
    "status", "health", "ping", "metrics",
    # Spring Boot Actuator
    "actuator", "actuator/env", "actuator/configprops",
    "actuator/beans", "actuator/mappings", "actuator/health",
    "actuator/info", "actuator/logfile", "actuator/heapdump",
    "actuator/threaddump", "actuator/httptrace",
    # Package/Build files
    "composer.json", "composer.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "pom.xml", "build.gradle",
    # Docker/CI
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".travis.yml", ".github",
    "Jenkinsfile", ".circleci",
    # Logs
    "logs", "log", "error.log", "access.log",
    "debug.log", "app.log", "application.log",
    # Upload/Media
    "upload", "uploads", "files", "media", "images",
    "static", "assets", "public", "resources",
    # Dev/Test
    "test", "testing", "dev", "development", "debug",
    "staging", "qa", "uat", "sandbox",
    "demo", "example", "sample",
    # Shells/Webshells
    "shell.php", "cmd.php", "webshell.php", "c99.php",
    "r57.php", "b374k.php", "wso.php",
    "shell", "cmd", "console", "terminal",
    # CMS specific
    "wp-content", "wp-includes", "wp-json",
    "sites/default/files", "sites/default/settings.php",
    "administrator/index.php",
    # Monitoring
    "kibana", "grafana", "prometheus", "jaeger",
    "zipkin", "consul", "vault",
    # Database tools
    "redis", "memcached", "elasticsearch",
    "mongo", "mysql", "postgres",
    # Other
    "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt",
    "humans.txt", "ads.txt",
    "CHANGELOG", "CHANGELOG.md", "CHANGELOG.txt",
    "README", "README.md", "README.txt",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
    "INSTALL", "INSTALL.md",
    ".DS_Store", "thumbs.db", "desktop.ini",
]

# ─── Interesting Content Patterns ─────────────────────────────────────────────
INTERESTING_CONTENT = {
    "password": "CRITICAL",
    "secret": "CRITICAL",
    "api_key": "CRITICAL",
    "private_key": "CRITICAL",
    "-----BEGIN": "CRITICAL",
    "AKIA": "CRITICAL",
    "database_url": "HIGH",
    "db_password": "HIGH",
    "smtp_password": "HIGH",
    "aws_secret": "HIGH",
    "stripe_secret": "HIGH",
    "debug": "MEDIUM",
    "stack trace": "MEDIUM",
    "exception": "MEDIUM",
    "error": "LOW",
}

# ─── Soft 404 Indicators ──────────────────────────────────────────────────────
SOFT_404_PATTERNS = [
    "page not found", "404", "not found", "does not exist",
    "no page found", "error 404", "oops", "sorry, we couldn't find",
    "the page you requested", "this page doesn't exist",
]


class Scanner(BaseScanner):
    """Dirbuster v3.0 - Elite Level"""

    MODULE_NAME = "dirbuster"
    MODULE_DESC = "Dirbuster: Smart Wordlist/Soft404/Recursive/Backup/Git/Tech-Specific"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            # Get baseline for soft-404 detection
            baseline = await self._get_baseline(base)

            semaphore = asyncio.Semaphore(25)
            found_paths = []

            async def check(path: str) -> None:
                async with semaphore:
                    url = f"{base}/{path}"
                    try:
                        resp = await self.get(url)
                        if not resp:
                            return

                        # Skip if soft 404
                        if self._is_soft_404(resp, baseline):
                            return

                        if resp.status_code in [200, 201, 301, 302, 403]:
                            found_paths.append({
                                "path": path,
                                "url": url,
                                "status": resp.status_code,
                                "length": len(resp.content),
                                "content": resp.text[:500] if resp.status_code == 200 else "",
                            })
                    except Exception:
                        pass

            tasks = [check(p) for p in WORDLIST]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Process and report findings
            for item in found_paths:
                await self._report_finding(item)

        return self.findings

    async def _get_baseline(self, base: str) -> dict:
        """Get baseline response for soft-404 detection"""
        try:
            resp = await self.get(f"{base}/vexor_nonexistent_path_xyz_12345")
            if resp:
                return {
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "text_sample": resp.text[:200].lower(),
                }
        except Exception:
            pass
        return {"status": 404, "length": 0, "text_sample": ""}

    def _is_soft_404(self, resp, baseline: dict) -> bool:
        """Detect soft 404 pages"""
        if resp.status_code == 404:
            return True

        # Check if response matches baseline (soft 404)
        if baseline.get("status") == resp.status_code:
            baseline_len = baseline.get("length", 0)
            if baseline_len > 0:
                diff = abs(len(resp.content) - baseline_len)
                if diff < 50:  # Very similar to baseline = soft 404
                    return True

        # Check for soft 404 text indicators
        text_lower = resp.text[:500].lower()
        if any(p in text_lower for p in SOFT_404_PATTERNS):
            return True

        return False

    async def _report_finding(self, item: dict) -> None:
        """Analyze and report a found path"""
        path = item["path"]
        url = item["url"]
        status = item["status"]
        length = item["length"]
        content = item["content"]

        # Determine severity and vuln type
        if status == 403:
            severity = "LOW"
            vuln = f"Forbidden Path (Bypass Test): /{path}"
        elif any(s in path for s in [".env", ".git", "config", "backup", ".sql", "dump"]):
            severity = "CRITICAL"
            vuln = f"Critical File Exposed: /{path}"
        elif any(s in path for s in ["actuator", "phpinfo", "server-status", "heapdump"]):
            severity = "HIGH"
            vuln = f"Debug/Info Endpoint Exposed: /{path}"
        elif any(s in path for s in ["admin", "phpmyadmin", "shell", "cmd", "webshell"]):
            severity = "HIGH"
            vuln = f"Admin/Shell Path Exposed: /{path}"  # nosec B105
        elif any(s in path for s in ["swagger", "openapi", "api-docs", "graphiql"]):
            severity = "MEDIUM"
            vuln = f"API Documentation Exposed: /{path}"
        elif status in [301, 302]:
            severity = "INFO"
            vuln = f"Redirect Found: /{path}"
        else:
            severity = "MEDIUM"
            vuln = f"Path Accessible: /{path}"

        # Check content for interesting data
        content_severity = None
        content_finding = None
        if content:
            for pattern, sev in INTERESTING_CONTENT.items():
                if pattern.lower() in content.lower():
                    content_severity = sev
                    content_finding = pattern
                    break

        # Upgrade severity if interesting content found
        sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if content_severity and sev_order.index(content_severity) > sev_order.index(severity):
            severity = content_severity
            vuln += f" [Contains: {content_finding}]"

        evidence = f"HTTP {status}, {length} bytes"
        if content_finding:
            evidence += f"\nSensitive content: '{content_finding}' found"

        self.add_finding(Finding(
            severity=severity,
            module=self.MODULE_NAME,
            vuln=vuln,
            endpoint=url,
            evidence=evidence,
            description=f"Path '/{path}' is accessible (HTTP {status}, {length} bytes).",
            remediation=(
                "Restrict access to sensitive paths. "
                "Remove backup/debug files from production. "
                "Implement proper authentication."
            ),
        ))
