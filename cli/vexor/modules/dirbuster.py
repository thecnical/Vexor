"""
Vexor Directory Bruteforcer
"""
import asyncio
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


COMMON_DIRS = [
    'admin', 'administrator', 'login', 'dashboard', 'panel',
    'wp-admin', 'wp-login.php', 'phpmyadmin', 'pma',
    'api', 'api/v1', 'api/v2', 'swagger', 'docs',
    'backup', 'backups', 'bak', 'old', 'temp', 'tmp',
    'upload', 'uploads', 'files', 'file', 'media',
    'images', 'img', 'static', 'assets', 'css', 'js',
    'config', 'configuration', 'conf', 'settings',
    'test', 'testing', 'dev', 'development', 'debug',
    'log', 'logs', 'error', 'errors',
    'git', '.git', '.env', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml',
    'web.config', 'app.config', 'database.yml',
    'phpinfo.php', 'info.php', 'test.php',
    'shell.php', 'cmd.php', 'webshell.php',
    'console', 'terminal', 'shell',
    'install', 'setup', 'installer',
    'cgi-bin', 'cgi', 'scripts',
    'server-status', 'server-info',
    '.well-known', 'security.txt',
    'actuator', 'actuator/env', 'actuator/health',
    'metrics', 'health', 'status', 'ping',
    'graphql', 'graphiql',
    'jenkins', 'hudson', 'bamboo',
    'kibana', 'grafana', 'prometheus',
    'redis', 'memcached',
    'wp-content', 'wp-includes',
    'vendor', 'node_modules', 'composer.json',
    'package.json', 'requirements.txt',
    'Dockerfile', 'docker-compose.yml',
    '.DS_Store', 'thumbs.db',
]

INTERESTING_EXTENSIONS = ['.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.env', '.bak', '.sql']


class Scanner(BaseScanner):
    """Directory Bruteforcer"""

    MODULE_NAME = "dirbuster"
    MODULE_DESC = "Directory and File Discovery"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            semaphore = asyncio.Semaphore(20)
            found = []

            async def check_path(path: str):
                async with semaphore:
                    url = f"{base}/{path}"
                    resp = await self.get(url)
                    if resp and resp.status_code in [200, 201, 301, 302, 403]:
                        found.append({
                            'path': path,
                            'url': url,
                            'status': resp.status_code,
                            'length': len(resp.content),
                        })

            tasks = [check_path(d) for d in COMMON_DIRS]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Report findings
            for item in found:
                severity = "HIGH"
                vuln = "Sensitive Path Exposed"

                if item['status'] == 403:
                    severity = "LOW"
                    vuln = "Forbidden Path Found"
                elif any(s in item['path'] for s in ['.env', '.git', 'config', 'backup', 'sql']):
                    severity = "CRITICAL"
                    vuln = "Critical File/Directory Exposed"
                elif any(s in item['path'] for s in ['admin', 'phpmyadmin', 'shell', 'cmd']):
                    severity = "HIGH"
                    vuln = "Admin/Shell Path Exposed"
                elif item['status'] in [301, 302]:
                    severity = "INFO"
                    vuln = "Redirect Found"

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=vuln,
                    endpoint=item['url'],
                    evidence=f"Status: {item['status']}, Length: {item['length']}",
                    description=f"Path '/{item['path']}' is accessible (HTTP {item['status']})",
                    remediation="Restrict access to sensitive paths and files",
                ))

        return self.findings
