"""
Vexor Subdomain Enumerator
"""
import asyncio
import socket
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test',
    'staging', 'beta', 'app', 'portal', 'dashboard', 'blog',
    'shop', 'store', 'cdn', 'static', 'assets', 'media',
    'img', 'images', 'video', 'docs', 'help', 'support',
    'forum', 'community', 'wiki', 'kb', 'status', 'monitor',
    'vpn', 'remote', 'ssh', 'git', 'gitlab', 'github',
    'jenkins', 'ci', 'build', 'deploy', 'prod', 'production',
    'internal', 'intranet', 'corp', 'office', 'hr', 'finance',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
    'smtp', 'pop', 'imap', 'webmail', 'mx', 'ns1', 'ns2',
    'backup', 'old', 'legacy', 'v1', 'v2', 'new', 'demo',
    'sandbox', 'qa', 'uat', 'preprod', 'preview',
    'mobile', 'm', 'wap', 'ios', 'android',
    'auth', 'login', 'sso', 'oauth', 'id',
    'payment', 'pay', 'billing', 'invoice',
    'search', 'elastic', 'kibana', 'grafana',
    'prometheus', 'metrics', 'logs', 'logging',
]


class Scanner(BaseScanner):
    """Subdomain Enumerator"""

    MODULE_NAME = "subdomain"
    MODULE_DESC = "Subdomain Enumeration"

    async def scan(self) -> list[Finding]:
        parsed = urlparse(self.target)
        domain = parsed.hostname or self.target

        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        found = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent DNS lookups

        async def check_subdomain(sub: str):
            async with semaphore:
                full = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(
                        None,
                        lambda: socket.gethostbyname(full)
                    )
                    found.append((full, ip))
                except socket.gaierror:
                    pass

        tasks = [check_subdomain(sub) for sub in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks, return_exceptions=True)

        if found:
            evidence = "\n".join(f"{sub} → {ip}" for sub, ip in found[:20])
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Subdomains Discovered",
                endpoint=self.target,
                evidence=evidence,
                description=f"Found {len(found)} subdomain(s) for {domain}",
                remediation=(
                    "Review all subdomains for security issues. "
                    "Remove unused subdomains. "
                    "Check for subdomain takeover vulnerabilities."
                ),
            ))

            # Check for interesting subdomains
            interesting = ['admin', 'dev', 'staging', 'test', 'internal',
                          'jenkins', 'gitlab', 'kibana', 'grafana', 'db']
            for sub, ip in found:
                sub_name = sub.split('.')[0]
                if sub_name in interesting:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Interesting Subdomain: {sub}",
                        endpoint=f"https://{sub}",
                        evidence=f"{sub} → {ip}",
                        description=f"Potentially sensitive subdomain found: {sub}",
                        remediation=f"Ensure {sub} is properly secured and not publicly accessible",
                    ))

        return self.findings
