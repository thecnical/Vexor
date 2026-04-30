"""
Vexor Wayback Machine Integration
Find historical endpoints and hidden paths
"""
import asyncio
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


WAYBACK_API = "https://web.archive.org/cdx/search/cdx"


class Scanner(BaseScanner):
    """Wayback Machine Historical Endpoint Finder"""

    MODULE_NAME = "wayback"
    MODULE_DESC = "Historical Endpoint Discovery via Wayback Machine"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            domain = parsed.hostname or self.target

            await asyncio.gather(
                self._fetch_wayback_urls(domain),
                return_exceptions=True
            )
        return self.findings

    async def _fetch_wayback_urls(self, domain: str) -> None:
        """Fetch historical URLs from Wayback Machine CDX API"""
        try:
            params = {
                'url': f"{domain}/*",
                'output': 'text',
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': '200',
                'filter': 'statuscode:200',
            }

            resp = await self.get(WAYBACK_API, params=params)
            if not resp or resp.status_code != 200:
                return

            urls = [line.strip() for line in resp.text.splitlines() if line.strip()]

            if not urls:
                return

            # Categorize URLs
            interesting = []
            api_endpoints = []
            admin_paths = []
            old_files = []

            for url in urls:
                url_lower = url.lower()

                if any(p in url_lower for p in ['/admin', '/dashboard', '/panel', '/manage']):
                    admin_paths.append(url)
                elif any(p in url_lower for p in ['/api/', '/v1/', '/v2/', '/graphql']):
                    api_endpoints.append(url)
                elif any(ext in url_lower for ext in ['.php', '.asp', '.jsp', '.bak', '.sql', '.env']):
                    old_files.append(url)
                elif any(p in url_lower for p in ['/login', '/register', '/signup', '/auth']):
                    interesting.append(url)

            # Report findings
            if urls:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="Historical URLs Found",
                    endpoint=self.target,
                    evidence=f"Found {len(urls)} historical URLs",
                    description=f"Wayback Machine has {len(urls)} archived URLs for {domain}",
                    remediation="Review historical endpoints for sensitive data exposure",
                ))

            if admin_paths:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Historical Admin Paths Found",
                    endpoint=self.target,
                    evidence="\n".join(admin_paths[:5]),
                    description=f"Found {len(admin_paths)} historical admin paths",
                    remediation="Check if these paths still exist and are secured",
                ))

            if api_endpoints:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Historical API Endpoints Found",
                    endpoint=self.target,
                    evidence="\n".join(api_endpoints[:5]),
                    description=f"Found {len(api_endpoints)} historical API endpoints",
                    remediation="Test old API endpoints — they may still be active",
                ))

            if old_files:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Historical Sensitive Files Found",
                    endpoint=self.target,
                    evidence="\n".join(old_files[:5]),
                    description=f"Found {len(old_files)} potentially sensitive historical files",
                    remediation="Check if these files still exist and remove if sensitive",
                ))

            # Check if old URLs still work
            if old_files:
                for url in old_files[:5]:
                    resp = await self.get(url)
                    if resp and resp.status_code == 200:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="Historical File Still Accessible",
                            endpoint=url,
                            evidence=f"HTTP 200, {len(resp.content)} bytes",
                            description=f"Old file still accessible: {url}",
                            remediation=f"Remove or restrict access to {url}",
                        ))

        except Exception:
            pass
