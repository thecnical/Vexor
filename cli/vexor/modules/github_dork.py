"""
Vexor GitHub Dorking
Find leaked secrets in GitHub repositories
"""
import asyncio
import re
from urllib.parse import urlparse, quote
from vexor.modules.base import BaseScanner, Finding


GITHUB_SEARCH_API = "https://api.github.com/search/code"

# Dork queries for finding secrets
DORK_QUERIES = [
    'password',
    'secret',
    'api_key',
    'apikey',
    'access_token',
    'private_key',
    'database_url',
    'db_password',
    'smtp_password',
    'aws_secret',
]

# Patterns to find in GitHub results
SECRET_PATTERNS = {
    "Password": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{4,}[\'"]',
    "API Key": r'(?i)(api_key|apikey)\s*[=:]\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
    "AWS Key": r'AKIA[0-9A-Z]{16}',
    "Private Key": r'-----BEGIN.*PRIVATE KEY-----',
    "Token": r'(?i)(token|secret)\s*[=:]\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
    "Database URL": r'(?i)(mysql|postgres|mongodb)://[^\s\'"]+',
}


class Scanner(BaseScanner):
    """GitHub Secret Dorking"""

    MODULE_NAME = "github_dork"
    MODULE_DESC = "GitHub Secret and Credential Dorking"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            domain = parsed.hostname or self.target

            # Remove www
            if domain.startswith('www.'):
                domain = domain[4:]

            # Extract org/company name from domain
            org_name = domain.split('.')[0]

            await asyncio.gather(
                self._search_github(domain, org_name),
                self._check_common_repos(org_name),
                return_exceptions=True
            )
        return self.findings

    async def _search_github(self, domain: str, org: str) -> None:
        """Search GitHub for leaked secrets"""
        # Note: GitHub API requires auth for full search
        # This does basic public search

        search_terms = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{org}" database_url',
        ]

        for term in search_terms[:2]:  # Limit to avoid rate limiting
            try:
                resp = await self.get(
                    GITHUB_SEARCH_API,
                    params={'q': term, 'per_page': '5'},
                    headers={
                        'Accept': 'application/vnd.github.v3+json',
                        'User-Agent': 'Vexor-Security-Scanner',
                    }
                )

                if not resp:
                    continue

                if resp.status_code == 403:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="GitHub Search Rate Limited",
                        endpoint=self.target,
                        description="GitHub API rate limited — add GitHub token for full search",
                        remediation="Configure GitHub token in Vexor settings",
                    ))
                    return

                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get('total_count', 0)

                    if total > 0:
                        items = data.get('items', [])
                        repos = [item.get('repository', {}).get('full_name', '') for item in items]

                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"GitHub Results for: {term}",
                            endpoint=f"https://github.com/search?q={quote(term)}",
                            evidence=f"Found {total} results. Repos: {', '.join(repos[:3])}",
                            description=f"GitHub search '{term}' returned {total} results",
                            remediation=(
                                "Review GitHub results for leaked credentials. "
                                "Rotate any exposed secrets immediately."
                            ),
                        ))

            except Exception:
                pass

    async def _check_common_repos(self, org: str) -> None:
        """Check if organization has public repos with sensitive files"""
        common_sensitive_files = [
            f'https://raw.githubusercontent.com/{org}/{org}/.env',
            f'https://raw.githubusercontent.com/{org}/backend/.env',
            f'https://raw.githubusercontent.com/{org}/api/.env',
        ]

        for url in common_sensitive_files:
            resp = await self.get(url)
            if resp and resp.status_code == 200 and len(resp.content) > 10:
                # Check for actual env file content
                if '=' in resp.text and any(
                    key in resp.text.upper()
                    for key in ['KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'URL']
                ):
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="Exposed .env File on GitHub",
                        endpoint=url,
                        evidence=f"Public .env file found with {len(resp.content)} bytes",
                        description=f"Environment file exposed on GitHub: {url}",
                        remediation=(
                            "Remove .env from GitHub immediately. "
                            "Add .env to .gitignore. "
                            "Rotate all exposed credentials."
                        ),
                    ))
