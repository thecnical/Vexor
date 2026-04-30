"""
Vexor Auth Bypass Scanner
Authentication and Authorization Bypass Detection
"""
import asyncio
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


# Common admin/protected paths
ADMIN_PATHS = [
    '/admin', '/admin/', '/admin/login', '/admin/dashboard',
    '/administrator', '/wp-admin', '/wp-login.php',
    '/dashboard', '/panel', '/cpanel', '/manager',
    '/api/admin', '/api/v1/admin', '/api/users',
    '/config', '/setup', '/install', '/backup',
    '/phpmyadmin', '/pma', '/mysql',
    '/console', '/shell', '/cmd',
    '/.env', '/.git/config', '/config.php',
    '/web.config', '/app.config',
]

# Auth bypass headers
BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Originating-IP": "127.0.0.1"},
]

# Default credentials
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("administrator", "administrator"),
]


class Scanner(BaseScanner):
    """Auth Bypass Scanner"""

    MODULE_NAME = "auth_bypass"
    MODULE_DESC = "Authentication Bypass Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._check_exposed_admin_paths(),
                self._test_header_bypass(),
                self._check_default_credentials(),
                self._check_path_traversal_auth(),
                return_exceptions=True
            )
        return self.findings

    async def _check_exposed_admin_paths(self) -> None:
        """Check for exposed admin/sensitive paths"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tasks = []
        for path in ADMIN_PATHS:
            tasks.append(self._check_path(base, path))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_path(self, base: str, path: str) -> None:
        url = base + path
        resp = await self.get(url)
        if not resp:
            return

        if resp.status_code == 200 and len(resp.content) > 100:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="Exposed Sensitive Path",
                endpoint=url,
                evidence=f"Status: {resp.status_code}, Length: {len(resp.content)}",
                description=f"Sensitive path '{path}' is publicly accessible",
                remediation="Restrict access to admin/sensitive paths with authentication",
            ))
        elif resp.status_code == 403:
            # 403 might be bypassable
            self.add_finding(Finding(
                severity="LOW",
                module=self.MODULE_NAME,
                vuln="Forbidden Path Found — Test for Bypass",
                endpoint=url,
                evidence=f"Status: 403 — may be bypassable",
                description=f"Path '{path}' returns 403 — test header bypass techniques",
                remediation="Ensure 403 cannot be bypassed via header manipulation",
            ))

    async def _test_header_bypass(self) -> None:
        """Test header-based auth bypass"""
        # First get normal response
        normal_resp = await self.get(self.target)
        if not normal_resp:
            return

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        admin_url = base + "/admin"

        # Check if admin returns 403
        admin_resp = await self.get(admin_url)
        if not admin_resp or admin_resp.status_code not in [401, 403]:
            return

        # Try bypass headers
        for headers in BYPASS_HEADERS:
            resp = await self.get(admin_url, headers=headers)
            if resp and resp.status_code == 200 and len(resp.content) > 100:
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="Authentication Bypass via Header",
                    endpoint=admin_url,
                    evidence=f"Bypass with headers: {headers}",
                    description=f"Admin access bypassed using headers: {headers}",
                    remediation=(
                        "Do not trust X-Forwarded-For or similar headers for auth. "
                        "Implement proper server-side authentication."
                    ),
                ))
                return

    async def _check_default_credentials(self) -> None:
        """Test for default credentials on login forms"""
        response = await self.get(self.target)
        if not response:
            return

        # Find login forms
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')

            login_forms = []
            for form in soup.find_all('form'):
                inputs = form.find_all('input')
                has_password = any(
                    inp.get('type', '').lower() == 'password'
                    for inp in inputs
                )
                if has_password:
                    login_forms.append(form)

            if not login_forms:
                return

            for form in login_forms[:1]:  # Test first login form
                action = form.get('action', self.target)
                if action.startswith('/'):
                    parsed = urlparse(self.target)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                elif not action.startswith('http'):
                    action = self.target

                # Get field names
                username_field = None
                password_field = None
                for inp in form.find_all('input'):
                    inp_type = inp.get('type', 'text').lower()
                    inp_name = inp.get('name', '')
                    if inp_type in ['text', 'email'] and not username_field:
                        username_field = inp_name
                    elif inp_type == 'password':
                        password_field = inp_name

                if not username_field or not password_field:
                    return

                # Test default creds
                for username, password in DEFAULT_CREDS[:5]:
                    resp = await self.post(
                        action,
                        data={username_field: username, password_field: password}
                    )
                    if resp and resp.status_code in [200, 302]:
                        # Check if login was successful
                        if self._looks_like_success(resp):
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="Default Credentials Work",
                                endpoint=action,
                                evidence=f"Login successful with {username}:{password}",
                                description=f"Default credentials work: {username}:{password}",
                                remediation="Change default credentials immediately",
                            ))
                            return

        except Exception:
            pass

    async def _check_path_traversal_auth(self) -> None:
        """Test path traversal to bypass auth"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        bypass_paths = [
            "/admin/..;/",
            "/admin/%2e%2e/",
            "/admin/./",
            "/%61dmin",  # URL encoded 'a'
            "/ADMIN",
            "/Admin",
        ]

        for path in bypass_paths:
            url = base + path
            resp = await self.get(url)
            if resp and resp.status_code == 200 and len(resp.content) > 200:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Auth Bypass via Path Manipulation",
                    endpoint=url,
                    evidence=f"Path '{path}' returned 200",
                    description="Authentication bypassed via path manipulation",
                    remediation="Normalize paths before authentication checks",
                ))

    def _looks_like_success(self, resp) -> bool:
        """Heuristic to detect successful login"""
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile',
            'account', 'settings', 'admin', 'panel'
        ]
        text_lower = resp.text.lower()
        return any(ind in text_lower for ind in success_indicators)
