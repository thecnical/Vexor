"""
Vexor Rate Limit Scanner v3.0 - Elite Level
Login brute force, API rate limiting, bypass techniques,
IP rotation bypass, header bypass, account lockout detection,
credential stuffing detection, CAPTCHA bypass detection
"""
import asyncio
import time
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Rate Limit Bypass Headers ────────────────────────────────────────────────
BYPASS_HEADERS = [
    {"X-Forwarded-For": "1.2.3.4"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "1.2.3.4"},
    {"X-Originating-IP": "1.2.3.4"},
    {"X-Remote-IP": "1.2.3.4"},
    {"X-Client-IP": "1.2.3.4"},
    {"True-Client-IP": "1.2.3.4"},
    {"CF-Connecting-IP": "1.2.3.4"},
    {"X-Cluster-Client-IP": "1.2.3.4"},
    {"Forwarded": "for=1.2.3.4"},
]

# ─── Login Paths ──────────────────────────────────────────────────────────────
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/api/login",
    "/api/auth", "/api/v1/login", "/api/v1/auth",
    "/user/login", "/account/login", "/session",
    "/wp-login.php", "/admin/login",
]

# ─── API Paths ────────────────────────────────────────────────────────────────
API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/",
    "/graphql", "/rest/",
]


class Scanner(BaseScanner):
    """Rate Limit Scanner v3.0 - Elite Level"""

    MODULE_NAME = "rate_limit"
    MODULE_DESC = "Rate Limit: Login/API/Bypass/Lockout/CAPTCHA/CredentialStuffing"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_login_rate_limit(),
                self._test_api_rate_limit(),
                self._test_rate_limit_bypass(),
                self._check_account_lockout(),
                self._check_captcha(),
                return_exceptions=True,
            )
        return self.findings

    async def _test_login_rate_limit(self) -> None:
        """Test login endpoints for rate limiting"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in LOGIN_PATHS:
            url = base + path
            try:
                # Check if endpoint exists
                probe = await self.get(url)
                if not probe or probe.status_code not in [200, 405, 401, 403]:
                    continue

                # Send 15 rapid login attempts
                statuses = []
                response_times = []
                start_total = time.time()

                for i in range(15):
                    t0 = time.time()
                    resp = await self.post(
                        url,
                        data={
                            "username": f"testuser{i}@example.com",
                            "password": "wrongpassword123",
                            "email": f"testuser{i}@example.com",
                        },
                    )
                    elapsed = time.time() - t0
                    if resp:
                        statuses.append(resp.status_code)
                        response_times.append(elapsed)
                    await asyncio.sleep(0.05)

                total_time = time.time() - start_total

                if not statuses:
                    continue

                rate_limited = any(s in [429, 503, 423, 503] for s in statuses)
                blocked = any(s in [403, 423] for s in statuses[5:])

                if not rate_limited and not blocked:
                    avg_time = sum(response_times) / len(response_times)
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="No Rate Limiting on Login Endpoint",
                        endpoint=url,
                        evidence=(
                            f"15 requests in {total_time:.1f}s — no rate limiting.\n"
                            f"Status codes: {list(set(statuses))}\n"
                            f"Avg response time: {avg_time:.2f}s"
                        ),
                        description=(
                            f"Login endpoint {url} has no rate limiting. "
                            "Brute force and credential stuffing attacks are possible."
                        ),
                        remediation=(
                            "Implement rate limiting: max 5 attempts per minute per IP. "
                            "Add CAPTCHA after 3 failed attempts. "
                            "Implement account lockout (e.g., 30 min after 10 failures). "
                            "Use exponential backoff."
                        ),
                    ))
                    return
                elif rate_limited:
                    # Rate limiting exists — check if it can be bypassed
                    await self._test_rate_limit_bypass_on_url(url)
                    return

            except Exception:
                continue

    async def _test_api_rate_limit(self) -> None:
        """Test API endpoints for rate limiting"""
        # Test the main target
        statuses = []
        response_times = []
        start = time.time()

        for i in range(30):
            t0 = time.time()
            resp = await self.get(self.target)
            elapsed = time.time() - t0
            if resp:
                statuses.append(resp.status_code)
                response_times.append(elapsed)
            await asyncio.sleep(0.02)

        total_time = time.time() - start

        if not statuses:
            return

        rate_limited = any(s == 429 for s in statuses)
        has_rate_headers = False

        # Check for rate limit headers in last response
        try:
            last_resp = await self.get(self.target)
            if last_resp:
                rate_headers = [
                    "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-rate-limit-limit", "retry-after",
                    "ratelimit-limit", "ratelimit-remaining",
                ]
                resp_headers_lower = {k.lower(): v for k, v in last_resp.headers.items()}
                has_rate_headers = any(h in resp_headers_lower for h in rate_headers)
        except Exception:
            pass

        if not rate_limited and not has_rate_headers:
            avg_time = sum(response_times) / len(response_times) if response_times else 0
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="No API Rate Limiting Detected",
                endpoint=self.target,
                evidence=(
                    f"30 requests in {total_time:.1f}s — no 429 response.\n"
                    f"No rate limit headers found.\n"
                    f"Avg response time: {avg_time:.2f}s"
                ),
                description=(
                    "API endpoint has no rate limiting. "
                    "Vulnerable to scraping, brute force, and DoS."
                ),
                remediation=(
                    "Implement rate limiting on all API endpoints. "
                    "Return 429 with Retry-After header. "
                    "Add X-RateLimit-Limit and X-RateLimit-Remaining headers."
                ),
            ))
        elif rate_limited:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Rate Limiting Active",
                endpoint=self.target,
                evidence=f"429 received after {statuses.index(429) + 1} requests",
                description="Rate limiting is implemented.",
                remediation="Verify rate limit bypass techniques are not effective.",
            ))

    async def _test_rate_limit_bypass(self) -> None:
        """Test if rate limiting can be bypassed via IP spoofing headers"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find a rate-limited endpoint first
        rate_limited_url = None
        for path in LOGIN_PATHS[:3]:
            url = base + path
            try:
                # Send enough requests to trigger rate limit
                for _ in range(20):
                    resp = await self.post(url, data={"username": "test", "password": "test"})  # nosec B105
                    if resp and resp.status_code == 429:
                        rate_limited_url = url
                        break
                if rate_limited_url:
                    break
            except Exception:
                continue

        if not rate_limited_url:
            return

        await self._test_rate_limit_bypass_on_url(rate_limited_url)

    async def _test_rate_limit_bypass_on_url(self, url: str) -> None:
        """Test bypass headers on a known rate-limited URL"""
        for headers in BYPASS_HEADERS:
            try:
                # Send multiple requests with bypass header
                bypass_statuses = []
                for i in range(5):
                    # Vary the IP slightly
                    varied_headers = dict(headers)
                    for k in varied_headers:
                        if "." in varied_headers[k]:
                            parts = varied_headers[k].split(".")
                            parts[-1] = str(i + 10)
                            varied_headers[k] = ".".join(parts)

                    resp = await self.post(
                        url,
                        data={"username": f"bypass_test_{i}", "password": "test"},  # nosec B105
                        headers=varied_headers,
                    )
                    if resp:
                        bypass_statuses.append(resp.status_code)

                # If bypass worked: no 429 responses
                if bypass_statuses and 429 not in bypass_statuses:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Rate Limit Bypass via IP Spoofing Header",
                        endpoint=url,
                        evidence=(
                            f"Bypass headers: {headers}\n"
                            f"Status codes: {bypass_statuses} (no 429)"
                        ),
                        description=(
                            f"Rate limiting bypassed using {list(headers.keys())[0]} header. "
                            "Attacker can rotate IP headers to bypass rate limits."
                        ),
                        remediation=(
                            "Do not trust X-Forwarded-For or similar headers for rate limiting. "
                            "Rate limit based on authenticated user identity, not IP. "
                            "Use a WAF that validates IP headers."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _check_account_lockout(self) -> None:
        """Check if account lockout is implemented"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in LOGIN_PATHS[:3]:
            url = base + path
            try:
                probe = await self.get(url)
                if not probe or probe.status_code not in [200, 405]:
                    continue

                # Send 20 failed login attempts for same account
                lockout_detected = False
                statuses = []

                for i in range(20):
                    resp = await self.post(
                        url,
                        data={
                            "username": "admin@example.com",
                            "email": "admin@example.com",
                            "password": f"wrongpassword{i}",
                        },
                    )
                    if resp:
                        statuses.append(resp.status_code)
                        # Check for lockout indicators
                        if resp.status_code in [423, 429]:
                            lockout_detected = True
                            break
                        if any(w in resp.text.lower() for w in [
                            "locked", "too many", "temporarily", "blocked", "suspended"
                        ]):
                            lockout_detected = True
                            break
                    await asyncio.sleep(0.1)

                if not lockout_detected and len(statuses) >= 10:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="No Account Lockout After Failed Logins",
                        endpoint=url,
                        evidence=(
                            f"20 failed login attempts for same account — no lockout.\n"
                            f"Status codes: {list(set(statuses))}"
                        ),
                        description=(
                            "No account lockout after repeated failed logins. "
                            "Targeted brute force attacks are possible."
                        ),
                        remediation=(
                            "Implement account lockout after 5-10 failed attempts. "
                            "Use progressive delays (exponential backoff). "
                            "Send lockout notification email to account owner."
                        ),
                    ))
                    return

            except Exception:
                continue

    async def _check_captcha(self) -> None:
        """Check if CAPTCHA is present on sensitive forms"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")

            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                has_password = any(  # nosec B105
                    inp.get("type", "").lower() == "password" for inp in inputs  # nosec B105
                )
                if not has_password:
                    continue

                # Check for CAPTCHA indicators
                form_html = str(form).lower()
                captcha_indicators = [
                    "recaptcha", "hcaptcha", "captcha", "g-recaptcha",
                    "turnstile", "cf-turnstile", "arkose",
                ]
                has_captcha = any(ind in form_html for ind in captcha_indicators)

                if not has_captcha:
                    action = form.get("action", self.target)
                    form_url = urljoin(self.target, action)
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln="No CAPTCHA on Login Form",
                        endpoint=form_url,
                        evidence="Login form has no CAPTCHA protection",
                        description=(
                            "Login form lacks CAPTCHA. "
                            "Automated brute force attacks are easier without CAPTCHA."
                        ),
                        remediation=(
                            "Add CAPTCHA (reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) "
                            "after 3 failed login attempts."
                        ),
                    ))
                    break

        except Exception:
            pass
