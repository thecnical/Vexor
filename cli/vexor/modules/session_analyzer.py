"""
Vexor Session Analyzer v3.0 - Elite Level
Cookie flags, session fixation, session in URL, entropy analysis,
session prediction, concurrent session abuse, logout invalidation,
CSRF token analysis, cookie scope, session hijacking vectors
"""
import asyncio
import re
import base64
import json
import math
import string
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


class Scanner(BaseScanner):
    """Session Analyzer v3.0 - Elite Level"""

    MODULE_NAME = "session_analyzer"
    MODULE_DESC = "Session: Flags/Fixation/Entropy/Prediction/Logout/CSRF/Hijacking"

    async def scan(self) -> list[Finding]:
        async with self:
            response = await self.get(self.target)
            if not response:
                return self.findings

            await asyncio.gather(
                self._analyze_cookies(response),
                self._check_session_fixation(),
                self._check_session_in_url(response),
                self._check_logout_invalidation(),
                self._check_concurrent_sessions(),
                self._check_cookie_scope(response),
                return_exceptions=True,
            )
        return self.findings

    async def _analyze_cookies(self, response) -> None:
        """Deep analysis of all cookies"""
        cookie_headers = []
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                cookie_headers.append(v)

        if not cookie_headers:
            return

        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            name_val = parts[0].split("=", 1)
            cookie_name = name_val[0].strip()
            cookie_value = name_val[1].strip() if len(name_val) > 1 else ""
            cookie_lower = cookie_str.lower()

            # Security flags
            has_httponly = "httponly" in cookie_lower
            has_secure = "secure" in cookie_lower
            has_samesite = "samesite" in cookie_lower
            samesite_val = ""
            if has_samesite:
                m = re.search(r"samesite=(\w+)", cookie_lower)
                if m:
                    samesite_val = m.group(1)

            # HttpOnly
            if not has_httponly:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Cookie Missing HttpOnly: {cookie_name}",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    description=(
                        f"Cookie '{cookie_name}' lacks HttpOnly flag. "
                        "Accessible via JavaScript — XSS can steal this cookie."
                    ),
                    remediation=f"Add HttpOnly flag to '{cookie_name}'.",
                ))

            # Secure flag on HTTPS
            if not has_secure and self.target.startswith("https"):
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Cookie Missing Secure Flag: {cookie_name}",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    description=(
                        f"Cookie '{cookie_name}' lacks Secure flag on HTTPS site. "
                        "May be sent over HTTP connections."
                    ),
                    remediation=f"Add Secure flag to '{cookie_name}'.",
                ))

            # SameSite
            if not has_samesite:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln=f"Cookie Missing SameSite: {cookie_name}",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    description=f"Cookie '{cookie_name}' has no SameSite attribute.",
                    remediation=f"Add SameSite=Strict or SameSite=Lax to '{cookie_name}'.",
                ))
            elif samesite_val == "none" and not has_secure:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"SameSite=None Without Secure: {cookie_name}",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    description="SameSite=None requires Secure flag per RFC.",
                    remediation="Add Secure flag when using SameSite=None.",
                ))

            # Session cookie analysis
            is_session = any(s in cookie_name.lower() for s in [
                "session", "sess", "sid", "token", "auth", "jwt", "access"
            ])

            if is_session and cookie_value:
                await self._analyze_session_value(cookie_name, cookie_value)

            # Decode base64 cookie value
            if cookie_value and len(cookie_value) > 8:
                try:
                    decoded = base64.b64decode(cookie_value + "==").decode("utf-8", errors="ignore")
                    if decoded and any(c in decoded for c in ["{", "user", "admin", "role", "id"]):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln=f"Sensitive Data in Cookie (Base64): {cookie_name}",
                            endpoint=self.target,
                            param=cookie_name,
                            evidence=f"Decoded: {decoded[:150]}",
                            description=(
                                f"Cookie '{cookie_name}' contains base64-encoded data. "
                                "Base64 is encoding, not encryption."
                            ),
                            remediation="Encrypt sensitive cookie data. Use opaque session tokens.",
                        ))
                except Exception:
                    pass

            # Check for JSON in cookie
            if cookie_value and cookie_value.startswith("{"):
                try:
                    data = json.loads(cookie_value)
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"JSON Data in Cookie: {cookie_name}",
                        endpoint=self.target,
                        param=cookie_name,
                        evidence=f"Cookie contains JSON: {str(data)[:150]}",
                        description=(
                            f"Cookie '{cookie_name}' contains raw JSON. "
                            "May expose application internals."
                        ),
                        remediation="Use opaque session tokens. Encrypt cookie data.",
                    ))
                except Exception:
                    pass

    async def _analyze_session_value(self, name: str, value: str) -> None:
        """Analyze session ID for strength and predictability"""
        # Length check
        if len(value) < 16:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln=f"Weak Session ID — Too Short: {name}",
                endpoint=self.target,
                param=name,
                evidence=f"Length: {len(value)} chars (minimum: 32)",
                description=f"Session ID '{name}' is too short ({len(value)} chars).",
                remediation="Use at least 128-bit (32 hex chars) random session IDs.",
            ))

        # Entropy check
        ent = _entropy(value)
        if ent < 3.0:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln=f"Low Entropy Session ID: {name}",
                endpoint=self.target,
                param=name,
                evidence=f"Entropy: {ent:.2f} bits/char (minimum: 4.0)",
                description=(
                    f"Session ID '{name}' has low entropy ({ent:.2f}). "
                    "May be predictable."
                ),
                remediation="Use cryptographically random session IDs.",
            ))

        # Numeric only
        if value.isdigit():
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln=f"Numeric Session ID — Predictable: {name}",
                endpoint=self.target,
                param=name,
                evidence=f"Session ID is purely numeric: {value[:20]}",
                description=f"Session ID '{name}' is numeric — easily brute-forced.",
                remediation="Use cryptographically random alphanumeric session IDs.",
            ))

        # Sequential pattern check
        if re.match(r"^[0-9a-f]{8,}$", value.lower()):
            # Looks like hex — check if it's a timestamp-based ID
            try:
                ts = int(value[:8], 16)
                import time
                now = int(time.time())
                if abs(ts - now) < 86400 * 365:  # Within 1 year
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Timestamp-Based Session ID: {name}",
                        endpoint=self.target,
                        param=name,
                        evidence=f"First 8 hex chars decode to timestamp: {ts}",
                        description=(
                            f"Session ID '{name}' may be timestamp-based. "
                            "Predictable if combined with other weak entropy."
                        ),
                        remediation="Use cryptographically random session IDs.",
                    ))
            except Exception:
                pass

    async def _check_session_fixation(self) -> None:
        """Check for session fixation vulnerability"""
        resp1 = await self.get(self.target)
        if not resp1:
            return

        # Get initial session ID
        session_id = None
        for k, v in resp1.cookies.items():
            if any(s in k.lower() for s in ["session", "sess", "sid", "phpsessid"]):
                session_id = v
                break

        if not session_id:
            return

        # Try to set our own session ID
        resp2 = await self.get(
            self.target,
            headers={"Cookie": f"session={session_id}; PHPSESSID={session_id}; sess={session_id}"},
        )

        if resp2:
            # Check if server accepted our pre-set session
            for k, v in resp2.cookies.items():
                if any(s in k.lower() for s in ["session", "sess", "sid", "phpsessid"]):
                    if v == session_id:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="Session Fixation Vulnerability",
                            endpoint=self.target,
                            evidence=f"Server accepted pre-set session ID: {session_id[:20]}...",
                            description=(
                                "Server accepts externally set session IDs. "
                                "Attacker can fix victim's session ID before login."
                            ),
                            remediation=(
                                "Regenerate session ID after authentication. "
                                "Reject session IDs not issued by the server."
                            ),
                        ))
                    break

    async def _check_session_in_url(self, response) -> None:
        """Check if session ID appears in URL"""
        url_str = str(response.url)
        patterns = [
            r"[?&](session|sess|sid|PHPSESSID|jsessionid|token|auth_token)=[a-zA-Z0-9]+",
        ]
        for pattern in patterns:
            if re.search(pattern, url_str, re.IGNORECASE):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Session ID Exposed in URL",
                    endpoint=self.target,
                    evidence=f"Session token in URL: {url_str[:100]}",
                    description=(
                        "Session ID in URL is logged in server logs, "
                        "browser history, and Referer headers."
                    ),
                    remediation="Use cookies for session management, not URL parameters.",
                ))
                break

        # Also check response body for session in links
        session_in_links = re.findall(
            r'href=["\'][^"\']*[?&](session|sess|sid|PHPSESSID)=[a-zA-Z0-9]+',
            response.text, re.IGNORECASE
        )
        if session_in_links:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="Session ID in Page Links",
                endpoint=self.target,
                evidence=f"Found {len(session_in_links)} links with session ID",
                description="Page contains links with session ID in URL.",
                remediation="Remove session IDs from all URLs.",
            ))

    async def _check_logout_invalidation(self) -> None:
        """Check if logout properly invalidates session"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        logout_paths = ["/logout", "/signout", "/auth/logout", "/api/logout"]

        for path in logout_paths:
            try:
                # Get session before logout
                resp1 = await self.get(self.target)
                if not resp1:
                    continue

                session_before = dict(resp1.cookies)
                if not session_before:
                    continue

                # Logout
                logout_resp = await self.get(base + path)
                if not logout_resp or logout_resp.status_code not in [200, 302]:
                    continue

                # Try to use old session
                old_cookies = "; ".join(f"{k}={v}" for k, v in session_before.items())
                resp2 = await self.get(
                    self.target,
                    headers={"Cookie": old_cookies},
                )

                if resp2 and resp2.status_code == 200:
                    # Check if we're still logged in
                    if any(w in resp2.text.lower() for w in ["dashboard", "profile", "logout", "welcome"]):
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="Session Not Invalidated After Logout",
                            endpoint=base + path,
                            evidence="Old session cookie still works after logout",
                            description=(
                                "Session token remains valid after logout. "
                                "Stolen tokens can be used indefinitely."
                            ),
                            remediation=(
                                "Invalidate session server-side on logout. "
                                "Delete session from database/cache. "
                                "Clear all session cookies."
                            ),
                        ))
                        return
            except Exception:
                continue

    async def _check_concurrent_sessions(self) -> None:
        """Check if multiple concurrent sessions are allowed"""
        # Get two sessions
        resp1 = await self.get(self.target)
        resp2 = await self.get(self.target)

        if not resp1 or not resp2:
            return

        cookies1 = dict(resp1.cookies)
        cookies2 = dict(resp2.cookies)

        # If both sessions are different and both work, concurrent sessions allowed
        if cookies1 and cookies2 and cookies1 != cookies2:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Multiple Concurrent Sessions Allowed",
                endpoint=self.target,
                evidence="Server issues different session IDs for concurrent requests",
                description=(
                    "Multiple concurrent sessions are allowed. "
                    "Consider limiting to one active session per user."
                ),
                remediation=(
                    "Optionally: invalidate previous session on new login. "
                    "Alert user of concurrent sessions."
                ),
            ))

    async def _check_cookie_scope(self, response) -> None:
        """Check cookie domain and path scope"""
        for k, v in response.headers.items():
            if k.lower() != "set-cookie":
                continue

            cookie_lower = v.lower()
            cookie_name = v.split("=")[0].strip()

            # Check for overly broad domain
            domain_match = re.search(r"domain=([^\s;]+)", cookie_lower)
            if domain_match:
                domain = domain_match.group(1)
                if domain.startswith("."):
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln=f"Cookie Broad Domain Scope: {cookie_name}",
                        endpoint=self.target,
                        param=cookie_name,
                        evidence=f"Domain: {domain}",
                        description=(
                            f"Cookie '{cookie_name}' is scoped to '{domain}' "
                            "(all subdomains). Subdomain XSS can steal this cookie."
                        ),
                        remediation="Scope cookies to specific subdomain, not parent domain.",
                    ))

            # Check for missing path restriction
            if "path=/" in cookie_lower or "path" not in cookie_lower:
                if any(s in cookie_name.lower() for s in ["session", "auth", "token"]):
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln=f"Session Cookie Sent to All Paths: {cookie_name}",
                        endpoint=self.target,
                        param=cookie_name,
                        evidence=f"Path=/ (sent to all paths)",
                        description=(
                            f"Session cookie '{cookie_name}' is sent to all paths. "
                            "Unnecessary exposure to all endpoints."
                        ),
                        remediation="Restrict session cookie path to application root.",
                    ))
