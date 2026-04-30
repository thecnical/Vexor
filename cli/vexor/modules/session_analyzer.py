"""
Vexor Session/Cookie Security Analyzer
"""
import asyncio
import re
import base64
import json
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """Session and Cookie Security Analyzer"""

    MODULE_NAME = "session_analyzer"
    MODULE_DESC = "Session and Cookie Security Analysis"

    async def scan(self) -> list[Finding]:
        async with self:
            response = await self.get(self.target)
            if not response:
                return self.findings

            await asyncio.gather(
                self._analyze_cookies(response),
                self._check_session_fixation(),
                self._check_session_in_url(),
                return_exceptions=True
            )
        return self.findings

    async def _analyze_cookies(self, response) -> None:
        """Analyze all cookies for security issues"""
        cookies = response.cookies

        # Parse cookies from headers — httpx returns multiple set-cookie headers
        cookie_headers = []
        for key, val in response.headers.multi_items():
            if key.lower() == 'set-cookie':
                cookie_headers.append(val)

        if not cookies and not cookie_headers:
            return

        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(';')]
            if not parts:
                continue

            name_val = parts[0].split('=', 1)
            cookie_name = name_val[0].strip()
            cookie_value = name_val[1].strip() if len(name_val) > 1 else ''

            cookie_lower = cookie_str.lower()
            flags = {
                'httponly': 'httponly' in cookie_lower,
                'secure': 'secure' in cookie_lower,
                'samesite': 'samesite' in cookie_lower,
            }

            # Check HttpOnly
            if not flags['httponly']:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Cookie Missing HttpOnly Flag",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    description=f"Cookie '{cookie_name}' missing HttpOnly — accessible via JS",
                    remediation=f"Add HttpOnly flag to cookie '{cookie_name}'",
                ))

            # Check Secure flag
            if not flags['secure'] and self.target.startswith('https'):
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Cookie Missing Secure Flag",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    description=f"Cookie '{cookie_name}' missing Secure flag on HTTPS site",
                    remediation=f"Add Secure flag to cookie '{cookie_name}'",
                ))

            # Check SameSite
            if not flags['samesite']:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln="Cookie Missing SameSite Attribute",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    description=f"Cookie '{cookie_name}' missing SameSite attribute",
                    remediation=f"Add SameSite=Strict or SameSite=Lax to '{cookie_name}'",
                ))

            # Check for weak session ID
            if any(s in cookie_name.lower() for s in ['session', 'sess', 'sid', 'token', 'auth']):
                await self._check_session_strength(cookie_name, cookie_value)

            # Check for base64 encoded data
            if cookie_value:
                try:
                    decoded = base64.b64decode(cookie_value + '==').decode('utf-8', errors='ignore')
                    if decoded and ('{' in decoded or 'user' in decoded.lower()):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="Sensitive Data in Cookie (Base64)",
                            endpoint=self.target,
                            param=cookie_name,
                            evidence=f"Decoded: {decoded[:100]}",
                            description=f"Cookie '{cookie_name}' contains base64-encoded data",
                            remediation="Encrypt sensitive cookie data, don't just encode it",
                        ))
                except Exception:
                    pass

    async def _check_session_strength(self, name: str, value: str) -> None:
        """Check session ID strength"""
        if len(value) < 16:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="Weak Session ID — Too Short",
                endpoint=self.target,
                param=name,
                evidence=f"Session ID length: {len(value)} chars",
                description=f"Session ID '{name}' is too short ({len(value)} chars)",
                remediation="Use at least 128-bit (32 hex chars) random session IDs",
            ))

        # Check for sequential/predictable patterns
        if value.isdigit():
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="Predictable Session ID — Numeric Only",
                endpoint=self.target,
                param=name,
                evidence=f"Session ID is purely numeric: {value[:20]}",
                description=f"Session ID '{name}' is numeric — potentially predictable",
                remediation="Use cryptographically random session IDs",
            ))

    async def _check_session_fixation(self) -> None:
        """Check for session fixation vulnerability"""
        # Get initial session
        resp1 = await self.get(self.target)
        if not resp1:
            return

        session1 = resp1.cookies.get('session') or resp1.cookies.get('PHPSESSID') or ''

        if not session1:
            return

        # Try to set our own session ID
        resp2 = await self.get(
            self.target,
            headers={"Cookie": f"session={session1}; PHPSESSID={session1}"}
        )

        if resp2:
            session2 = resp2.cookies.get('session') or resp2.cookies.get('PHPSESSID') or ''
            if session2 == session1:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Potential Session Fixation",
                    endpoint=self.target,
                    evidence="Server accepted pre-set session ID",
                    description="Server may accept externally set session IDs",
                    remediation="Regenerate session ID after authentication",
                ))

    async def _check_session_in_url(self) -> None:
        """Check if session ID appears in URL"""
        response = await self.get(self.target)
        if not response:
            return

        full_url = str(response.url)
        url_session_patterns = [
            r'[?&](session|sess|sid|PHPSESSID|jsessionid)=[a-zA-Z0-9]+',
            r'[?&](token|auth_token)=[a-zA-Z0-9]+',
        ]

        for pattern in url_session_patterns:
            if re.search(pattern, full_url, re.IGNORECASE):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Session ID in URL",
                    endpoint=self.target,
                    evidence="Session token found in URL",
                    description="Session ID exposed in URL — logged in server logs, referrer headers",
                    remediation="Use cookies instead of URL parameters for session management",
                ))
                break
