"""
Vexor CSRF Scanner
Detects Cross-Site Request Forgery vulnerabilities
"""
import re
import asyncio
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """CSRF Vulnerability Scanner"""

    MODULE_NAME = "csrf"
    MODULE_DESC = "Cross-Site Request Forgery Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._check_forms(),
                self._check_samesite_cookies(),
                self._check_origin_validation(),
                return_exceptions=True
            )
        return self.findings

    async def _check_forms(self) -> None:
        """Check HTML forms for CSRF tokens"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            forms = soup.find_all('form')

            for form in forms:
                method = form.get('method', 'get').lower()
                if method != 'post':
                    continue

                # Check for CSRF token
                has_csrf = False
                csrf_names = [
                    'csrf', 'csrftoken', '_token', 'authenticity_token',
                    'csrf_token', 'xsrf', '_csrf', 'token', 'nonce'
                ]

                for inp in form.find_all('input'):
                    name = inp.get('name', '').lower()
                    inp_type = inp.get('type', '').lower()
                    if any(csrf_name in name for csrf_name in csrf_names):
                        has_csrf = True
                        break
                    if inp_type == 'hidden' and inp.get('value', ''):
                        has_csrf = True
                        break

                if not has_csrf:
                    action = form.get('action', self.target)
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Missing CSRF Token in Form",
                        endpoint=self.target,
                        param=action,
                        evidence=f"POST form without CSRF token: action={action}",
                        description="Form submits POST request without CSRF protection",
                        remediation=(
                            "Add CSRF token to all state-changing forms. "
                            "Use SameSite=Strict cookie attribute."
                        ),
                    ))
        except Exception:
            pass

    async def _check_samesite_cookies(self) -> None:
        """Check cookies for SameSite attribute"""
        response = await self.get(self.target)
        if not response:
            return

        set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(
            response.headers, 'get_list'
        ) else [response.headers.get("set-cookie", "")]

        for cookie_header in set_cookie_headers:
            if not cookie_header:
                continue

            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split('=')[0].strip()

            if 'samesite' not in cookie_lower:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Cookie Missing SameSite Attribute",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_header[:100]}",
                    description=f"Cookie '{cookie_name}' missing SameSite attribute",
                    remediation="Add SameSite=Strict or SameSite=Lax to all cookies",
                ))
            elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="SameSite=None Without Secure Flag",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_header[:100]}",
                    description="SameSite=None requires Secure flag",
                    remediation="Add Secure flag when using SameSite=None",
                ))

    async def _check_origin_validation(self) -> None:
        """Test if server validates Origin/Referer headers"""
        # Send POST with mismatched origin
        try:
            response = await self.post(
                self.target,
                headers={
                    "Origin": "https://evil-attacker.com",
                    "Referer": "https://evil-attacker.com/csrf.html",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=b"test=csrf_test"
            )

            if response and response.status_code in [200, 302, 301]:
                # Server accepted request from evil origin
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="No Origin/Referer Validation",
                    endpoint=self.target,
                    evidence=(
                        f"POST accepted from Origin: https://evil-attacker.com "
                        f"(Status: {response.status_code})"
                    ),
                    description="Server does not validate Origin or Referer headers",
                    remediation="Validate Origin and Referer headers on state-changing requests",
                ))
        except Exception:
            pass
