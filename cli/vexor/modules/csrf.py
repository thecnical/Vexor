"""
Vexor CSRF Scanner v3.0 - Elite Level
Token detection, SameSite analysis, Origin/Referer bypass,
CSRF PoC generation, JSON CSRF, multipart CSRF, CORS-CSRF chain
"""
import asyncio
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "_token", "authenticity_token",
    "csrf_token", "xsrf", "_csrf", "token", "nonce",
    "xsrf_token", "anti_csrf", "request_token", "form_token",
    "_xsrf", "csrfmiddlewaretoken", "csrf-token", "x-csrf-token",
    "__requestverificationtoken", "viewstate",
]


class Scanner(BaseScanner):
    """CSRF Scanner v3.0 - Elite Level"""

    MODULE_NAME = "csrf"
    MODULE_DESC = "CSRF: Token/SameSite/Origin/JSON/Multipart/PoC-Generation"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._check_forms(),
                self._check_samesite_cookies(),
                self._check_origin_validation(),
                self._check_json_csrf(),
                self._check_multipart_csrf(),
                self._check_cors_csrf_chain(),
                return_exceptions=True,
            )
        return self.findings

    async def _check_forms(self) -> None:
        """Check all POST forms for CSRF token presence and strength"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")
            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "get").lower()
                if method != "post":
                    continue

                action = form.get("action", self.target)
                form_url = urljoin(self.target, action)

                # Collect all inputs
                inputs = form.find_all("input")
                csrf_token = None
                csrf_value = None

                for inp in inputs:
                    name = inp.get("name", "").lower()
                    val = inp.get("value", "")
                    inp_type = inp.get("type", "text").lower()

                    # Check by name
                    if any(cn in name for cn in CSRF_TOKEN_NAMES):
                        csrf_token = name
                        csrf_value = val
                        break

                    # Check hidden inputs with long random-looking values
                    if inp_type == "hidden" and len(val) >= 16:
                        if re.search(r"[a-zA-Z0-9+/=_-]{16,}", val):
                            csrf_token = name
                            csrf_value = val
                            break

                if not csrf_token:
                    # Generate PoC HTML
                    poc = self._generate_csrf_poc(form_url, inputs)
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="CSRF — Missing Token in POST Form",
                        endpoint=form_url,
                        evidence=(
                            f"POST form at {form_url} has no CSRF token.\n"
                            f"PoC HTML:\n{poc}"
                        ),
                        description=(
                            f"POST form at {form_url} lacks CSRF protection. "
                            "Attacker can forge requests on behalf of authenticated users."
                        ),
                        remediation=(
                            "Add CSRF token to all state-changing forms. "
                            "Use SameSite=Strict cookie attribute. "
                            "Validate Origin/Referer headers."
                        ),
                    ))
                else:
                    # Token exists — check if it's weak (predictable)
                    if csrf_value and len(csrf_value) < 16:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="CSRF — Weak Token (Too Short)",
                            endpoint=form_url,
                            evidence=f"Token '{csrf_token}' value: '{csrf_value}' (length: {len(csrf_value)})",
                            description="CSRF token is too short and may be predictable.",
                            remediation="Use cryptographically random tokens of at least 32 characters.",
                        ))

                    # Check if token is static (same across requests)
                    resp2 = await self.get(self.target)
                    if resp2:
                        soup2 = BeautifulSoup(resp2.text, "lxml")
                        for inp2 in soup2.find_all("input"):
                            if inp2.get("name", "").lower() == csrf_token:
                                val2 = inp2.get("value", "")
                                if val2 == csrf_value and len(csrf_value) > 0:
                                    self.add_finding(Finding(
                                        severity="HIGH",
                                        module=self.MODULE_NAME,
                                        vuln="CSRF — Static Token (Not Rotated)",
                                        endpoint=form_url,
                                        evidence=(
                                            f"Token '{csrf_token}' is identical across requests: '{csrf_value}'"
                                        ),
                                        description=(
                                            "CSRF token is static and never changes. "
                                            "Attacker can reuse a leaked token indefinitely."
                                        ),
                                        remediation="Rotate CSRF tokens per-request or per-session.",
                                    ))
                                break

        except Exception:
            pass

    def _generate_csrf_poc(self, action: str, inputs) -> str:
        """Generate a CSRF proof-of-concept HTML page"""
        fields = []
        for inp in inputs:
            name = inp.get("name", "")
            val = inp.get("value", "")
            inp_type = inp.get("type", "text")
            if name and inp_type not in ["submit", "button", "reset", "image"]:
                fields.append(f'  <input type="hidden" name="{name}" value="{val}">')

        poc = f"""<html>
<body>
<h1>CSRF PoC</h1>
<form action="{action}" method="POST">
{chr(10).join(fields)}
  <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>"""
        return poc

    async def _check_samesite_cookies(self) -> None:
        """Check all cookies for SameSite attribute"""
        response = await self.get(self.target)
        if not response:
            return

        # httpx stores multiple Set-Cookie headers
        cookies_raw = []
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                cookies_raw.append(v)

        for cookie_header in cookies_raw:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()

            if "samesite" not in cookie_lower:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln=f"Cookie Missing SameSite ({cookie_name})",
                    endpoint=self.target,
                    param=cookie_name,
                    evidence=f"Set-Cookie: {cookie_header[:120]}",
                    description=(
                        f"Cookie '{cookie_name}' has no SameSite attribute. "
                        "Cross-site requests will include this cookie."
                    ),
                    remediation="Add SameSite=Strict or SameSite=Lax to all session cookies.",
                ))
            elif "samesite=none" in cookie_lower:
                if "secure" not in cookie_lower:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"SameSite=None Without Secure ({cookie_name})",
                        endpoint=self.target,
                        param=cookie_name,
                        evidence=f"Set-Cookie: {cookie_header[:120]}",
                        description="SameSite=None requires Secure flag per RFC.",
                        remediation="Add Secure flag when using SameSite=None.",
                    ))
                else:
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln=f"SameSite=None Allows Cross-Site Requests ({cookie_name})",
                        endpoint=self.target,
                        param=cookie_name,
                        evidence=f"Set-Cookie: {cookie_header[:120]}",
                        description=(
                            f"Cookie '{cookie_name}' uses SameSite=None, "
                            "allowing cross-site requests to include it."
                        ),
                        remediation="Use SameSite=Strict unless cross-site access is required.",
                    ))

    async def _check_origin_validation(self) -> None:
        """Test if server validates Origin/Referer headers on state-changing requests"""
        evil_origin = "https://evil-attacker.com"

        # Test with evil Origin
        try:
            resp = await self.post(
                self.target,
                headers={
                    "Origin": evil_origin,
                    "Referer": f"{evil_origin}/csrf.html",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=b"test=csrf_test&action=delete",
            )
            if resp and resp.status_code in [200, 201, 302]:
                # Check response doesn't contain CSRF error
                if not any(w in resp.text.lower() for w in ["csrf", "forbidden", "invalid origin", "bad request"]):
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="CSRF — No Origin Header Validation",
                        endpoint=self.target,
                        evidence=(
                            f"POST accepted from Origin: {evil_origin} "
                            f"(HTTP {resp.status_code})"
                        ),
                        description=(
                            "Server does not validate Origin header. "
                            "Cross-origin POST requests are accepted."
                        ),
                        remediation=(
                            "Validate Origin header on all state-changing requests. "
                            "Reject requests from unexpected origins."
                        ),
                    ))
        except Exception:
            pass

        # Test with no Referer (some sites check Referer)
        try:
            resp2 = await self.post(
                self.target,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "",
                },
                content=b"test=csrf_test",
            )
            if resp2 and resp2.status_code in [200, 201]:
                if not any(w in resp2.text.lower() for w in ["csrf", "forbidden", "referer"]):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="CSRF — Missing Referer Accepted",
                        endpoint=self.target,
                        evidence=f"POST with empty Referer accepted (HTTP {resp2.status_code})",
                        description="Server accepts requests with missing Referer header.",
                        remediation="Require valid Referer header on state-changing requests.",
                    ))
        except Exception:
            pass

    async def _check_json_csrf(self) -> None:
        """Test JSON-based CSRF (no CSRF token in JSON APIs)"""
        json_payloads = [
            b'{"action":"delete","id":"1"}',
            b'{"username":"attacker","role":"admin"}',
            b'{"email":"attacker@evil.com"}',
        ]

        for payload in json_payloads:
            try:
                resp = await self.post(
                    self.target,
                    content=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Origin": "https://evil-attacker.com",
                    },
                )
                if resp and resp.status_code in [200, 201]:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or "application" in content_type:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="JSON CSRF — API Accepts Cross-Origin JSON",
                            endpoint=self.target,
                            payload=payload.decode(),
                            evidence=(
                                f"JSON POST from evil origin accepted (HTTP {resp.status_code}). "
                                f"Response: {resp.text[:100]}"
                            ),
                            description=(
                                "JSON API accepts cross-origin requests without CSRF protection. "
                                "Attacker can use fetch() to send JSON CSRF attacks."
                            ),
                            remediation=(
                                "Validate Content-Type header (reject text/plain). "
                                "Implement CSRF tokens in JSON APIs. "
                                "Use SameSite=Strict cookies."
                            ),
                        ))
                        return
            except Exception:
                continue

    async def _check_multipart_csrf(self) -> None:
        """Test multipart/form-data CSRF (file upload forms)"""
        try:
            import httpx
            boundary = "VexorCSRFBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="action"\r\n\r\n'
                f"delete\r\n"
                f"--{boundary}--\r\n"
            ).encode()

            resp = await self.post(
                self.target,
                content=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Origin": "https://evil-attacker.com",
                },
            )
            if resp and resp.status_code in [200, 201]:
                if not any(w in resp.text.lower() for w in ["csrf", "forbidden", "invalid"]):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Multipart CSRF — Cross-Origin Accepted",
                        endpoint=self.target,
                        evidence=f"Multipart POST from evil origin accepted (HTTP {resp.status_code})",
                        description="Multipart form submission accepted from cross-origin.",
                        remediation="Validate Origin header and CSRF token in multipart requests.",
                    ))
        except Exception:
            pass

    async def _check_cors_csrf_chain(self) -> None:
        """Check for CORS misconfiguration that enables CSRF"""
        try:
            resp = await self.get(
                self.target,
                headers={"Origin": "https://evil-attacker.com"},
            )
            if not resp:
                return

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*" and "true" in acac.lower():
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="CORS-CSRF Chain — Wildcard + Credentials",
                    endpoint=self.target,
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    description=(
                        "CORS wildcard with credentials enables CSRF via fetch(). "
                        "Attacker can read responses from cross-origin requests."
                    ),
                    remediation=(
                        "Never combine Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true."
                    ),
                ))
            elif acao == "https://evil-attacker.com":
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="CORS — Arbitrary Origin Reflected",
                    endpoint=self.target,
                    evidence=f"Access-Control-Allow-Origin: {acao} (reflected attacker origin)",
                    description="CORS reflects arbitrary Origin header — CSRF via fetch() possible.",
                    remediation="Whitelist specific trusted origins in CORS configuration.",
                ))
        except Exception:
            pass
