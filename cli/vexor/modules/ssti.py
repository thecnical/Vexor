"""
Vexor SSTI Scanner — Server-Side Template Injection
Detects: Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


# SSTI detection payloads — each has a unique expected output
SSTI_PROBES = [
    # (payload, expected_pattern, engine)
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/EL"),
    ("#{7*7}", "49", "Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/JSP"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Spring EL"),
    ("{7*7}", "49", "Smarty"),
    ("*{7*7}", "49", "Spring"),
    ("@(7*7)", "49", "Razor"),
    ("{{config}}", "SECRET_KEY|DEBUG|DATABASE", "Jinja2 config leak"),
    ("{{self.__dict__}}", "__module__|__class__", "Jinja2 object"),
]

SSTI_PARAMS = ['name', 'template', 'msg', 'message', 'text', 'content',
               'subject', 'body', 'title', 'search', 'q', 'input']


class Scanner(BaseScanner):
    """SSTI Scanner"""

    MODULE_NAME = "ssti"
    MODULE_DESC = "Server-Side Template Injection Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            # Test existing params + common SSTI params
            test_params = list(params.keys()) + SSTI_PARAMS

            tasks = []
            for param in test_params[:10]:
                tasks.append(self._test_ssti(self.target, param))

            await asyncio.gather(*tasks, return_exceptions=True)

        return self.findings

    async def _test_ssti(self, url: str, param: str) -> None:
        for payload, expected, engine in SSTI_PROBES[:6]:
            test_url = self._inject_param(url, param, payload)
            resp = await self.get(test_url)

            if not resp:
                continue

            # Check if expected output appears in response
            if re.search(expected, resp.text, re.IGNORECASE):
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln=f"SSTI — {engine}",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=f"Payload '{payload}' evaluated to '{expected}' in response",
                    description=(
                        f"Server-Side Template Injection in '{param}'. "
                        f"Engine: {engine}. RCE possible."
                    ),
                    remediation=(
                        "Never pass user input directly to template engines. "
                        "Use sandboxed environments or escape all user input."
                    ),
                ))
                return

            # Also POST test
            resp_post = await self.post(url, data={param: payload})
            if resp_post and re.search(expected, resp_post.text, re.IGNORECASE):
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln=f"SSTI (POST) — {engine}",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=f"POST payload '{payload}' evaluated",
                    description=f"SSTI via POST in '{param}'. Engine: {engine}",
                    remediation="Sanitize all template inputs",
                ))
                return

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
