"""
Vexor File Upload Security Tester
"""
import asyncio
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


SVG_XSS = b"""<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
</svg>"""

PHP_TEST = b"<?php echo 'VEXOR_TEST_' . phpversion(); ?>"


class Scanner(BaseScanner):
    """File Upload Security Tester"""

    MODULE_NAME = "file_upload"
    MODULE_DESC = "File Upload Vulnerability Testing"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._find_upload_forms(),
                self._check_upload_endpoints(),
                return_exceptions=True
            )
        return self.findings

    async def _find_upload_forms(self) -> None:
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')

            for form in soup.find_all('form'):
                has_file = any(
                    inp.get('type', '').lower() == 'file'
                    for inp in form.find_all('input')
                )
                if not has_file:
                    continue

                action = form.get('action', self.target)
                if action.startswith('/'):
                    parsed = urlparse(self.target)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                elif not action.startswith('http'):
                    action = self.target

                for inp in form.find_all('input'):
                    if inp.get('type', '').lower() != 'file':
                        continue
                    name = inp.get('name', 'file')
                    accept = inp.get('accept', 'any')

                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="File Upload Form Found",
                        endpoint=action,
                        param=name,
                        evidence=f"Input: {name}, accept={accept}",
                        description="File upload form found — test for bypass",
                        remediation="Validate file type and content server-side",
                    ))
                    await self._test_svg_upload(action, name)
                    await self._test_php_upload(action, name)

        except Exception:
            pass

    async def _test_svg_upload(self, url: str, field: str) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                files = {field: ('test.svg', SVG_XSS, 'image/svg+xml')}
                resp = await client.post(url, files=files)
                if resp.status_code in [200, 201]:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="SVG Upload Allowed — XSS Risk",
                        endpoint=url,
                        param=field,
                        evidence="SVG file accepted",
                        description="SVG upload allowed — can contain XSS",
                        remediation="Block SVG or sanitize SVG content",
                    ))
        except Exception:
            pass

    async def _test_php_upload(self, url: str, field: str) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                files = {field: ('test.php', PHP_TEST, 'image/jpeg')}
                resp = await client.post(url, files=files)
                if resp.status_code in [200, 201]:
                    path_match = re.search(r'(/[^\s"\'<>]+\.php)', resp.text)
                    if path_match:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="PHP File Upload Bypass — RCE Risk",
                            endpoint=url,
                            param=field,
                            evidence=f"PHP uploaded to: {path_match.group(1)}",
                            description="PHP file upload bypass — Remote Code Execution possible",
                            remediation=(
                                "Validate extension AND MIME type. "
                                "Store uploads outside web root."
                            ),
                        ))
        except Exception:
            pass

    async def _check_upload_endpoints(self) -> None:
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ['/upload', '/api/upload', '/file/upload', '/media/upload']

        for path in paths:
            resp = await self.get(base + path)
            if resp and resp.status_code in [200, 405]:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="Upload Endpoint Found",
                    endpoint=base + path,
                    evidence=f"HTTP {resp.status_code}",
                    description=f"Upload endpoint at {path}",
                    remediation="Test for file type bypass",
                ))
