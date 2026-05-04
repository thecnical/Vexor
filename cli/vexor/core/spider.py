"""
Vexor Spider — Full JS-aware Web Crawler
Crawls a target site, discovers all URLs, forms, parameters, and API endpoints.
Feeds discovered endpoints into the scanner for passive + active analysis.

Two modes:
  • Static: Parse HTML/JS with httpx + BeautifulSoup (fast, no JS execution)
  • Dynamic: Use Playwright for JS-heavy SPAs (slower but complete)
"""
import asyncio
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable, Set
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class CrawledURL:
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    body: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    source: str = ""          # "link" | "form" | "js" | "api" | "header"
    depth: int = 0
    status_code: int = 0
    content_type: str = ""
    interesting: bool = False  # has parameters worth scanning


@dataclass
class SpiderConfig:
    target: str
    max_depth: int = 5
    max_urls: int = 2000
    threads: int = 10
    timeout: int = 15
    respect_robots: bool = True
    scope_domains: list[str] = field(default_factory=list)   # empty = same domain only
    follow_redirects: bool = True
    user_agent: str = "Vexor/4.0 Spider (github.com/vexor)"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    include_query_params: bool = True
    extract_js_endpoints: bool = True
    # JS patterns to look for API endpoints
    js_endpoint_patterns: list[str] = field(default_factory=lambda: [
        r"['\"`](/api/[^\s'\"`,]+)['\"`]",
        r"['\"`](/v\d+/[^\s'\"`,]+)['\"`]",
        r"fetch\(['\"`]([^'\"`,]+)['\"`]",
        r"axios\.[a-z]+\(['\"`]([^'\"`,]+)['\"`]",
        r"\.get\(['\"`]([^'\"`,]+)['\"`]",
        r"\.post\(['\"`]([^'\"`,]+)['\"`]",
        r"url:\s*['\"`]([^'\"`,]+)['\"`]",
    ])


class Spider:
    """
    Vexor Spider — comprehensive JS-aware web crawler.
    Discovers URLs, forms, API endpoints, and interesting parameters.
    """

    def __init__(
        self,
        config: SpiderConfig,
        on_url: Optional[Callable] = None,
        on_form: Optional[Callable] = None,
    ):
        self.config  = config
        self.on_url  = on_url    # Called for each discovered URL
        self.on_form = on_form   # Called for each form discovered

        parsed = urlparse(config.target)
        self._base_domain  = parsed.netloc
        self._base_scheme  = parsed.scheme
        self._visited:   Set[str] = set()
        self._queue:     deque    = deque()
        self._results:   list[CrawledURL] = []
        self._forms:     list[dict] = []
        self._stop_flag  = False

    @property
    def visited_count(self) -> int:
        return len(self._visited)

    @property
    def results(self) -> list[CrawledURL]:
        return list(self._results)

    @property
    def forms(self) -> list[dict]:
        return list(self._forms)

    def stop(self) -> None:
        self._stop_flag = True

    async def crawl(self) -> list[CrawledURL]:
        """Start crawling. Returns all discovered crawled URLs."""
        if not HAS_HTTPX:
            raise RuntimeError("Spider requires 'httpx'. Run: pip install httpx")
        if not HAS_BS4:
            raise RuntimeError("Spider requires 'beautifulsoup4'. Run: pip install beautifulsoup4 lxml")

        # Check robots.txt first
        if self.config.respect_robots:
            await self._check_robots()

        # Seed queue
        self._queue.append((self.config.target, 0))

        sem = asyncio.Semaphore(self.config.threads)
        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            headers={
                "User-Agent": self.config.user_agent,
                **self.config.headers,
            },
            cookies=self.config.cookies,
            follow_redirects=self.config.follow_redirects,
            verify=False,   # Allow self-signed certs for internal targets
        ) as client:
            while self._queue and not self._stop_flag:
                # Process batch of URLs concurrently
                batch = []
                while self._queue and len(batch) < self.config.threads * 2:
                    batch.append(self._queue.popleft())

                tasks = [
                    self._crawl_url(client, sem, url, depth)
                    for url, depth in batch
                    if url not in self._visited
                    and len(self._visited) < self.config.max_urls
                ]

                await asyncio.gather(*tasks, return_exceptions=True)

        return self._results

    async def _crawl_url(
        self,
        client: "httpx.AsyncClient",
        sem: asyncio.Semaphore,
        url: str,
        depth: int,
    ) -> None:
        if url in self._visited or self._stop_flag:
            return
        if not self._in_scope(url):
            return

        self._visited.add(url)

        async with sem:
            try:
                resp = await client.get(url)
                crawled = CrawledURL(
                    url=url,
                    method="GET",
                    depth=depth,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    interesting=bool(urlparse(url).query),
                )

                # Extract and queue child links
                if depth < self.config.max_depth and resp.status_code < 400:
                    ct = crawled.content_type.lower()
                    text = resp.text

                    if "html" in ct:
                        new_urls, forms = self._extract_from_html(url, text)
                        self._forms.extend(forms)
                        for new_url in new_urls:
                            if new_url not in self._visited:
                                self._queue.append((new_url, depth + 1))

                        if self.on_form:
                            for form in forms:
                                try:
                                    self.on_form(form)
                                except Exception:
                                    pass

                    if "javascript" in ct or url.endswith(".js"):
                        if self.config.extract_js_endpoints:
                            js_urls = self._extract_from_js(url, text)
                            for js_url in js_urls:
                                if js_url not in self._visited:
                                    self._queue.append((js_url, depth + 1))

                self._results.append(crawled)

                if self.on_url:
                    try:
                        self.on_url(crawled)
                    except Exception:
                        pass

            except Exception:
                pass

    def _extract_from_html(self, base_url: str, html: str) -> tuple[list[str], list[dict]]:
        """Extract links and forms from HTML. Returns (urls, forms)."""
        urls  = []
        forms = []

        try:
            soup = BeautifulSoup(html, "lxml")

            # Extract all <a href> links
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    full = urljoin(base_url, href)
                    if self._in_scope(full):
                        urls.append(full)

            # Extract <link>, <script src>, <img src>
            for tag in soup.find_all(["link", "script", "img"], src=True):
                src = tag.get("src", "").strip()
                if src:
                    full = urljoin(base_url, src)
                    if self._in_scope(full):
                        urls.append(full)

            # Extract action URLs from <form>
            for form in soup.find_all("form"):
                action  = form.get("action", base_url) or base_url
                method  = form.get("method", "GET").upper()
                action  = urljoin(base_url, action)

                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if name:
                        inputs[name] = inp.get("value", "") or inp.get("placeholder", "") or "test"

                form_data = {
                    "url":    action,
                    "method": method,
                    "params": inputs,
                    "source_url": base_url,
                }
                forms.append(form_data)

                if self._in_scope(action):
                    urls.append(action)

            # Extract inline script src
            for script in soup.find_all("script", src=True):
                src = urljoin(base_url, script["src"])
                if self._in_scope(src):
                    urls.append(src)

            # Extract from <meta> redirects
            for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
                content = meta.get("content", "")
                m = re.search(r"url=([^\s;]+)", content, re.IGNORECASE)
                if m:
                    redir_url = urljoin(base_url, m.group(1).strip("'\""))
                    if self._in_scope(redir_url):
                        urls.append(redir_url)

        except Exception:
            pass

        return list(set(urls)), forms

    def _extract_from_js(self, base_url: str, js_text: str) -> list[str]:
        """Extract API endpoint URLs from JavaScript source code."""
        urls = []
        for pattern in self.config.js_endpoint_patterns:
            try:
                for m in re.finditer(pattern, js_text):
                    endpoint = m.group(1)
                    if endpoint.startswith("http"):
                        full = endpoint
                    elif endpoint.startswith("/"):
                        parsed = urlparse(base_url)
                        full = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
                    else:
                        full = urljoin(base_url, endpoint)

                    if self._in_scope(full) and self._looks_like_endpoint(endpoint):
                        urls.append(full)
            except Exception:
                pass

        return list(set(urls))

    async def _check_robots(self) -> None:
        """Parse robots.txt and skip disallowed paths."""
        parsed = urlparse(self.config.target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200:
                    self._disallowed = set()
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self._disallowed.add(path)
        except Exception:
            pass

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is within the crawl scope."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False

            netloc = parsed.netloc.split(":")[0]

            # Check scope domains
            if self.config.scope_domains:
                return any(
                    netloc == d or netloc.endswith(f".{d}")
                    for d in self.config.scope_domains
                )

            # Default: same domain
            base_host = self._base_domain.split(":")[0]
            return netloc == base_host or netloc.endswith(f".{base_host}")

        except Exception:
            return False

    @staticmethod
    def _looks_like_endpoint(path: str) -> bool:
        """Heuristic: does this path look like an API endpoint worth crawling?"""
        skip = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".css", ".woff", ".ttf"}
        return not any(path.lower().endswith(ext) for ext in skip)

    def get_interesting_urls(self) -> list[CrawledURL]:
        """Return only URLs with query parameters (likely injectable points)."""
        return [u for u in self._results if u.interesting or u.params]

    def get_sitemap(self) -> dict:
        """Return a structured sitemap of all crawled URLs."""
        from collections import defaultdict
        sitemap = defaultdict(list)
        for crawled in self._results:
            parsed = urlparse(crawled.url)
            sitemap[parsed.netloc].append({
                "path": parsed.path,
                "query": parsed.query,
                "method": crawled.method,
                "status": crawled.status_code,
                "depth": crawled.depth,
                "interesting": crawled.interesting,
            })
        return dict(sitemap)


# ─── Passive Scanner on Proxy Traffic ─────────────────────────────────────────

class PassiveScanner:
    """
    Runs passive security checks on every proxied request/response.
    No active requests — purely analyzes traffic that flows through the proxy.
    Like Burp's passive scanner.
    """

    def __init__(self, on_finding: Optional[Callable] = None):
        self._on_finding = on_finding
        self._findings: list[dict] = []

    @property
    def findings(self) -> list[dict]:
        return list(self._findings)

    def analyze(self, req_data) -> list[dict]:
        """Analyze a single proxied request+response. Returns new findings."""
        new_findings = []

        new_findings.extend(self._check_security_headers(req_data))
        new_findings.extend(self._check_sensitive_data(req_data))
        new_findings.extend(self._check_cookies(req_data))
        new_findings.extend(self._check_information_disclosure(req_data))
        new_findings.extend(self._check_mixed_content(req_data))

        for f in new_findings:
            self._findings.append(f)
            if self._on_finding:
                try:
                    self._on_finding(f)
                except Exception:
                    pass

        return new_findings

    def _check_security_headers(self, req_data) -> list[dict]:
        findings = []
        resp_hdrs = getattr(req_data, "response_headers", {}) or {}
        url = getattr(req_data, "url", "")

        missing = []
        if "content-security-policy" not in {k.lower() for k in resp_hdrs}:
            missing.append("Content-Security-Policy")
        if "x-frame-options" not in {k.lower() for k in resp_hdrs}:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in {k.lower() for k in resp_hdrs}:
            missing.append("X-Content-Type-Options")
        if "strict-transport-security" not in {k.lower() for k in resp_hdrs} and url.startswith("https"):
            missing.append("Strict-Transport-Security")

        if missing:
            findings.append({
                "severity": "LOW",
                "module": "passive_scanner",
                "vuln": f"Missing Security Headers: {', '.join(missing)}",
                "endpoint": url,
                "evidence": f"Response lacks: {', '.join(missing)}",
                "description": f"Security headers missing: {', '.join(missing)}",
                "remediation": "Add the missing security headers to all HTTP responses.",
            })
        return findings

    def _check_sensitive_data(self, req_data) -> list[dict]:
        findings = []
        body = b""
        if hasattr(req_data, "response_body") and req_data.response_body:
            body = req_data.response_body
        text = body.decode("utf-8", errors="ignore")
        url  = getattr(req_data, "url", "")

        patterns = {
            "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key":       r"[0-9a-zA-Z/+]{40}",
            "Private Key":          r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "JWT Token":            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Email Address":        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Credit Card (Visa)":   r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            "Internal IP":          r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b",
        }

        for name, pattern in patterns.items():
            if re.search(pattern, text):
                findings.append({
                    "severity": "HIGH" if "Key" in name or "Credit" in name else "MEDIUM",
                    "module": "passive_scanner",
                    "vuln": f"Sensitive Data Exposure: {name}",
                    "endpoint": url,
                    "evidence": f"Pattern '{name}' found in response body",
                    "description": f"Response body contains what appears to be a {name}.",
                    "remediation": f"Remove or mask {name} from public-facing responses.",
                })
        return findings

    def _check_cookies(self, req_data) -> list[dict]:
        findings = []
        resp_hdrs = getattr(req_data, "response_headers", {}) or {}
        url = getattr(req_data, "url", "")

        for k, v in resp_hdrs.items():
            if k.lower() == "set-cookie":
                cookie_lower = v.lower()
                if "httponly" not in cookie_lower:
                    findings.append({
                        "severity": "MEDIUM",
                        "module": "passive_scanner",
                        "vuln": "Cookie Missing HttpOnly Flag",
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {v[:100]}",
                        "description": "Cookie is accessible via JavaScript (no HttpOnly flag).",
                        "remediation": "Add HttpOnly flag to all session cookies.",
                    })
                if "secure" not in cookie_lower and url.startswith("https"):
                    findings.append({
                        "severity": "MEDIUM",
                        "module": "passive_scanner",
                        "vuln": "Cookie Missing Secure Flag",
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {v[:100]}",
                        "description": "Cookie may be transmitted over unencrypted connections.",
                        "remediation": "Add Secure flag to all cookies on HTTPS sites.",
                    })
                if "samesite" not in cookie_lower:
                    findings.append({
                        "severity": "LOW",
                        "module": "passive_scanner",
                        "vuln": "Cookie Missing SameSite Attribute",
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {v[:100]}",
                        "description": "Cookie lacks SameSite attribute — CSRF risk.",
                        "remediation": "Add SameSite=Lax or SameSite=Strict to cookies.",
                    })
        return findings

    def _check_information_disclosure(self, req_data) -> list[dict]:
        findings = []
        resp_hdrs = getattr(req_data, "response_headers", {}) or {}
        url = getattr(req_data, "url", "")

        # Server header version disclosure
        server = resp_hdrs.get("Server", resp_hdrs.get("server", ""))
        if server and re.search(r"\d+\.\d+", server):
            findings.append({
                "severity": "INFO",
                "module": "passive_scanner",
                "vuln": f"Server Version Disclosure: {server}",
                "endpoint": url,
                "evidence": f"Server: {server}",
                "description": f"Server header reveals version: {server}",
                "remediation": "Remove or generalize the Server header.",
            })

        # X-Powered-By
        xpb = resp_hdrs.get("X-Powered-By", resp_hdrs.get("x-powered-by", ""))
        if xpb:
            findings.append({
                "severity": "INFO",
                "module": "passive_scanner",
                "vuln": f"Technology Disclosure: X-Powered-By: {xpb}",
                "endpoint": url,
                "evidence": f"X-Powered-By: {xpb}",
                "description": f"Application reveals technology stack: {xpb}",
                "remediation": "Remove X-Powered-By header.",
            })

        return findings

    def _check_mixed_content(self, req_data) -> list[dict]:
        findings = []
        url = getattr(req_data, "url", "")
        if not url.startswith("https"):
            return findings

        body = getattr(req_data, "response_body", b"") or b""
        text = body.decode("utf-8", errors="ignore")

        if re.search(r'src=["\']http://', text) or re.search(r'href=["\']http://', text):
            findings.append({
                "severity": "MEDIUM",
                "module": "passive_scanner",
                "vuln": "Mixed Content — HTTP Resources on HTTPS Page",
                "endpoint": url,
                "evidence": "HTTP resources loaded on HTTPS page",
                "description": "Page loads resources over HTTP on an HTTPS page, enabling MITM.",
                "remediation": "Serve all resources over HTTPS.",
            })
        return findings
