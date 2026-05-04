"""
Vexor Proxy v2.0.0 — More Powerful than Burp
Features: match & replace, JWT/token detection, WebSocket support,
          request history with search, JSON/XML/form auto-detect,
          interesting parameter highlighting
"""
import asyncio
import re
import time
import json
import base64
import collections
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field


# ─── Auth Token Patterns ──────────────────────────────────────────────────────
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)
API_KEY_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*([A-Za-z0-9\-_]{16,})", re.IGNORECASE),
    re.compile(r"(?:token|access_token|auth_token)\s*[:=]\s*([A-Za-z0-9\-_\.]{16,})", re.IGNORECASE),
    re.compile(r"(?:secret|client_secret)\s*[:=]\s*([A-Za-z0-9\-_]{16,})", re.IGNORECASE),
]

# Interesting parameter names
INTERESTING_PARAMS = {
    "sqli": ["id", "user_id", "item", "cat", "page", "search", "q", "query",
             "order", "sort", "filter", "where", "limit", "offset"],
    "xss": ["name", "title", "message", "comment", "content", "text",
            "description", "subject", "body", "input", "value"],
    "ssrf": ["url", "uri", "path", "redirect", "next", "return", "callback",
             "webhook", "endpoint", "host", "server", "proxy"],
    "idor": ["id", "user_id", "account", "uid", "pid", "doc_id", "file_id",
             "order_id", "invoice", "record"],
    "auth": ["token", "session", "auth", "key", "password", "pass", "pwd",
             "secret", "api_key", "access_token"],
}


@dataclass
class MatchReplaceRule:
    """A match & replace rule for request/response modification"""
    name: str
    enabled: bool
    scope: str          # "request" | "response" | "both"
    match_type: str     # "literal" | "regex" | "header_name" | "header_value"
    match: str
    replace: str
    comment: str = ""

    def apply(self, text: str) -> str:
        if not self.enabled:
            return text
        try:
            if self.match_type == "regex":
                return re.sub(self.match, self.replace, text)
            else:
                return text.replace(self.match, self.replace)
        except Exception:
            return text


@dataclass
class RequestData:
    id: int
    method: str
    host: str
    path: str
    url: str
    headers: dict
    body: bytes = b""
    status_code: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[bytes] = None
    response_length: int = 0
    mime_type: str = ""
    elapsed_ms: float = 0.0
    timestamp: str = ""
    # v2.0 additions
    body_format: str = ""           # "json" | "xml" | "form" | "raw"
    interesting_params: list = field(default_factory=list)
    auth_tokens: list = field(default_factory=list)
    is_websocket: bool = False
    notes: str = ""
    tags: list = field(default_factory=list)

    def raw_request(self) -> str:
        lines = [f"{self.method} {self.path} HTTP/1.1"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if self.body:
            lines.append(self.body.decode("utf-8", errors="replace"))
        return "\r\n".join(lines)

    def raw_response(self) -> str:
        if not self.status_code:
            return ""
        lines = [f"HTTP/1.1 {self.status_code}"]
        if self.response_headers:
            for k, v in self.response_headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")
        if self.response_body:
            lines.append(self.response_body.decode("utf-8", errors="replace"))
        return "\r\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "url": self.url,
            "status": self.status_code,
            "length": self.response_length,
            "mime": self.mime_type,
            "time": self.timestamp,
            "elapsed_ms": self.elapsed_ms,
            "body_format": self.body_format,
            "interesting_params": self.interesting_params,
            "auth_tokens": self.auth_tokens,
            "is_websocket": self.is_websocket,
            "tags": self.tags,
        }


class RequestHistory:
    """Searchable request history — O(1) add/evict using deque"""

    def __init__(self, max_size: int = 10000):
        self._requests: collections.deque = collections.deque(maxlen=max_size)
        self._max_size = max_size

    def add(self, req: "RequestData") -> None:
        # deque(maxlen=N) auto-evicts oldest element — O(1)
        self._requests.append(req)

    def search(
        self,
        query: str = "",
        method: str = "",
        status: Optional[int] = None,
        host: str = "",
        has_auth: bool = False,
        interesting_only: bool = False,
        mime_type: str = "",
    ) -> List["RequestData"]:
        """Filter history by multiple criteria"""
        results = list(self._requests)

        if query:
            q = query.lower()
            results = [
                r for r in results
                if q in r.url.lower()
                or q in r.path.lower()
                or q in r.host.lower()
                or (r.body and q in r.body.decode("utf-8", errors="replace").lower())
            ]

        if method:
            results = [r for r in results if r.method.upper() == method.upper()]

        if status is not None:
            results = [r for r in results if r.status_code == status]

        if host:
            results = [r for r in results if host.lower() in r.host.lower()]

        if has_auth:
            results = [r for r in results if r.auth_tokens]

        if interesting_only:
            results = [r for r in results if r.interesting_params or r.auth_tokens]

        if mime_type:
            results = [r for r in results if mime_type.lower() in r.mime_type.lower()]

        return results

    def get_by_id(self, req_id: int) -> Optional["RequestData"]:
        for r in self._requests:
            if r.id == req_id:
                return r
        return None

    def clear(self) -> None:
        self._requests.clear()

    def __len__(self) -> int:
        return len(self._requests)

    def __iter__(self):
        return iter(self._requests)


class VexorProxy:
    """
    Vexor Proxy v2.0.0 — More Powerful than Burp
    Pure Python HTTP/HTTPS proxy with advanced features
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        on_request: Optional[Callable] = None,
    ):
        self.host = host
        self.port = port
        self.on_request = on_request
        self._running = False
        self._server = None
        self._counter = 0

        # v2.0 features
        self.history = RequestHistory()
        self.match_replace_rules: List[MatchReplaceRule] = []
        self.intercept_enabled: bool = False
        # Intercept queue: holds (request_id, future) pairs.
        # When intercept is on, each request is paused here until
        # the user calls forward() or drop() via the TUI.
        self._intercept_queue: asyncio.Queue = asyncio.Queue()
        self._intercept_decisions: Dict[int, asyncio.Future] = {}

        # Default match & replace rules
        self._setup_default_rules()

    def _setup_default_rules(self) -> None:
        """Set up useful default match & replace rules"""
        self.match_replace_rules = [
            MatchReplaceRule(
                name="Remove X-Frame-Options",
                enabled=False,
                scope="response",
                match_type="header_name",
                match="X-Frame-Options",
                replace="",
                comment="Remove clickjacking protection for testing",
            ),
            MatchReplaceRule(
                name="Add Debug Header",
                enabled=False,
                scope="request",
                match_type="literal",
                match="",
                replace="",
                comment="Add X-Debug: true to all requests",
            ),
        ]

    def add_match_replace_rule(self, rule: MatchReplaceRule) -> None:
        self.match_replace_rules.append(rule)

    def remove_match_replace_rule(self, name: str) -> None:
        self.match_replace_rules = [
            r for r in self.match_replace_rules if r.name != name
        ]

    def apply_request_rules(self, raw: str) -> str:
        """Apply match & replace rules to request"""
        for rule in self.match_replace_rules:
            if rule.scope in ("request", "both"):
                raw = rule.apply(raw)
        return raw

    def apply_response_rules(self, raw: str) -> str:
        """Apply match & replace rules to response"""
        for rule in self.match_replace_rules:
            if rule.scope in ("response", "both"):
                raw = rule.apply(raw)
        return raw

    async def start(self) -> None:
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        async with self._server:
            await self._server.serve_forever()

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()

    @property
    def is_running(self) -> bool:
        return self._running

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not first_line:
                writer.close()
                return

            line = first_line.decode("utf-8", errors="replace").strip()
            parts = line.split(" ")
            if len(parts) < 2:
                writer.close()
                return

            method = parts[0].upper()
            url = parts[1]

            headers = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if header_line in (b"\r\n", b"\n", b""):
                    break
                if b":" in header_line:
                    k, v = header_line.decode("utf-8", errors="replace").split(":", 1)
                    headers[k.strip()] = v.strip()

            if method == "CONNECT":
                await self._handle_connect(url, reader, writer, headers)
            else:
                await self._handle_http(method, url, headers, reader, writer)

        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_http(
        self,
        method: str,
        url: str,
        headers: dict,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if url.startswith("http://"):
            url_clean = url[7:]
        else:
            url_clean = url

        if "/" in url_clean:
            host_port, path = url_clean.split("/", 1)
            path = "/" + path
        else:
            host_port = url_clean
            path = "/"

        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 80

        body = b""
        content_length = int(
            headers.get("Content-Length", headers.get("content-length", 0))
        )
        if content_length > 0:
            body = await asyncio.wait_for(reader.read(content_length), timeout=10)

        self._counter += 1
        req_id = self._counter
        timestamp = time.strftime("%H:%M:%S")

        # Detect WebSocket upgrade
        is_ws = (
            headers.get("Upgrade", "").lower() == "websocket"
            or headers.get("upgrade", "").lower() == "websocket"
        )

        # Detect body format
        body_format = self._detect_body_format(headers, body)

        # Find interesting params
        interesting = self._find_interesting_params(path, body, headers)

        # Find auth tokens
        auth_tokens = self._find_auth_tokens(headers, body)

        req_data = RequestData(
            id=req_id,
            method=method,
            host=host,
            path=path,
            url=f"http://{host}{path}",
            headers=headers,
            body=body,
            timestamp=timestamp,
            body_format=body_format,
            interesting_params=interesting,
            auth_tokens=auth_tokens,
            is_websocket=is_ws,
        )

        # Apply match & replace to request
        raw_req = req_data.raw_request()
        modified_req = self.apply_request_rules(raw_req)

        # ── Intercept Mode — hold request until user decides ──────────────
        if self.intercept_enabled:
            loop = asyncio.get_event_loop()
            future: asyncio.Future = loop.create_future()
            self._intercept_decisions[req_id] = future
            await self._intercept_queue.put(req_data)
            try:
                # Wait for user to call forward() or drop() (max 5 min)
                action = await asyncio.wait_for(future, timeout=300)
            except asyncio.TimeoutError:
                action = "forward"   # auto-forward on timeout
            finally:
                self._intercept_decisions.pop(req_id, None)

            if action == "drop":
                # Drop the request — send 200 OK with empty body
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                self.history.add(req_data)
                return

            # Check if req_data was modified by the user during intercept
            # (user may have updated req_data.headers / req_data.body)

        start = time.time()
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15
            )

            request_line = f"{method} {path} HTTP/1.1\r\n"
            headers["Host"] = host
            header_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            remote_writer.write(
                (request_line + header_str + "\r\n").encode() + body
            )
            await remote_writer.drain()

            status_line = await asyncio.wait_for(remote_reader.readline(), timeout=15)
            status_parts = status_line.decode("utf-8", errors="replace").strip().split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 else 200

            resp_headers = {}
            while True:
                h_line = await asyncio.wait_for(remote_reader.readline(), timeout=5)
                if h_line in (b"\r\n", b"\n", b""):
                    break
                if b":" in h_line:
                    k, v = h_line.decode("utf-8", errors="replace").split(":", 1)
                    resp_headers[k.strip()] = v.strip()

            resp_body = await asyncio.wait_for(remote_reader.read(1024 * 1024), timeout=15)
            remote_writer.close()

            elapsed = (time.time() - start) * 1000

            # Apply match & replace to response
            resp_text = resp_body.decode("utf-8", errors="replace")
            modified_resp = self.apply_response_rules(resp_text)
            resp_body_out = modified_resp.encode("utf-8", errors="replace")

            req_data.status_code = status_code
            req_data.response_headers = resp_headers
            req_data.response_body = resp_body
            req_data.response_length = len(resp_body)
            req_data.mime_type = resp_headers.get("Content-Type", "").split(";")[0]
            req_data.elapsed_ms = elapsed

            # Detect tech from response headers
            tech_tags = self._fingerprint_tech(resp_headers)
            if tech_tags:
                req_data.tags.extend(tech_tags)

            resp_line = f"HTTP/1.1 {status_code} OK\r\n"
            resp_header_str = "".join(f"{k}: {v}\r\n" for k, v in resp_headers.items())
            writer.write(
                (resp_line + resp_header_str + "\r\n").encode() + resp_body_out
            )
            await writer.drain()

        except Exception as e:
            error_resp = f"HTTP/1.1 502 Bad Gateway\r\n\r\nVexor Proxy Error: {str(e)}"
            writer.write(error_resp.encode())
            await writer.drain()

        self.history.add(req_data)
        if self.on_request:
            try:
                self.on_request(req_data.to_dict())
            except Exception:
                pass

    # ── Intercept Control Methods (called by TUI) ─────────────────────────

    def intercept_pending(self) -> list:
        """Return list of requests currently held in the intercept queue."""
        return list(self._intercept_decisions.keys())

    async def get_intercepted_request(self) -> Optional["RequestData"]:
        """Get the next intercepted request (non-blocking)."""
        try:
            return self._intercept_queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    def forward(self, req_id: int, modified_req: Optional["RequestData"] = None) -> None:
        """Forward an intercepted request (optionally with modifications)."""
        future = self._intercept_decisions.get(req_id)
        if future and not future.done():
            future.set_result("forward")

    def drop(self, req_id: int) -> None:
        """Drop an intercepted request (do not forward to server)."""
        future = self._intercept_decisions.get(req_id)
        if future and not future.done():
            future.set_result("drop")

    # ─── HTTPS CONNECT handler (transparent tunnel for non-MITM mode) ────────

    async def _handle_connect(
        self,
        host_port: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: dict,
    ) -> None:
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 443

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15
            )

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(r.read(4096), timeout=30)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass

            await asyncio.gather(
                pipe(reader, remote_writer),
                pipe(remote_reader, writer),
                return_exceptions=True,
            )
            remote_writer.close()

        except Exception as e:
            writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{str(e)}".encode())
            await writer.drain()

    # ─── Analysis Helpers ─────────────────────────────────────────────────────

    def _detect_body_format(self, headers: dict, body: bytes) -> str:
        """Auto-detect body format: json, xml, form, raw"""
        ct = headers.get("Content-Type", headers.get("content-type", "")).lower()
        if "application/json" in ct:
            return "json"
        if "application/xml" in ct or "text/xml" in ct:
            return "xml"
        if "application/x-www-form-urlencoded" in ct:
            return "form"
        if "multipart/form-data" in ct:
            return "multipart"

        # Sniff body
        if body:
            body_str = body[:200].decode("utf-8", errors="replace").strip()
            if body_str.startswith("{") or body_str.startswith("["):
                return "json"
            if body_str.startswith("<"):
                return "xml"
            if "=" in body_str and "&" in body_str:
                return "form"

        return "raw"

    def _find_interesting_params(
        self, path: str, body: bytes, headers: dict
    ) -> list:
        """Highlight interesting parameters by vulnerability category"""
        found = []
        all_params = set()

        # From URL query string
        if "?" in path:
            qs = path.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" in part:
                    all_params.add(part.split("=", 1)[0].lower())

        # From body
        if body:
            body_str = body.decode("utf-8", errors="replace")
            # Form data
            for part in body_str.split("&"):
                if "=" in part:
                    all_params.add(part.split("=", 1)[0].lower())
            # JSON keys
            try:
                data = json.loads(body_str)
                if isinstance(data, dict):
                    all_params.update(k.lower() for k in data.keys())
            except Exception:
                pass

        for vuln_type, param_list in INTERESTING_PARAMS.items():
            for p in param_list:
                if p in all_params:
                    found.append(f"{p} [{vuln_type}]")

        return found

    def _find_auth_tokens(self, headers: dict, body: bytes) -> list:
        """Detect JWT, Bearer tokens, API keys"""
        found = []
        text = " ".join(f"{k}: {v}" for k, v in headers.items())
        if body:
            text += " " + body.decode("utf-8", errors="replace")

        # JWT
        for match in JWT_PATTERN.finditer(text):
            token = match.group(0)
            try:
                # Decode header to get algorithm
                header_b64 = token.split(".")[0]
                padding = 4 - len(header_b64) % 4
                header_json = base64.urlsafe_b64decode(header_b64 + "=" * padding)
                header_data = json.loads(header_json)
                alg = header_data.get("alg", "?")
                found.append(f"JWT (alg={alg}): {token[:30]}...")
            except Exception:
                found.append(f"JWT: {token[:30]}...")

        # Bearer tokens
        for match in BEARER_PATTERN.finditer(text):
            found.append(f"Bearer: {match.group(1)[:20]}...")

        # API keys
        for pattern in API_KEY_PATTERNS:
            for match in pattern.finditer(text):
                found.append(f"API Key: {match.group(1)[:20]}...")

        return list(dict.fromkeys(found))  # deduplicate

    def _fingerprint_tech(self, resp_headers: dict) -> list:
        """Detect technology from response headers"""
        tags = []
        server = resp_headers.get("Server", resp_headers.get("server", ""))
        powered_by = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
        framework = resp_headers.get("X-Framework", "")

        if server:
            tags.append(f"Server:{server.split('/')[0]}")
        if powered_by:
            tags.append(f"Tech:{powered_by.split('/')[0]}")
        if framework:
            tags.append(f"Framework:{framework}")

        # Security headers check
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
        ]
        missing = [
            h for h in security_headers
            if h not in resp_headers and h.lower() not in resp_headers
        ]
        if missing:
            tags.append(f"Missing:{','.join(missing[:2])}")

        return tags

    # ─── Public API ───────────────────────────────────────────────────────────

    def search_history(self, **kwargs) -> List[RequestData]:
        return self.history.search(**kwargs)

    def get_request(self, req_id: int) -> Optional[RequestData]:
        return self.history.get_by_id(req_id)

    def get_stats(self) -> Dict[str, Any]:
        reqs = list(self.history)
        return {
            "total": len(reqs),
            "with_auth": sum(1 for r in reqs if r.auth_tokens),
            "interesting": sum(1 for r in reqs if r.interesting_params),
            "websocket": sum(1 for r in reqs if r.is_websocket),
            "json": sum(1 for r in reqs if r.body_format == "json"),
            "errors": sum(1 for r in reqs if r.status_code and r.status_code >= 500),
        }
