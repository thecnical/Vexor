"""
Vexor Repeater — Manual Request Replay Engine
Like Burp Repeater: load any request from history, edit it, send it, diff responses.
Supports HTTP and HTTPS (via MITM proxy engine).
"""
import asyncio
import ssl
import time
import difflib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class RepeaterTab:
    """A single Repeater tab — holds a request and all its responses."""
    id: int
    name: str
    host: str
    port: int
    use_https: bool

    # Current editable request
    method:  str = "GET"
    path:    str = "/"
    headers: dict = field(default_factory=dict)
    body:    bytes = b""

    # Response history (each send adds an entry)
    responses: list = field(default_factory=list)

    def raw_request(self) -> str:
        """Build the raw HTTP request string for editing."""
        lines = [f"{self.method} {self.path} HTTP/1.1"]
        if "Host" not in self.headers and "host" not in self.headers:
            self.headers["Host"] = self.host
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if self.body:
            lines.append(self.body.decode("utf-8", errors="replace"))
        return "\r\n".join(lines)

    def load_raw_request(self, raw: str) -> None:
        """Parse a raw HTTP request string back into fields."""
        lines = raw.replace("\r\n", "\n").split("\n")
        if not lines:
            return

        # Request line
        req_line = lines[0].strip().split(" ")
        if len(req_line) >= 2:
            self.method = req_line[0]
            self.path   = req_line[1]

        # Headers
        self.headers = {}
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip()] = v.strip()

        # Body
        body_lines = lines[body_start:]
        self.body  = "\n".join(body_lines).encode("utf-8")


@dataclass
class RepeaterResponse:
    """A single response recorded by the Repeater."""
    status_code: int
    headers: dict
    body: bytes
    elapsed_ms: float
    timestamp: str

    def raw(self) -> str:
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if self.body:
            lines.append(self.body.decode("utf-8", errors="replace"))
        return "\r\n".join(lines)

    def diff_against(self, other: "RepeaterResponse") -> str:
        """Unified diff between this response body and another."""
        a = self.body.decode("utf-8", errors="replace").splitlines(keepends=True)
        b = other.body.decode("utf-8", errors="replace").splitlines(keepends=True)
        diff = difflib.unified_diff(a, b, fromfile="Previous", tofile="Current", n=3)
        return "".join(diff)


class Repeater:
    """
    Vexor Repeater — send/edit/replay HTTP(S) requests manually.
    """

    def __init__(self):
        self._tabs: dict[int, RepeaterTab] = {}
        self._tab_counter = 0

    def new_tab(
        self,
        host: str,
        port: int = 80,
        use_https: bool = False,
        method: str = "GET",
        path: str = "/",
        headers: Optional[dict] = None,
        body: bytes = b"",
        name: str = "",
    ) -> RepeaterTab:
        """Create a new Repeater tab."""
        self._tab_counter += 1
        tab = RepeaterTab(
            id=self._tab_counter,
            name=name or f"Tab {self._tab_counter}",
            host=host,
            port=port,
            use_https=use_https,
            method=method,
            path=path,
            headers=dict(headers or {}),
            body=body,
        )
        self._tabs[tab.id] = tab
        return tab

    def from_history(self, req_data) -> RepeaterTab:
        """
        Create a Repeater tab from a proxy history RequestData object.
        Supports both HTTP and HTTPS entries.
        """
        use_https = req_data.url.startswith("https://")
        port      = 443 if use_https else 80

        # Extract port from host header
        host = req_data.host
        if ":" in host:
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)

        return self.new_tab(
            host=host,
            port=port,
            use_https=use_https,
            method=req_data.method,
            path=req_data.path,
            headers=dict(req_data.headers),
            body=req_data.body or b"",
            name=f"{req_data.method} {req_data.path[:30]}",
        )

    def from_raw(self, raw_request: str, host: str, port: int = 80, use_https: bool = False) -> RepeaterTab:
        """Create a tab from a raw HTTP request string."""
        tab = self.new_tab(host=host, port=port, use_https=use_https)
        tab.load_raw_request(raw_request)
        return tab

    def get_tab(self, tab_id: int) -> Optional[RepeaterTab]:
        return self._tabs.get(tab_id)

    def list_tabs(self) -> list[RepeaterTab]:
        return list(self._tabs.values())

    def close_tab(self, tab_id: int) -> None:
        self._tabs.pop(tab_id, None)

    async def send(self, tab_id: int) -> Optional[RepeaterResponse]:
        """Send the current request in a Repeater tab. Returns response."""
        tab = self._tabs.get(tab_id)
        if not tab:
            raise ValueError(f"Tab {tab_id} not found")

        return await self._send_request(tab)

    async def send_raw(self, tab_id: int, raw_request: str) -> Optional[RepeaterResponse]:
        """Parse a raw request string and send it."""
        tab = self._tabs.get(tab_id)
        if not tab:
            raise ValueError(f"Tab {tab_id} not found")
        tab.load_raw_request(raw_request)
        return await self._send_request(tab)

    async def _send_request(self, tab: RepeaterTab) -> Optional[RepeaterResponse]:
        """Actually send the HTTP(S) request and return the response."""
        start = time.time()

        try:
            if tab.use_https:
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(tab.host, tab.port, ssl=ctx, server_hostname=tab.host),
                    timeout=30,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(tab.host, tab.port),
                    timeout=30,
                )

            # Build and send request
            hdrs = dict(tab.headers)
            hdrs.setdefault("Host", tab.host)
            hdrs.setdefault("Connection", "close")
            if tab.body:
                hdrs["Content-Length"] = str(len(tab.body))

            req_line = f"{tab.method} {tab.path} HTTP/1.1\r\n"
            hdr_str  = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
            writer.write((req_line + hdr_str + "\r\n").encode() + tab.body)
            await writer.drain()

            # Read response
            status_line = await asyncio.wait_for(reader.readline(), timeout=15)
            status_parts = status_line.decode("utf-8", errors="replace").strip().split(" ", 2)
            status_code  = int(status_parts[1]) if len(status_parts) > 1 else 0

            resp_headers = {}
            content_length = 0
            transfer_encoding = ""
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if h_line in (b"\r\n", b"\n", b""):
                    break
                if b":" in h_line:
                    k, v = h_line.decode("utf-8", errors="replace").split(":", 1)
                    k, v = k.strip(), v.strip()
                    resp_headers[k] = v
                    if k.lower() == "content-length":
                        content_length = int(v)
                    if k.lower() == "transfer-encoding":
                        transfer_encoding = v.lower()

            # Read body
            if transfer_encoding == "chunked":
                resp_body = await self._read_chunked(reader)
            elif content_length > 0:
                resp_body = await asyncio.wait_for(reader.read(content_length), timeout=30)
            else:
                resp_body = await asyncio.wait_for(reader.read(4 * 1024 * 1024), timeout=30)

            writer.close()

            elapsed_ms = (time.time() - start) * 1000
            response = RepeaterResponse(
                status_code=status_code,
                headers=resp_headers,
                body=resp_body,
                elapsed_ms=elapsed_ms,
                timestamp=time.strftime("%H:%M:%S"),
            )

            tab.responses.append(response)
            return response

        except asyncio.TimeoutError:
            raise ConnectionError(f"Request timed out after 30s")
        except Exception as e:
            raise ConnectionError(f"Request failed: {e}")

    @staticmethod
    async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
        """Read HTTP chunked transfer encoded body."""
        body = b""
        while True:
            size_line = await asyncio.wait_for(reader.readline(), timeout=5)
            size = int(size_line.strip(), 16)
            if size == 0:
                break
            chunk = await asyncio.wait_for(reader.read(size), timeout=10)
            body += chunk
            await reader.readline()  # consume CRLF
        return body

    def diff_responses(self, tab_id: int, idx1: int, idx2: int) -> str:
        """Diff two historical responses for a tab."""
        tab = self._tabs.get(tab_id)
        if not tab or idx1 >= len(tab.responses) or idx2 >= len(tab.responses):
            return ""
        return tab.responses[idx1].diff_against(tab.responses[idx2])


# Global singleton
_repeater = Repeater()


def get_repeater() -> Repeater:
    return _repeater
