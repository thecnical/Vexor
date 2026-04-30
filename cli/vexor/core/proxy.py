"""
Vexor Proxy — Pure Python HTTP/HTTPS Interceptor
No mitmproxy dependency — works on any system including Python 3.13
"""
import asyncio
import ssl
import socket
import threading
import time
import re
from typing import Callable, Optional
from dataclasses import dataclass, field


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


class VexorProxy:
    """
    Pure Python HTTP/HTTPS Proxy
    Works without mitmproxy — uses raw sockets
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
        self.history: list[RequestData] = []

    async def start(self) -> None:
        """Start the proxy server"""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
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
            # Read first line
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

            # Read headers
            headers = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if header_line in (b"\r\n", b"\n", b""):
                    break
                if b":" in header_line:
                    k, v = header_line.decode("utf-8", errors="replace").split(":", 1)
                    headers[k.strip()] = v.strip()

            if method == "CONNECT":
                # HTTPS tunnel
                await self._handle_connect(url, reader, writer, headers)
            else:
                # HTTP request
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
        """Handle plain HTTP request"""
        # Parse URL
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

        # Read body if present
        body = b""
        content_length = int(headers.get("Content-Length", headers.get("content-length", 0)))
        if content_length > 0:
            body = await asyncio.wait_for(reader.read(content_length), timeout=10)

        self._counter += 1
        req_id = self._counter
        timestamp = time.strftime("%H:%M:%S")

        req_data = RequestData(
            id=req_id,
            method=method,
            host=host,
            path=path,
            url=f"http://{host}{path}",
            headers=headers,
            body=body,
            timestamp=timestamp,
        )

        # Forward request
        start = time.time()
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=15
            )

            # Send request
            request_line = f"{method} {path} HTTP/1.1\r\n"
            headers["Host"] = host
            header_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            remote_writer.write(
                (request_line + header_str + "\r\n").encode() + body
            )
            await remote_writer.drain()

            # Read response
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
            req_data.status_code = status_code
            req_data.response_headers = resp_headers
            req_data.response_body = resp_body
            req_data.response_length = len(resp_body)
            req_data.mime_type = resp_headers.get("Content-Type", "").split(";")[0]
            req_data.elapsed_ms = elapsed

            # Send response back to client
            resp_line = f"HTTP/1.1 {status_code} OK\r\n"
            resp_header_str = "".join(f"{k}: {v}\r\n" for k, v in resp_headers.items())
            writer.write(
                (resp_line + resp_header_str + "\r\n").encode() + resp_body
            )
            await writer.drain()

        except Exception as e:
            error_resp = f"HTTP/1.1 502 Bad Gateway\r\n\r\nVexor Proxy Error: {str(e)}"
            writer.write(error_resp.encode())
            await writer.drain()

        # Store and notify
        self.history.append(req_data)
        if self.on_request:
            try:
                self.on_request({
                    "id": req_id,
                    "method": method,
                    "host": host,
                    "path": path,
                    "status": req_data.status_code,
                    "length": req_data.response_length,
                    "mime": req_data.mime_type,
                    "time": timestamp,
                })
            except Exception:
                pass

    async def _handle_connect(
        self,
        host_port: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: dict,
    ) -> None:
        """Handle HTTPS CONNECT tunnel"""
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = 443

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=15
            )

            # Tell client tunnel is established
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # Bidirectional pipe
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
                return_exceptions=True
            )
            remote_writer.close()

        except Exception as e:
            writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{str(e)}".encode())
            await writer.drain()
