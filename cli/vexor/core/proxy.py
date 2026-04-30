"""
Vexor Proxy — HTTP/HTTPS Interceptor
Uses mitmproxy for man-in-the-middle interception
"""
import asyncio
import threading
from typing import Callable, Optional
from dataclasses import dataclass, field
import time

try:
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


@dataclass
class RequestData:
    """Captured HTTP request/response data"""
    id: int
    method: str
    host: str
    path: str
    url: str
    headers: dict
    body: bytes
    status_code: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[bytes] = None
    response_length: int = 0
    mime_type: str = ""
    elapsed_ms: float = 0.0
    timestamp: str = ""


class VexorAddon:
    """mitmproxy addon for Vexor"""

    def __init__(self, on_request: Optional[Callable] = None):
        self.on_request_cb = on_request
        self._counter = 0

    def request(self, flow: "http.HTTPFlow") -> None:
        self._counter += 1
        if self.on_request_cb:
            data = {
                "id": self._counter,
                "method": flow.request.method,
                "host": flow.request.host,
                "path": flow.request.path,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "body": flow.request.content,
                "timestamp": time.strftime("%H:%M:%S"),
            }
            self.on_request_cb(data)

    def response(self, flow: "http.HTTPFlow") -> None:
        if self.on_request_cb and flow.response:
            data = {
                "id": self._counter,
                "status": flow.response.status_code,
                "length": len(flow.response.content),
                "mime": flow.response.headers.get("content-type", ""),
                "time": time.strftime("%H:%M:%S"),
            }
            self.on_request_cb(data)


class VexorProxy:
    """
    Vexor HTTP/HTTPS Proxy
    Intercepts all traffic between browser and target
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        on_request: Optional[Callable] = None
    ):
        self.host = host
        self.port = port
        self.on_request = on_request
        self._master = None
        self._running = False
        self._history: list[RequestData] = []

    async def start(self) -> None:
        """Start the proxy server"""
        if not MITMPROXY_AVAILABLE:
            raise RuntimeError(
                "mitmproxy not installed. Run: pip install mitmproxy"
            )

        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True,
        )

        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._master.addons.add(VexorAddon(on_request=self.on_request))
        self._running = True

        try:
            await self._master.run()
        except KeyboardInterrupt:
            self._master.shutdown()
        finally:
            self._running = False

    def stop(self) -> None:
        """Stop the proxy"""
        if self._master:
            self._master.shutdown()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def get_history(self) -> list:
        return self._history
