"""
Vexor OOB Callback Server
Built-in out-of-band server for Blind XSS and Blind SSRF detection.
Listens on a local port, generates unique callback URLs per payload.
When a callback fires, creates a confirmed finding.
"""
import asyncio
import uuid
import datetime
import socket
from typing import Callable, Optional
from dataclasses import dataclass, field


@dataclass
class CallbackHit:
    """A received OOB callback"""
    token: str
    source_ip: str
    source_port: int
    data: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    vuln_type: str = "unknown"   # "xss", "ssrf", "xxe", etc.
    target: str = ""
    param: str = ""


class VexorCallbackServer:
    """
    Lightweight HTTP server that listens for OOB callbacks.
    Each payload gets a unique token — when it fires, we know exactly
    which payload triggered it.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 7331):
        self.host = host
        self.port = port
        self._tokens: dict[str, dict] = {}   # token → metadata
        self._hits: list[CallbackHit] = []
        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._callbacks: list[Callable] = []

    def register_callback(self, fn: Callable) -> None:
        """Register a function to call when a hit arrives"""
        self._callbacks.append(fn)

    def generate_token(
        self,
        vuln_type: str = "unknown",
        target: str = "",
        param: str = "",
    ) -> tuple[str, str]:
        """
        Generate a unique token and return (token, callback_url).
        Use the callback_url as the payload value.
        """
        token = uuid.uuid4().hex[:12]
        self._tokens[token] = {
            "vuln_type": vuln_type,
            "target": target,
            "param": param,
            "created": datetime.datetime.now().isoformat(),
        }
        local_ip = self._get_local_ip()
        url = f"http://{local_ip}:{self.port}/cb/{token}"
        return token, url

    def get_hits(self) -> list[CallbackHit]:
        return list(self._hits)

    def get_hits_for_token(self, token: str) -> list[CallbackHit]:
        return [h for h in self._hits if h.token == token]

    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start the callback server"""
        if self._running:
            return
        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                self.host,
                self.port,
            )
            self._running = True
        except OSError as e:
            raise RuntimeError(f"Cannot start callback server on port {self.port}: {e}")

    async def stop(self) -> None:
        """Stop the callback server"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming HTTP connection"""
        try:
            peer = writer.get_extra_info("peername")
            source_ip   = peer[0] if peer else "unknown"
            source_port = peer[1] if peer else 0

            # Read HTTP request (up to 4KB)
            raw = await asyncio.wait_for(reader.read(4096), timeout=5)
            data = raw.decode(errors="ignore")

            # Extract token from path: GET /cb/<token> HTTP/1.1
            token = self._extract_token(data)

            # Send minimal HTTP response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n"
                "\r\nOK"
            )
            writer.write(response.encode())
            await writer.drain()

            # Record the hit
            meta = self._tokens.get(token, {})
            hit = CallbackHit(
                token=token,
                source_ip=source_ip,
                source_port=source_port,
                data=data[:500],
                vuln_type=meta.get("vuln_type", "unknown"),
                target=meta.get("target", ""),
                param=meta.get("param", ""),
            )
            self._hits.append(hit)

            # Notify listeners
            for cb in self._callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        asyncio.create_task(cb(hit))
                    else:
                        cb(hit)
                except Exception:
                    pass

        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _extract_token(self, request: str) -> str:
        """Extract token from HTTP request path — handles query strings and encoding"""
        try:
            first_line = request.split("\r\n")[0]
            # GET /cb/<token>?extra=data HTTP/1.1
            parts = first_line.split(" ")
            if len(parts) < 2:
                return "unknown"

            raw_path = parts[1]

            # Strip query string
            if "?" in raw_path:
                raw_path = raw_path.split("?")[0]

            # URL decode
            from urllib.parse import unquote
            path = unquote(raw_path)

            # Extract token from /cb/<token>
            segments = path.strip("/").split("/")
            if len(segments) >= 2 and segments[0] == "cb":
                token = segments[1].strip()
                if token and len(token) == 12:  # Our tokens are 12 hex chars
                    return token

            # Also check if token is in query string
            if "?" in parts[1]:
                qs = parts[1].split("?")[1]
                for kv in qs.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        if k == "token" and len(v) == 12:
                            return v

        except Exception:
            pass
        return "unknown"

    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


# Global singleton
_server: Optional[VexorCallbackServer] = None


def get_callback_server() -> VexorCallbackServer:
    """Get or create the global callback server"""
    global _server
    if _server is None:
        _server = VexorCallbackServer()
    return _server
