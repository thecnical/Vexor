"""
Vexor WebSocket Security Tester
"""
import asyncio
import json
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


XSS_WS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]

SQLI_WS_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
]


class Scanner(BaseScanner):
    """WebSocket Security Tester"""

    MODULE_NAME = "websocket"
    MODULE_DESC = "WebSocket Security Testing"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._find_websocket_endpoints(),
                self._check_ws_origin(),
                return_exceptions=True
            )
        return self.findings

    async def _find_websocket_endpoints(self) -> None:
        """Find WebSocket endpoints in page source"""
        response = await self.get(self.target)
        if not response:
            return

        # Find WebSocket URLs in JS
        ws_pattern = re.compile(r'(wss?://[^\s\'"]+)', re.IGNORECASE)
        ws_urls = ws_pattern.findall(response.text)

        # Also look for WebSocket constructor calls
        ws_new_pattern = re.compile(
            r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE
        )
        ws_new_urls = ws_new_pattern.findall(response.text)

        all_ws = list(set(ws_urls + ws_new_urls))

        if all_ws:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="WebSocket Endpoints Found",
                endpoint=self.target,
                evidence=f"WebSocket URLs: {', '.join(all_ws[:5])}",
                description=f"Found {len(all_ws)} WebSocket endpoint(s)",
                remediation="Test WebSocket endpoints for injection and auth issues",
            ))

            # Test each WebSocket
            for ws_url in all_ws[:3]:
                await self._test_websocket(ws_url)

    async def _test_websocket(self, ws_url: str) -> None:
        """Test a WebSocket endpoint"""
        try:
            import websockets

            async with websockets.connect(ws_url, timeout=10) as ws:
                # Test XSS payloads
                for payload in XSS_WS_PAYLOADS[:2]:
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        if payload in str(response):
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln="WebSocket XSS",
                                endpoint=ws_url,
                                payload=payload,
                                evidence=f"Payload reflected in WebSocket response",
                                description="WebSocket reflects XSS payload",
                                remediation="Sanitize all WebSocket message data",
                            ))
                    except asyncio.TimeoutError:
                        pass

                # Test SQLi payloads
                for payload in SQLI_WS_PAYLOADS[:2]:
                    await ws.send(json.dumps({"message": payload}))
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        if any(err in str(response).lower() for err in
                               ['sql', 'syntax', 'mysql', 'error']):
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln="WebSocket SQL Injection",
                                endpoint=ws_url,
                                payload=payload,
                                evidence=f"SQL error in WebSocket response",
                                description="WebSocket endpoint vulnerable to SQL injection",
                                remediation="Use parameterized queries for WebSocket data",
                            ))
                    except asyncio.TimeoutError:
                        pass

        except ImportError:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="WebSocket Testing Skipped",
                endpoint=ws_url,
                evidence="websockets library not installed",
                description="Install websockets: pip install websockets",
                remediation="pip install websockets",
            ))
        except Exception:
            pass

    async def _check_ws_origin(self) -> None:
        """Check if WebSocket validates Origin header"""
        response = await self.get(self.target)
        if not response:
            return

        # Look for WebSocket upgrade in response
        upgrade = response.headers.get("upgrade", "")
        if "websocket" in upgrade.lower():
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="WebSocket — Test Origin Validation",
                endpoint=self.target,
                evidence="WebSocket upgrade detected",
                description="Test if WebSocket validates Origin header to prevent CSWSH",
                remediation="Validate Origin header in WebSocket handshake",
            ))
