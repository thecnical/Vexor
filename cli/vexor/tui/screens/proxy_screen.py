"""
Vexor Proxy Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive
import asyncio


class ProxyScreen(Widget):
    """HTTP/HTTPS Proxy Interceptor Screen"""

    DEFAULT_CSS = """
    ProxyScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .proxy-controls {
        height: 6;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .traffic-table {
        height: 15;
        border: solid #1a1a2e;
    }
    .request-panel {
        height: 15;
        border: solid #00ffff;
        padding: 1;
    }
    .response-panel {
        height: 15;
        border: solid #ff00ff;
        padding: 1;
    }
    """

    proxy_running = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_cyan]◈ PROXY INTERCEPTOR[/]  [dim]HTTP/HTTPS Man-in-the-Middle[/]")

        # Controls
        with Container(classes="proxy-controls"):
            with Horizontal():
                yield Input(value="127.0.0.1", id="proxy-host", placeholder="Host")
                yield Input(value="8080", id="proxy-port", placeholder="Port")
                yield Button("▶ Start Proxy", id="btn-start-proxy", classes="success")
                yield Button("■ Stop Proxy", id="btn-stop-proxy", classes="danger")
                yield Button("⊘ Clear", id="btn-clear-proxy")
            yield Static(
                "[dim]Configure browser proxy: 127.0.0.1:8080 | "
                "Install CA cert for HTTPS interception[/]",
                id="proxy-status"
            )

        # Traffic table
        yield Static("[bold bright_magenta]◈ HTTP HISTORY[/]")
        table = DataTable(classes="traffic-table", id="traffic-table")
        table.add_columns(
            "#", "Method", "Host", "Path",
            "Status", "Length", "MIME", "Time"
        )
        yield table

        # Request/Response panels
        with Horizontal():
            with Container(classes="request-panel"):
                yield Static("[bold bright_cyan]REQUEST[/]")
                yield TextArea(
                    "Select a request from history above...",
                    id="request-editor",
                )
                with Horizontal():
                    yield Button("→ Send to Repeater", id="btn-to-repeater")
                    yield Button("→ Send to Intruder", id="btn-to-intruder")
                    yield Button("🤖 AI Analyze", id="btn-ai-analyze")

            with Container(classes="response-panel"):
                yield Static("[bold bright_magenta]RESPONSE[/]")
                yield TextArea(
                    "Response will appear here...",
                    id="response-viewer",
                )
                with Horizontal():
                    yield Button("→ Send to Comparer", id="btn-to-comparer")
                    yield Button("💾 Save", id="btn-save-response")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start-proxy":
            self.start_proxy()
        elif event.button.id == "btn-stop-proxy":
            self.stop_proxy()

    @work(exclusive=True)
    async def start_proxy(self) -> None:
        """Start mitmproxy"""
        host = self.query_one("#proxy-host", Input).value
        port = int(self.query_one("#proxy-port", Input).value)

        self.proxy_running = True
        self.query_one("#proxy-status").update(
            f"[bright_green]● Proxy running on {host}:{port}[/]  "
            f"[dim]Configure browser to use this proxy[/]"
        )
        self.notify(f"Proxy started on {host}:{port}", severity="information")

        try:
            from vexor.core.proxy import VexorProxy
            proxy = VexorProxy(host=host, port=port)
            proxy.on_request = self._on_request
            await proxy.start()
        except Exception as e:
            self.notify(f"Proxy error: {str(e)}", severity="error")
            self.proxy_running = False

    def stop_proxy(self) -> None:
        self.proxy_running = False
        self.query_one("#proxy-status").update(
            "[bright_red]● Proxy stopped[/]"
        )
        self.notify("Proxy stopped", severity="warning")

    def _on_request(self, request_data: dict) -> None:
        """Called when proxy intercepts a request"""
        table = self.query_one("#traffic-table", DataTable)
        table.add_row(
            str(table.row_count + 1),
            f"[bright_cyan]{request_data.get('method', 'GET')}[/]",
            request_data.get('host', ''),
            request_data.get('path', '/'),
            f"[bright_green]{request_data.get('status', '---')}[/]",
            str(request_data.get('length', 0)),
            request_data.get('mime', ''),
            request_data.get('time', ''),
        )
