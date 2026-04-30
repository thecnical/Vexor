"""
Vexor Proxy Screen — Fixed responsive layout
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
from textual.reactive import reactive
import asyncio


class ProxyScreen(Widget):

    DEFAULT_CSS = """
    ProxyScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .proxy-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .proxy-controls {
        height: 6;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .proxy-btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .traffic-table {
        height: 12;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .req-resp-row {
        height: 18;
        margin-bottom: 1;
    }
    .request-panel {
        border: solid #00ffff;
        padding: 1;
    }
    .response-panel {
        border: solid #ff00ff;
        padding: 1;
    }
    .req-textarea {
        height: 10;
    }
    .btn-row {
        height: 3;
        margin-top: 1;
    }
    """

    proxy_running = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ PROXY INTERCEPTOR[/]  [dim]HTTP/HTTPS Man-in-the-Middle[/]",
            classes="proxy-title"
        )

        with Container(classes="proxy-controls"):
            with Horizontal(classes="proxy-btn-row"):
                yield Input(value="127.0.0.1", id="proxy-host", placeholder="Host")
                yield Input(value="8080", id="proxy-port", placeholder="Port")
                yield Button("▶ Start", id="btn-start-proxy", classes="success")
                yield Button("■ Stop", id="btn-stop-proxy", classes="danger")
                yield Button("⊘ Clear", id="btn-clear-proxy")
            yield Static(
                "[dim]Configure browser: 127.0.0.1:8080[/]",
                id="proxy-status"
            )

        yield Static("[bold bright_magenta]◈ HTTP HISTORY[/]")
        table = DataTable(classes="traffic-table", id="traffic-table")
        table.add_columns("#", "Method", "Host", "Path", "Status", "Length", "MIME", "Time")
        yield table

        with Horizontal(classes="req-resp-row"):
            with Container(classes="request-panel"):
                yield Static("[bold bright_cyan]REQUEST[/]")
                yield TextArea(
                    "Select a request from history above...",
                    id="request-editor",
                    classes="req-textarea"
                )
                with Horizontal(classes="btn-row"):
                    yield Button("→ Repeater", id="btn-to-repeater")
                    yield Button("→ Intruder", id="btn-to-intruder")
                    yield Button("🤖 AI", id="btn-ai-analyze")

            with Container(classes="response-panel"):
                yield Static("[bold bright_magenta]RESPONSE[/]")
                yield TextArea(
                    "Response will appear here...",
                    id="response-viewer",
                    classes="req-textarea"
                )
                with Horizontal(classes="btn-row"):
                    yield Button("→ Comparer", id="btn-to-comparer")
                    yield Button("💾 Save", id="btn-save-response")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start-proxy":
            self.start_proxy()
        elif event.button.id == "btn-stop-proxy":
            self.stop_proxy()
        elif event.button.id == "btn-clear-proxy":
            try:
                self.query_one("#traffic-table", DataTable).clear()
            except Exception:
                pass

    @work(exclusive=True)
    async def start_proxy(self) -> None:
        host = self.query_one("#proxy-host", Input).value
        port = int(self.query_one("#proxy-port", Input).value)
        self.proxy_running = True
        self.query_one("#proxy-status").update(
            f"[bright_green]● Running on {host}:{port}[/]"
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
        self.query_one("#proxy-status").update("[bright_red]● Stopped[/]")
        self.notify("Proxy stopped", severity="warning")

    def _on_request(self, data: dict) -> None:
        try:
            table = self.query_one("#traffic-table", DataTable)
            table.add_row(
                str(table.row_count + 1),
                f"[bright_cyan]{data.get('method', 'GET')}[/]",
                data.get('host', ''),
                data.get('path', '/')[:40],
                f"[bright_green]{data.get('status', '---')}[/]",
                str(data.get('length', 0)),
                data.get('mime', ''),
                data.get('time', ''),
            )
        except Exception:
            pass
