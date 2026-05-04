"""
Vexor Proxy Screen v2.0
- Added: MITM toggle button (enables HTTPS interception)
- Added: Intercept toggle (hold/forward/drop requests)
- Added: Passive scanner toggle
- Added: CA cert install instructions
- Fixed: Send to Repeater/Intruder/Comparer
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea, Checkbox
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive


class ProxyScreen(Widget):

    DEFAULT_CSS = """
    ProxyScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .proxy-title { height: 2; color: #00ffff; text-style: bold; }
    .proxy-controls { border: solid #1a1a2e; padding: 1; margin-bottom: 1; height: auto; }
    .proxy-btn-row  { height: 3; margin-bottom: 1; }
    .proxy-btn-row Button { height: 3; margin-right: 1; }
    .proxy-toggle-row { height: 3; margin-bottom: 1; }
    .traffic-table  { height: 12; border: solid #1a1a2e; margin-bottom: 1; }
    .req-resp-row   { height: 18; margin-bottom: 1; }
    .request-panel  { border: solid #00ffff; padding: 1; }
    .response-panel { border: solid #ff00ff; padding: 1; }
    .req-textarea   { height: 10; }
    .action-row     { height: 3; margin-top: 1; }
    .action-row Button { height: 3; margin-right: 1; }
    .intercept-panel {
        border: solid #ffaa00;
        padding: 1;
        margin-bottom: 1;
        height: auto;
        display: none;
    }
    .intercept-panel.visible { display: block; }
    .ca-info { color: #888888; height: 2; }
    """

    proxy_running = reactive(False)
    intercept_enabled = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ PROXY INTERCEPTOR[/]  [dim]HTTP/HTTPS Man-in-the-Middle[/]",
            classes="proxy-title",
        )

        with Container(classes="proxy-controls"):
            # Host + Port row
            with Horizontal(classes="proxy-btn-row"):
                yield Input(value="127.0.0.1", id="proxy-host", placeholder="Host")
                yield Input(value="8080",       id="proxy-port", placeholder="Port")
                yield Button("▶ Start",    id="btn-start-proxy",  classes="success")
                yield Button("■ Stop",     id="btn-stop-proxy",   classes="danger")
                yield Button("⊘ Clear",   id="btn-clear-proxy")

            # Mode toggles
            with Horizontal(classes="proxy-toggle-row"):
                yield Checkbox("🔒 MITM (HTTPS decrypt)",   id="chk-mitm",     value=False)
                yield Checkbox("✋ Intercept (hold reqs)",   id="chk-intercept", value=False)
                yield Checkbox("🔍 Passive Scanner",         id="chk-passive",   value=False)

            yield Static(
                "[dim]Configure browser: Settings → Manual Proxy → 127.0.0.1:8080[/]",
                id="proxy-status",
            )
            yield Static("", id="ca-info", classes="ca-info")

        # Intercept queue panel (shown when intercept mode is ON)
        with Container(classes="intercept-panel", id="intercept-panel"):
            yield Static("[bold bright_yellow]✋ INTERCEPTED REQUEST — Forward or Drop[/]")
            yield TextArea("", id="intercept-editor", classes="req-textarea")
            with Horizontal(classes="action-row"):
                yield Button("✓ Forward", id="btn-forward",  classes="success")
                yield Button("✗ Drop",    id="btn-drop",     classes="danger")
                yield Button("→ Repeater",id="btn-intercept-to-repeater")

        yield Static("[bold bright_magenta]◈ HTTP HISTORY[/]")
        table = DataTable(classes="traffic-table", id="traffic-table")
        table.add_columns("#", "Method", "Host", "Path", "Status", "Length", "MIME", "Time")
        table.cursor_type = "row"
        yield table

        with Horizontal(classes="req-resp-row"):
            with Container(classes="request-panel"):
                yield Static("[bold bright_cyan]REQUEST[/]")
                yield TextArea(
                    "Select a request from history above...",
                    id="request-editor",
                    classes="req-textarea",
                )
                with Horizontal(classes="action-row"):
                    yield Button("→ Repeater",  id="btn-to-repeater")
                    yield Button("→ Intruder",  id="btn-to-intruder")
                    yield Button("→ Comparer",  id="btn-req-to-comparer")
                    yield Button("🤖 AI",       id="btn-ai-analyze")

            with Container(classes="response-panel"):
                yield Static("[bold bright_magenta]RESPONSE[/]")
                yield TextArea(
                    "Response will appear here...",
                    id="response-viewer",
                    classes="req-textarea",
                )
                with Horizontal(classes="action-row"):
                    yield Button("→ Comparer", id="btn-to-comparer")
                    yield Button("💾 Save",    id="btn-save-response")

        yield Static("[bold bright_magenta]◈ PASSIVE FINDINGS[/]")
        passive_table = DataTable(id="passive-table", classes="traffic-table")
        passive_table.add_columns("Severity", "Issue", "Endpoint")
        yield passive_table

    # ─── Events ───────────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-start-proxy":
            self.start_proxy()
        elif bid == "btn-stop-proxy":
            self.stop_proxy()
        elif bid == "btn-clear-proxy":
            self._clear()
        elif bid == "btn-to-repeater":
            self._send_to_repeater()
        elif bid == "btn-to-intruder":
            self._send_to_intruder()
        elif bid in ("btn-to-comparer", "btn-req-to-comparer"):
            self._send_to_comparer()
        elif bid == "btn-forward":
            self._forward_intercepted()
        elif bid == "btn-drop":
            self._drop_intercepted()
        elif bid == "btn-intercept-to-repeater":
            self._intercepted_to_repeater()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk-mitm" and event.value:
            self._show_ca_instructions()
        if event.checkbox.id == "chk-intercept":
            panel = self.query_one("#intercept-panel")
            if event.value:
                panel.add_class("visible")
            else:
                panel.remove_class("visible")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "traffic-table":
            self._load_request_at(event.cursor_row)

    # ─── Proxy control ────────────────────────────────────────────────────────

    @work(exclusive=True)
    async def start_proxy(self) -> None:
        host = self.query_one("#proxy-host", Input).value or "127.0.0.1"
        port = int(self.query_one("#proxy-port", Input).value or "8080")
        use_mitm    = self.query_one("#chk-mitm",     Checkbox).value
        use_intercept = self.query_one("#chk-intercept", Checkbox).value
        use_passive = self.query_one("#chk-passive",  Checkbox).value

        self.proxy_running = True
        mode = "MITM" if use_mitm else "Transparent"
        self.query_one("#proxy-status").update(
            f"[bright_green]● Running [{mode}] on {host}:{port}[/]  "
            f"[dim]Intercept:{'ON' if use_intercept else 'off'}  Passive:{'ON' if use_passive else 'off'}[/]"
        )
        self.notify(f"Proxy [{mode}] started on {host}:{port}", severity="information")

        passive_scanner = None
        if use_passive:
            try:
                from vexor.core.spider import PassiveScanner
                passive_scanner = PassiveScanner(on_finding=self._on_passive_finding)
            except Exception:
                pass

        def on_request(data: dict) -> None:
            try:
                table = self.query_one("#traffic-table", DataTable)
                table.add_row(
                    str(table.row_count + 1),
                    f"[bright_cyan]{data.get('method', 'GET')}[/]",
                    data.get("host", ""),
                    data.get("path", "/")[:45],
                    f"[bright_green]{data.get('status', '---')}[/]",
                    str(data.get("length", 0)),
                    data.get("mime", ""),
                    data.get("time", ""),
                )
                self._last_request = data
            except Exception:
                pass

        def on_response(req_data) -> None:
            if passive_scanner:
                passive_scanner.analyze(req_data)

        try:
            if use_mitm:
                from vexor.core.mitm_proxy import VexorMITMProxy
                proxy = VexorMITMProxy(host=host, port=port, on_request=on_request, on_response=on_response)
            else:
                from vexor.core.proxy import VexorProxy
                proxy = VexorProxy(host=host, port=port, on_request=on_request)

            if use_intercept:
                proxy.intercept_enabled = True
            self._proxy_instance = proxy
            await proxy.start()
            import asyncio
            await asyncio.sleep(3600 * 24)
        except Exception as e:
            self.notify(f"Proxy error: {str(e)[:60]}", severity="error")
            self.proxy_running = False

    def stop_proxy(self) -> None:
        self.proxy_running = False
        self.query_one("#proxy-status").update("[bright_red]● Stopped[/]")
        self.notify("Proxy stopped", severity="warning")
        try:
            proxy = getattr(self, "_proxy_instance", None)
            if proxy and hasattr(proxy, "stop"):
                import asyncio
                asyncio.ensure_future(proxy.stop())
        except Exception:
            pass

    # ─── Intercept forward/drop ───────────────────────────────────────────────

    def _forward_intercepted(self) -> None:
        try:
            proxy = getattr(self, "_proxy_instance", None)
            if proxy and hasattr(proxy, "forward"):
                proxy.forward()
                self.notify("Request forwarded", severity="information")
                self.query_one("#intercept-editor", TextArea).load_text("")
        except Exception as e:
            self.notify(f"Forward error: {e}", severity="error")

    def _drop_intercepted(self) -> None:
        try:
            proxy = getattr(self, "_proxy_instance", None)
            if proxy and hasattr(proxy, "drop"):
                proxy.drop()
                self.notify("Request dropped", severity="warning")
                self.query_one("#intercept-editor", TextArea).load_text("")
        except Exception as e:
            self.notify(f"Drop error: {e}", severity="error")

    def _intercepted_to_repeater(self) -> None:
        raw = self.query_one("#intercept-editor", TextArea).text
        if raw:
            try:
                from vexor.core.state import state
                state.pending_repeater_request = raw
            except Exception:
                pass
            self.app.action_show_screen("repeater")
            self.notify("Sent to Repeater", severity="information")

    # ─── Send to other screens ────────────────────────────────────────────────

    def _send_to_repeater(self) -> None:
        raw = self.query_one("#request-editor", TextArea).text
        if not raw or raw.startswith("Select"):
            self.notify("Select a request first", severity="warning")
            return
        try:
            from vexor.core.state import state
            state.pending_repeater_request = raw
        except Exception:
            pass
        self.app.action_show_screen("repeater")
        self.notify("Sent to Repeater", severity="information")

    def _send_to_intruder(self) -> None:
        raw = self.query_one("#request-editor", TextArea).text
        if not raw or raw.startswith("Select"):
            self.notify("Select a request first", severity="warning")
            return
        try:
            from vexor.core.state import state
            state.pending_intruder_request = raw
        except Exception:
            pass
        self.app.action_show_screen("intruder")
        self.notify("Sent to Intruder — wrap positions with §markers§", severity="information")

    def _send_to_comparer(self) -> None:
        raw = self.query_one("#request-editor", TextArea).text
        try:
            from vexor.core.state import state
            state.comparer_left = raw
        except Exception:
            pass
        self.app.action_show_screen("comparer")
        self.notify("Sent to Comparer (left side)", severity="information")

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _load_request_at(self, row_idx: int) -> None:
        """Load request details into editor when row selected."""
        try:
            data = getattr(self, "_last_request", {})
            raw = (
                f"{data.get('method','GET')} {data.get('path','/')} HTTP/1.1\r\n"
                f"Host: {data.get('host','')}\r\n"
                f"User-Agent: Vexor/4.1\r\n\r\n"
            )
            self.query_one("#request-editor", TextArea).load_text(raw)
        except Exception:
            pass

    def _on_passive_finding(self, finding: dict) -> None:
        try:
            table = self.query_one("#passive-table", DataTable)
            sev = finding.get("severity", "INFO")
            color = {"CRITICAL": "bold bright_red", "HIGH": "bold bright_magenta",
                     "MEDIUM": "bright_yellow", "LOW": "bright_blue"}.get(sev, "dim white")
            table.add_row(
                f"[{color}]{sev}[/]",
                finding.get("vuln", "")[:40],
                finding.get("endpoint", "")[:50],
            )
        except Exception:
            pass

    def _show_ca_instructions(self) -> None:
        try:
            from vexor.core.mitm_proxy import CA_CERT
            self.query_one("#ca-info", Static).update(
                f"[bright_yellow]⚠ MITM: Install CA cert → {CA_CERT}[/]  "
                f"[dim]Chrome: Settings→Privacy→Certificates→Import[/]"
            )
        except Exception:
            self.query_one("#ca-info", Static).update(
                "[bright_yellow]⚠ MITM mode: CA cert auto-generated at ~/.vexor/ca/vexor_ca.crt[/]"
            )

    def _clear(self) -> None:
        try:
            self.query_one("#traffic-table",  DataTable).clear()
            self.query_one("#passive-table",  DataTable).clear()
            self.query_one("#request-editor", TextArea).load_text("Select a request from history above...")
            self.query_one("#response-viewer", TextArea).load_text("Response will appear here...")
        except Exception:
            pass
