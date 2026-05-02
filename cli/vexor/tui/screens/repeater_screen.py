"""
Vexor Repeater Screen v3.0 — Manual Request Manipulation
+ Send to Scanner · AI Analysis · Request History
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, TextArea, Log, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
import httpx
import asyncio


class RepeaterScreen(Widget):

    DEFAULT_CSS = """
    RepeaterScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .repeater-title { height: 2; color: #00ffff; text-style: bold; }
    .url-row { height: 3; margin-bottom: 1; }
    .btn-row { height: 3; margin-bottom: 1; }
    .btn-row Button { height: 3; margin-right: 1; }
    .req-resp-row { height: 20; margin-bottom: 1; }
    .request-area { border: solid #00ffff; padding: 1; width: 1fr; }
    .response-area { border: solid #ff00ff; padding: 1; width: 1fr; }
    .req-textarea { height: 14; }
    .history-log { height: 6; border: solid #1a1a2e; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ REPEATER[/]  [dim]Manual Request Manipulation[/]",
            classes="repeater-title"
        )

        with Horizontal(classes="url-row"):
            yield Input(placeholder="https://target.com/api/endpoint", id="repeater-url")

        with Horizontal(classes="btn-row"):
            yield Button("▶ Send",           id="btn-send",          classes="success")
            yield Button("🔍 Send to Scanner", id="btn-send-scanner")
            yield Button("⚔ Send to Intruder", id="btn-send-intruder")
            yield Button("🤖 AI Analyze",    id="btn-ai")
            yield Button("⊘ Clear",          id="btn-clear")

        with Horizontal(classes="req-resp-row"):
            with Container(classes="request-area"):
                yield Static("[bold bright_cyan]REQUEST[/]  [dim](Edit and send)[/]")
                yield TextArea(
                    "GET / HTTP/1.1\nHost: target.com\nUser-Agent: Vexor/4.0\n\n",
                    id="request-input",
                    classes="req-textarea"
                )
            with Container(classes="response-area"):
                yield Static("[bold bright_magenta]RESPONSE[/]")
                yield TextArea(
                    "Response will appear here after sending...",
                    id="response-output",
                    classes="req-textarea"
                )

        yield Static("[bold bright_magenta]◈ REQUEST HISTORY[/]")
        yield Log(classes="history-log", id="history-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-send":
            self.send_request()
        elif bid == "btn-send-scanner":
            self._send_to_scanner()
        elif bid == "btn-send-intruder":
            self._send_to_intruder()
        elif bid == "btn-clear":
            try:
                self.query_one("#request-input",  TextArea).load_text("")
                self.query_one("#response-output", TextArea).load_text("")
            except Exception:
                pass
        elif bid == "btn-ai":
            self.ai_analyze()

    @work(exclusive=True)
    async def send_request(self) -> None:
        url = self.query_one("#repeater-url", Input).value
        raw_request = self.query_one("#request-input", TextArea).text
        log = self.query_one("#history-log", Log)

        if not url:
            self.notify("Enter a URL first", severity="error")
            return

        log.write_line(f"[*] Sending to {url}...")
        try:
            lines = raw_request.strip().split("\n")
            method_line = lines[0].split()
            method = method_line[0] if method_line else "GET"

            headers = {}
            body = ""
            in_body = False
            for line in lines[1:]:
                if line.strip() == "":
                    in_body = True
                    continue
                if in_body:
                    body += line + "\n"
                elif ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                response = await client.request(
                    method=method, url=url, headers=headers,
                    content=body.encode() if body else None
                )

            resp_text = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n"
            for k, v in response.headers.items():
                resp_text += f"{k}: {v}\n"
            resp_text += f"\n{response.text[:5000]}"

            self.query_one("#response-output", TextArea).load_text(resp_text)
            log.write_line(f"[+] {response.status_code} | {len(response.content)} bytes")

        except Exception as e:
            self.query_one("#response-output", TextArea).load_text(f"Error: {str(e)}")
            log.write_line(f"[!] Error: {str(e)}")

    def _send_to_scanner(self) -> None:
        """Send current URL to Scanner screen and start a scan"""
        url = self.query_one("#repeater-url", Input).value.strip()
        if not url:
            self.notify("Enter a URL first", severity="error")
            return
        try:
            from vexor.tui.screens.scanner_screen import ScannerScreen
            scanner = self.app.query_one("#scanner-panel", ScannerScreen)
            scanner.query_one("#scan-target").value = url
            self.app.action_show_screen("scanner")
            self.notify(f"Sent to Scanner: {url}", severity="information")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def _send_to_intruder(self) -> None:
        """Send current URL + request to Intruder screen"""
        url = self.query_one("#repeater-url", Input).value.strip()
        request = self.query_one("#request-input", TextArea).text
        if not url:
            self.notify("Enter a URL first", severity="error")
            return
        try:
            from vexor.tui.screens.intruder_screen import IntruderScreen
            intruder = self.app.query_one("#intruder-panel", IntruderScreen)
            intruder.query_one("#intruder-url").value = url
            intruder.query_one("#request-template").load_text(request)
            self.app.action_show_screen("intruder")
            self.notify(f"Sent to Intruder: {url}", severity="information")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    @work(exclusive=True)
    async def ai_analyze(self) -> None:
        request  = self.query_one("#request-input",  TextArea).text
        response = self.query_one("#response-output", TextArea).text
        if not request.strip():
            self.notify("Send a request first", severity="warning")
            return
        self.notify("Analyzing with AI...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            analysis = await client.analyze(request=request, response=response)
            log = self.query_one("#history-log", Log)
            log.write_line(f"[🤖 AI] {analysis[:200]}")
            self.notify("AI analysis complete — see log", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
