"""
Vexor Repeater Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, TextArea, Select, Log
from textual.containers import Horizontal, Vertical, Container
from textual import work
import httpx
import asyncio


class RepeaterScreen(Widget):
    """HTTP Request Repeater"""

    DEFAULT_CSS = """
    RepeaterScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .repeater-controls {
        height: 5;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .request-area {
        height: 20;
        border: solid #00ffff;
        padding: 1;
    }
    .response-area {
        height: 20;
        border: solid #ff00ff;
        padding: 1;
    }
    .history-log {
        height: 8;
        border: solid #1a1a2e;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_cyan]◈ REPEATER[/]  [dim]Manual Request Manipulation[/]")

        with Container(classes="repeater-controls"):
            with Horizontal():
                yield Input(placeholder="https://target.com/api/endpoint", id="repeater-url")
                yield Button("▶ Send", id="btn-send", classes="success")
                yield Button("⊘ Clear", id="btn-clear")
                yield Button("🤖 AI Analyze", id="btn-ai")
                yield Button("+ New Tab", id="btn-new-tab")

        with Horizontal():
            with Container(classes="request-area"):
                yield Static("[bold bright_cyan]REQUEST[/]  [dim](Edit and send)[/]")
                yield TextArea(
                    "GET / HTTP/1.1\nHost: target.com\nUser-Agent: Vexor/1.0\n\n",
                    id="request-input",
                    language="http"
                )

            with Container(classes="response-area"):
                yield Static("[bold bright_magenta]RESPONSE[/]")
                yield TextArea(
                    "Response will appear here after sending...",
                    id="response-output",
                    language="http"
                )

        yield Static("[bold bright_magenta]◈ REQUEST HISTORY[/]")
        yield Log(classes="history-log", id="history-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-send":
            self.send_request()
        elif event.button.id == "btn-clear":
            self.query_one("#request-input", TextArea).clear()
            self.query_one("#response-output", TextArea).clear()
        elif event.button.id == "btn-ai":
            self.ai_analyze()

    @work(exclusive=True)
    async def send_request(self) -> None:
        """Send HTTP request"""
        url = self.query_one("#repeater-url", Input).value
        raw_request = self.query_one("#request-input", TextArea).text
        log = self.query_one("#history-log", Log)

        if not url:
            self.notify("Enter a URL first", severity="error")
            return

        log.write_line(f"[*] Sending request to {url}...")

        try:
            # Parse raw request
            lines = raw_request.strip().split('\n')
            method_line = lines[0].split()
            method = method_line[0] if method_line else "GET"
            path = method_line[1] if len(method_line) > 1 else "/"

            headers = {}
            body = ""
            in_body = False
            for line in lines[1:]:
                if line.strip() == "":
                    in_body = True
                    continue
                if in_body:
                    body += line + "\n"
                else:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None
                )

            # Display response
            resp_text = (
                f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n"
            )
            for k, v in response.headers.items():
                resp_text += f"{k}: {v}\n"
            resp_text += f"\n{response.text[:5000]}"

            self.query_one("#response-output", TextArea).load_text(resp_text)
            log.write_line(
                f"[+] Response: {response.status_code} | "
                f"Length: {len(response.content)} bytes"
            )

        except Exception as e:
            self.query_one("#response-output", TextArea).load_text(f"Error: {str(e)}")
            log.write_line(f"[!] Error: {str(e)}")

    @work(exclusive=True)
    async def ai_analyze(self) -> None:
        """Send to AI for analysis"""
        request = self.query_one("#request-input", TextArea).text
        response = self.query_one("#response-output", TextArea).text

        if not request or not response:
            self.notify("Send a request first", severity="warning")
            return

        self.notify("Sending to AI for analysis...", severity="information")

        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            analysis = await client.analyze(request=request, response=response)
            self.notify(f"AI: {analysis[:100]}...", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
