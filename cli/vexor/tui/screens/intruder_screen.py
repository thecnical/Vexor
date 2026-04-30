"""
Vexor Intruder Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive
import asyncio


ATTACK_TYPES = [
    ("sniper", "Sniper — Single position, one payload list"),
    ("battering_ram", "Battering Ram — All positions, same payload"),
    ("pitchfork", "Pitchfork — Multiple positions, parallel payloads"),
    ("cluster_bomb", "Cluster Bomb — All combinations"),
]


class IntruderScreen(Widget):
    """Automated Attack Tool"""

    DEFAULT_CSS = """
    IntruderScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .intruder-config {
        height: 14;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .payload-area {
        height: 12;
        border: solid #ff00ff;
        padding: 1;
        margin-bottom: 1;
    }
    .results-table {
        height: 15;
        border: solid #1a1a2e;
    }
    .attack-log {
        height: 8;
        border: solid #1a1a2e;
        margin-top: 1;
    }
    """

    attacking = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_cyan]◈ INTRUDER[/]  [dim]Automated Customized Attacks[/]")

        # Config
        with Container(classes="intruder-config"):
            yield Static("[bold bright_magenta]Attack Configuration[/]")
            yield Input(placeholder="https://target.com/login", id="intruder-url")
            yield Static("[dim]Request Template (mark positions with §payload§):[/]")
            yield TextArea(
                "POST /login HTTP/1.1\nHost: target.com\n\nusername=\xa7admin\xa7&password=\xa7password\xa7",
                id="request-template",
            )
            with Horizontal():
                yield Select(
                    [(label, val) for val, label in ATTACK_TYPES],
                    id="attack-type",
                    value="sniper"
                )
                yield Button("▶ Start Attack", id="btn-start-attack", classes="success")
                yield Button("■ Stop", id="btn-stop-attack", classes="danger")
                yield Button("🤖 AI Payloads", id="btn-ai-payloads")

        # Payload config
        with Container(classes="payload-area"):
            yield Static("[bold bright_magenta]Payloads[/]  [dim](One per line or load file)[/]")
            with Horizontal():
                yield TextArea(
                    "admin\nroot\ntest\nuser\nadministrator",
                    id="payload-list"
                )
                with Vertical():
                    yield Button("📂 Load File", id="btn-load-file")
                    yield Button("📚 Built-in Lists", id="btn-builtin")
                    yield Button("🤖 AI Generate", id="btn-ai-generate")

        # Results
        yield Static("[bold bright_magenta]◈ ATTACK RESULTS[/]")
        table = DataTable(classes="results-table", id="intruder-results")
        table.add_columns(
            "#", "Payload", "Status", "Length",
            "Time(ms)", "Error", "Interesting"
        )
        yield table

        yield Static("[bold bright_magenta]◈ ATTACK LOG[/]")
        yield Log(classes="attack-log", id="attack-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start-attack":
            self.start_attack()
        elif event.button.id == "btn-stop-attack":
            self.attacking = False
        elif event.button.id == "btn-ai-payloads":
            self.generate_ai_payloads()
        elif event.button.id == "btn-ai-generate":
            self.generate_ai_payloads()

    @work(exclusive=True)
    async def start_attack(self) -> None:
        """Start intruder attack"""
        url = self.query_one("#intruder-url", Input).value
        template = self.query_one("#request-template", TextArea).text
        payloads_text = self.query_one("#payload-list", TextArea).text
        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
        log = self.query_one("#attack-log", Log)
        table = self.query_one("#intruder-results", DataTable)

        if not url or not payloads:
            self.notify("Enter URL and payloads", severity="error")
            return

        self.attacking = True
        log.write_line(f"[*] Starting attack on {url} with {len(payloads)} payloads...")

        import httpx
        import time

        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            for i, payload in enumerate(payloads):
                if not self.attacking:
                    break

                # Replace §payload§ markers
                request_body = template.replace("§admin§", payload).replace("§password§", payload)

                start = time.time()
                try:
                    response = await client.post(url, data={"payload": payload})
                    elapsed = int((time.time() - start) * 1000)
                    interesting = "⚠️" if response.status_code not in [400, 401, 403, 404] else ""

                    table.add_row(
                        str(i + 1),
                        payload[:30],
                        f"[bright_green]{response.status_code}[/]" if response.status_code == 200
                        else f"[bright_red]{response.status_code}[/]",
                        str(len(response.content)),
                        str(elapsed),
                        "",
                        interesting
                    )
                except Exception as e:
                    table.add_row(str(i + 1), payload[:30], "ERR", "0", "0", str(e)[:20], "")

                await asyncio.sleep(0.05)  # Rate limiting

        log.write_line(f"[+] Attack complete! {len(payloads)} payloads tested.")
        self.attacking = False

    @work(exclusive=True)
    async def generate_ai_payloads(self) -> None:
        """Generate AI payloads"""
        url = self.query_one("#intruder-url", Input).value
        self.notify("Generating AI payloads...", severity="information")

        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            payloads = await client.generate_payloads(target=url, payload_type="general")
            if payloads:
                self.query_one("#payload-list", TextArea).load_text('\n'.join(payloads))
                self.notify(f"Generated {len(payloads)} AI payloads!", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
