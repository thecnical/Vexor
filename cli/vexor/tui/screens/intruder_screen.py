"""
Vexor Intruder Screen — Fixed responsive layout
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive
import asyncio


ATTACK_TYPES = [
    ("sniper", "Sniper — Single position"),
    ("battering_ram", "Battering Ram — All positions"),
    ("pitchfork", "Pitchfork — Parallel payloads"),
    ("cluster_bomb", "Cluster Bomb — All combinations"),
]


class IntruderScreen(Widget):

    DEFAULT_CSS = """
    IntruderScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .intruder-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .config-section {
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .template-area {
        height: 6;
        margin-bottom: 1;
    }
    .attack-btn-row {
        height: 3;
        margin-top: 1;
    }
    .payload-section {
        border: solid #ff00ff;
        padding: 1;
        margin-bottom: 1;
        height: 14;
    }
    .payload-area {
        height: 8;
    }
    .payload-btn-col {
        width: 20;
        padding-left: 1;
    }
    .results-table {
        height: 12;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .attack-log {
        height: 6;
        border: solid #1a1a2e;
    }
    """

    attacking = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ INTRUDER[/]  [dim]Automated Customized Attacks[/]",
            classes="intruder-title"
        )

        with Container(classes="config-section"):
            yield Static("[bold bright_magenta]Attack Configuration[/]")
            yield Input(placeholder="https://target.com/login", id="intruder-url")
            yield Static("[dim]Request Template (mark positions with §payload§):[/]")
            yield TextArea(
                "POST /login HTTP/1.1\nHost: target.com\n\nusername=§admin§&password=§password§",
                id="request-template",
                classes="template-area"
            )
            with Horizontal(classes="attack-btn-row"):
                yield Select(
                    [(label, val) for val, label in ATTACK_TYPES],
                    id="attack-type",
                    value="sniper"
                )
                yield Button("▶ Start Attack", id="btn-start-attack", classes="success")
                yield Button("■ Stop", id="btn-stop-attack", classes="danger")
                yield Button("🤖 AI Payloads", id="btn-ai-payloads")

        with Container(classes="payload-section"):
            yield Static("[bold bright_magenta]Payloads[/]  [dim](One per line)[/]")
            with Horizontal():
                yield TextArea(
                    "admin\nroot\ntest\nuser\nadministrator",
                    id="payload-list",
                    classes="payload-area"
                )
                with Vertical(classes="payload-btn-col"):
                    yield Button("📂 Load File", id="btn-load-file")
                    yield Button("📚 Built-in", id="btn-builtin")
                    yield Button("🤖 AI Gen", id="btn-ai-generate")

        yield Static("[bold bright_magenta]◈ RESULTS[/]")
        table = DataTable(classes="results-table", id="intruder-results")
        table.add_columns("#", "Payload", "Status", "Length", "Time(ms)", "Interesting")
        yield table

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(classes="attack-log", id="attack-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start-attack":
            self.start_attack()
        elif event.button.id == "btn-stop-attack":
            self.attacking = False
        elif event.button.id in ("btn-ai-payloads", "btn-ai-generate"):
            self.generate_ai_payloads()

    @work(exclusive=True)
    async def start_attack(self) -> None:
        url = self.query_one("#intruder-url", Input).value
        payloads_text = self.query_one("#payload-list", TextArea).text
        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
        log = self.query_one("#attack-log", Log)
        table = self.query_one("#intruder-results", DataTable)

        if not url or not payloads:
            self.notify("Enter URL and payloads", severity="error")
            return

        self.attacking = True
        log.write_line(f"[*] Starting attack on {url} with {len(payloads)} payloads...")

        import httpx, time
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            for i, payload in enumerate(payloads):
                if not self.attacking:
                    break
                start = time.time()
                try:
                    response = await client.post(url, data={"payload": payload})
                    elapsed = int((time.time() - start) * 1000)
                    interesting = "⚠️" if response.status_code not in [400, 401, 403, 404] else ""
                    table.add_row(
                        str(i + 1), payload[:25],
                        f"[bright_green]{response.status_code}[/]" if response.status_code == 200
                        else f"[bright_red]{response.status_code}[/]",
                        str(len(response.content)), str(elapsed), interesting
                    )
                except Exception as e:
                    table.add_row(str(i + 1), payload[:25], "ERR", "0", "0", "")
                await asyncio.sleep(0.05)

        log.write_line(f"[+] Done! {len(payloads)} payloads tested.")
        self.attacking = False

    @work(exclusive=True)
    async def generate_ai_payloads(self) -> None:
        url = self.query_one("#intruder-url", Input).value
        self.notify("Generating AI payloads...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            payloads = await client.generate_payloads(target=url, payload_type="general")
            if payloads:
                self.query_one("#payload-list", TextArea).load_text('\n'.join(payloads))
                self.notify(f"Generated {len(payloads)} payloads!", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
