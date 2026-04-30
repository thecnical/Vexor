"""
Vexor OSINT Screen — SpiderFoot-style intelligence
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log
from textual.containers import Horizontal, Container
from textual import work
import asyncio


class OSINTScreen(Widget):

    DEFAULT_CSS = """
    OSINTScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .osint-title { height: 2; color: #00ffff; text-style: bold; }
    .controls { border: solid #1a1a2e; padding: 1; height: auto; margin-bottom: 1; }
    .url-row { height: 3; margin-bottom: 1; }
    .btn-row { height: 3; margin-bottom: 1; }
    .results-table { height: 16; border: solid #1a1a2e; margin-bottom: 1; }
    .osint-log { height: 8; border: solid #1a1a2e; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ OSINT[/]  [dim]SpiderFoot-style Intelligence Gathering[/]",
            classes="osint-title"
        )

        with Container(classes="controls"):
            yield Static("[bold bright_magenta]Target[/]")
            yield Input(placeholder="https://target.com or domain.com", id="osint-target", classes="url-row")
            with Horizontal(classes="btn-row"):
                yield Button("🕵️ Full OSINT", id="btn-full-osint", classes="success")
                yield Button("🌐 DNS Info", id="btn-dns")
                yield Button("📜 Cert Transparency", id="btn-ct")
                yield Button("🔍 Breach Check", id="btn-breach")
                yield Button("■ Stop", id="btn-stop", classes="danger")

        yield Static("[bold bright_magenta]◈ INTELLIGENCE FINDINGS[/]")
        table = DataTable(classes="results-table", id="osint-results")
        table.add_columns("Severity", "Type", "Finding", "Evidence")
        yield table

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(classes="osint-log", id="osint-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-full-osint":
            self.run_osint("full")
        elif event.button.id == "btn-dns":
            self.run_osint("dns")
        elif event.button.id == "btn-ct":
            self.run_osint("ct")
        elif event.button.id == "btn-breach":
            self.run_osint("breach")

    @work(exclusive=True)
    async def run_osint(self, scan_type: str) -> None:
        target = self.query_one("#osint-target", Input).value
        if not target:
            self.notify("Enter a target", severity="error")
            return

        if not target.startswith("http"):
            target = f"https://{target}"

        log = self.query_one("#osint-log", Log)
        table = self.query_one("#osint-results", DataTable)

        log.write_line(f"[*] Starting OSINT on {target}...")

        try:
            from vexor.modules.osint import Scanner
            scanner = Scanner(target=target, timeout=30)
            findings = await scanner.scan()

            for f in findings:
                sev_colors = {
                    "CRITICAL": "bold bright_red",
                    "HIGH": "bold bright_magenta",
                    "MEDIUM": "bright_yellow",
                    "LOW": "bright_blue",
                    "INFO": "dim white",
                }
                color = sev_colors.get(f.severity, "white")
                table.add_row(
                    f"[{color}]{f.severity}[/]",
                    f.module,
                    f.vuln[:40],
                    f.evidence[:60] if f.evidence else "-"
                )
                log.write_line(f"[+] {f.severity}: {f.vuln}")

            log.write_line(f"[+] OSINT complete! {len(findings)} findings.")
            self.notify(f"OSINT done: {len(findings)} findings", severity="information")

        except Exception as e:
            log.write_line(f"[!] Error: {str(e)}")
            self.notify(f"Error: {str(e)}", severity="error")
