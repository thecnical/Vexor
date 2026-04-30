"""
Vexor Scanner Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, ProgressBar, Select
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
from textual.reactive import reactive
import asyncio


SCAN_MODULES = [
    ("sqli",           "SQL Injection"),
    ("xss",            "Cross-Site Scripting"),
    ("csrf",           "CSRF"),
    ("idor",           "IDOR"),
    ("ssrf",           "SSRF"),
    ("xxe",            "XXE Injection"),
    ("lfi",            "Local File Inclusion"),
    ("jwt_analyzer",   "JWT Analyzer"),
    ("ssl_analyzer",   "SSL/TLS Analyzer"),
    ("cors",           "CORS Misconfiguration"),
    ("headers",        "Security Headers"),
    ("websocket",      "WebSocket Tester"),
    ("api_tester",     "API Tester"),
    ("port_scanner",   "Port Scanner"),
    ("ratelimit",      "Rate Limit"),
    ("open_redirect",  "Open Redirect"),
    ("file_upload",    "File Upload"),
    ("session_analyzer","Session Analyzer"),
    ("fingerprinter",  "Tech Fingerprinter"),
    ("subdomain",      "Subdomain Enum"),
    ("dirbuster",      "Directory Bruteforce"),
    ("cve_lookup",     "CVE Lookup"),
    ("wayback",        "Wayback Machine"),
    ("github_dork",    "GitHub Dorking"),
    ("sensitive_data", "Sensitive Data"),
    ("auth_bypass",    "Auth Bypass"),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH": "bold bright_magenta",
    "MEDIUM": "bright_yellow",
    "LOW": "bright_blue",
    "INFO": "dim white",
}


class ScannerScreen(Widget):
    """Scanner Module Screen"""

    DEFAULT_CSS = """
    ScannerScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .scan-controls {
        height: 12;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .module-select {
        height: 10;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .results-table {
        height: 20;
        border: solid #1a1a2e;
    }
    .scan-log {
        height: 10;
        border: solid #1a1a2e;
        margin-top: 1;
    }
    """

    scanning = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_cyan]◈ SCANNER[/]  [dim]Automated Vulnerability Detection[/]")

        # Controls
        with Container(classes="scan-controls"):
            yield Static("[bold bright_magenta]Target Configuration[/]")
            yield Input(placeholder="https://target.com", id="scan-target")
            with Horizontal():
                yield Button("▶ Full Scan", id="btn-full-scan", classes="success")
                yield Button("▶ Quick Scan", id="btn-quick-scan")
                yield Button("▶ Custom Scan", id="btn-custom-scan")
                yield Button("■ Stop", id="btn-stop-scan", classes="danger")
            yield ProgressBar(id="scan-progress", total=100)

        # Module selection
        with Container(classes="module-select"):
            yield Static("[bold bright_magenta]Modules[/]  [dim](Select for custom scan)[/]")
            with Horizontal():
                # Left column
                with Vertical():
                    for i, (mod_id, mod_name) in enumerate(SCAN_MODULES[:13]):
                        yield Static(
                            f"[dim]☐[/] [white]{mod_name}[/]",
                            id=f"mod-{mod_id}"
                        )
                # Right column
                with Vertical():
                    for i, (mod_id, mod_name) in enumerate(SCAN_MODULES[13:]):
                        yield Static(
                            f"[dim]☐[/] [white]{mod_name}[/]",
                            id=f"mod-{mod_id}"
                        )

        # Results
        yield Static("[bold bright_magenta]◈ FINDINGS[/]", )
        table = DataTable(classes="results-table", id="results-table")
        table.add_columns(
            "Severity", "Module", "Vulnerability",
            "Endpoint", "Parameter", "AI Analysis"
        )
        yield table

        # Scan log
        yield Static("[bold bright_magenta]◈ SCAN LOG[/]")
        yield Log(classes="scan-log", id="scan-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-full-scan":
            self.start_scan("full")
        elif event.button.id == "btn-quick-scan":
            self.start_scan("quick")
        elif event.button.id == "btn-stop-scan":
            self.stop_scan()

    @work(exclusive=True)
    async def start_scan(self, scan_type: str) -> None:
        """Start scanning"""
        target = self.query_one("#scan-target", Input).value
        if not target:
            self.notify("Please enter a target URL", severity="error")
            return

        log = self.query_one("#scan-log", Log)
        table = self.query_one("#results-table", DataTable)
        progress = self.query_one("#scan-progress", ProgressBar)

        log.write_line(f"[*] Starting {scan_type} scan on: {target}")
        log.write_line(f"[*] Loading modules...")

        self.scanning = True
        modules = SCAN_MODULES if scan_type == "full" else SCAN_MODULES[:5]

        for i, (mod_id, mod_name) in enumerate(modules):
            if not self.scanning:
                break

            log.write_line(f"[*] Running {mod_name}...")
            progress.advance(100 / len(modules))
            await asyncio.sleep(0.1)  # Non-blocking

            # Import and run module dynamically
            try:
                result = await self._run_module(mod_id, target)
                if result:
                    for finding in result:
                        sev_color = SEVERITY_COLORS.get(finding.get("severity", "INFO"), "white")
                        table.add_row(
                            f"[{sev_color}]{finding.get('severity', 'INFO')}[/]",
                            mod_name,
                            finding.get("vuln", ""),
                            finding.get("endpoint", ""),
                            finding.get("param", ""),
                            finding.get("ai_note", "Pending...")
                        )
            except Exception as e:
                log.write_line(f"[!] {mod_name} error: {str(e)}")

        log.write_line(f"[+] Scan complete!")
        self.scanning = False

    async def _run_module(self, module_id: str, target: str) -> list:
        """Dynamically run a scan module"""
        try:
            import importlib
            mod = importlib.import_module(f"vexor.modules.{module_id}")
            scanner = mod.Scanner(target)
            return await scanner.scan()
        except ImportError:
            return []
        except Exception:
            return []

    def stop_scan(self) -> None:
        self.scanning = False
        self.notify("Scan stopped", severity="warning")
