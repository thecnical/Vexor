"""
Vexor Scanner Screen — Fixed responsive layout
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, ProgressBar
from textual.containers import Horizontal, Vertical, Container
from textual import work
from textual.reactive import reactive
import asyncio


SCAN_MODULES = [
    ("sqli", "SQL Injection"),
    ("xss", "Cross-Site Scripting"),
    ("csrf", "CSRF"),
    ("idor", "IDOR"),
    ("ssrf", "SSRF"),
    ("xxe", "XXE Injection"),
    ("lfi", "Local File Inclusion"),
    ("jwt_analyzer", "JWT Analyzer"),
    ("ssl_analyzer", "SSL/TLS Analyzer"),
    ("cors", "CORS Misconfiguration"),
    ("headers", "Security Headers"),
    ("websocket", "WebSocket Tester"),
    ("api_tester", "API Tester"),
    ("port_scanner", "Port Scanner"),
    ("rate_limit", "Rate Limit"),
    ("open_redirect", "Open Redirect"),
    ("file_upload", "File Upload"),
    ("session_analyzer", "Session Analyzer"),
    ("fingerprinter", "Tech Fingerprinter"),
    ("subdomain", "Subdomain Enum"),
    ("dirbuster", "Directory Bruteforce"),
    ("cve_lookup", "CVE Lookup"),
    ("wayback", "Wayback Machine"),
    ("github_dork", "GitHub Dorking"),
    ("sensitive_data", "Sensitive Data"),
    ("auth_bypass", "Auth Bypass"),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH": "bold bright_magenta",
    "MEDIUM": "bright_yellow",
    "LOW": "bright_blue",
    "INFO": "dim white",
}


class ScannerScreen(Widget):

    DEFAULT_CSS = """
    ScannerScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .scanner-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .scan-controls {
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .url-row {
        height: 3;
        margin-bottom: 1;
    }
    .btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .module-list {
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        height: 10;
    }
    .results-table {
        height: 14;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .scan-log {
        height: 8;
        border: solid #1a1a2e;
    }
    """

    scanning = reactive(False)

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ SCANNER[/]  [dim]Automated Vulnerability Detection[/]",
            classes="scanner-title"
        )

        with Container(classes="scan-controls"):
            yield Static("[bold bright_magenta]Target Configuration[/]")
            yield Input(placeholder="https://target.com", id="scan-target", classes="url-row")
            with Horizontal(classes="btn-row"):
                yield Button("▶ Full Scan", id="btn-full-scan", classes="success")
                yield Button("▶ Quick Scan", id="btn-quick-scan")
                yield Button("▶ Custom Scan", id="btn-custom-scan")
                yield Button("■ Stop", id="btn-stop-scan", classes="danger")
            yield ProgressBar(id="scan-progress", total=100)

        with Container(classes="module-list"):
            yield Static("[bold bright_magenta]Modules[/]  [dim](26 total)[/]")
            with Horizontal():
                with Vertical():
                    for mod_id, mod_name in SCAN_MODULES[:13]:
                        yield Static(f"[dim]☐[/] [white]{mod_name}[/]", id=f"mod-{mod_id}")
                with Vertical():
                    for mod_id, mod_name in SCAN_MODULES[13:]:
                        yield Static(f"[dim]☐[/] [white]{mod_name}[/]", id=f"mod-{mod_id}")

        yield Static("[bold bright_magenta]◈ FINDINGS[/]")
        table = DataTable(classes="results-table", id="results-table")
        table.add_columns("Severity", "Module", "Vulnerability", "Endpoint", "Parameter")
        yield table

        yield Static("[bold bright_magenta]◈ SCAN LOG[/]")
        yield Log(classes="scan-log", id="scan-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-full-scan":
            self.start_scan("full")
        elif event.button.id == "btn-quick-scan":
            self.start_scan("quick")
        elif event.button.id == "btn-stop-scan":
            self.scanning = False

    @work(exclusive=True)
    async def start_scan(self, scan_type: str) -> None:
        target = self.query_one("#scan-target", Input).value
        if not target:
            self.notify("Enter a target URL", severity="error")
            return

        log = self.query_one("#scan-log", Log)
        table = self.query_one("#results-table", DataTable)
        progress = self.query_one("#scan-progress", ProgressBar)

        log.write_line(f"[*] Starting {scan_type} scan: {target}")
        self.scanning = True

        modules = SCAN_MODULES if scan_type == "full" else SCAN_MODULES[:5]

        for i, (mod_id, mod_name) in enumerate(modules):
            if not self.scanning:
                break
            log.write_line(f"[*] Running {mod_name}...")
            progress.advance(100 / len(modules))
            await asyncio.sleep(0.05)

            try:
                import importlib
                mod = importlib.import_module(f"vexor.modules.{mod_id}")
                scanner = mod.Scanner(target=target)
                findings = await scanner.scan()
                for finding in findings:
                    sev_color = SEVERITY_COLORS.get(finding.severity, "white")
                    table.add_row(
                        f"[{sev_color}]{finding.severity}[/]",
                        mod_name, finding.vuln,
                        finding.endpoint[:35], finding.param or "-"
                    )
            except Exception:
                pass

        log.write_line(f"[+] Scan complete!")
        self.scanning = False
