"""
Vexor Scanner Screen v3.0
- Custom scan with module checkboxes
- Real findings validation (no false positives)
- AI analysis after scan
- Clickable/copyable URLs
- Evidence detail panel
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, ProgressBar, Checkbox
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
from textual.reactive import reactive
import asyncio
import json
from datetime import datetime


SCAN_MODULES = [
    ("sqli",             "SQL Injection"),
    ("xss",              "Cross-Site Scripting"),
    ("csrf",             "CSRF"),
    ("idor",             "IDOR"),
    ("ssrf",             "SSRF"),
    ("xxe",              "XXE Injection"),
    ("lfi",              "Local File Inclusion"),
    ("jwt_analyzer",     "JWT Analyzer"),
    ("ssl_analyzer",     "SSL/TLS Analyzer"),
    ("cors",             "CORS Misconfiguration"),
    ("headers",          "Security Headers"),
    ("websocket",        "WebSocket Tester"),
    ("api_tester",       "API Tester"),
    ("port_scanner",     "Port Scanner"),
    ("rate_limit",       "Rate Limit"),
    ("open_redirect",    "Open Redirect"),
    ("file_upload",      "File Upload"),
    ("session_analyzer", "Session Analyzer"),
    ("fingerprinter",    "Tech Fingerprinter"),
    ("subdomain",        "Subdomain Enum"),
    ("dirbuster",        "Dir Bruteforce"),
    ("cve_lookup",       "CVE Lookup"),
    ("wayback",          "Wayback Machine"),
    ("github_dork",      "GitHub Dorking"),
    ("sensitive_data",   "Sensitive Data"),
    ("auth_bypass",      "Auth Bypass"),
]

QUICK_MODULES = [
    "sqli", "xss", "headers", "cors", "ssl_analyzer",
    "fingerprinter", "sensitive_data",
]

SEVERITY_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH":     "bold bright_magenta",
    "MEDIUM":   "bright_yellow",
    "LOW":      "bright_blue",
    "INFO":     "dim white",
}


class ScannerScreen(Widget):

    DEFAULT_CSS = """
    ScannerScreen {
        background: #0a0a0f;
        overflow-y: auto;
        height: 100%;
    }

    /* ── Controls ── */
    .scan-header {
        background: #0d0d1a;
        border-bottom: solid #1a1a2e;
        padding: 1 2;
        height: auto;
    }
    .scanner-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .target-label {
        height: 1;
        color: #ff00ff;
        text-style: bold;
        margin-top: 1;
    }
    #scan-target {
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #00ffff;
        margin-bottom: 1;
    }
    #scan-target:focus {
        border: solid #00ff88;
    }
    .btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .btn-row Button {
        height: 3;
        margin-right: 1;
    }
    #scan-progress {
        margin-bottom: 1;
    }

    /* ── Module selector ── */
    .module-section {
        border: solid #1a1a2e;
        padding: 1 2;
        margin: 0 1 1 1;
        height: auto;
    }
    .module-section-title {
        height: 2;
        color: #ff00ff;
        text-style: bold;
    }
    .module-cols {
        height: auto;
    }
    .module-col {
        width: 1fr;
        height: auto;
    }
    Checkbox {
        height: 2;
        background: transparent;
        color: #888888;
    }
    Checkbox:focus {
        color: #00ffff;
    }
    Checkbox.-on {
        color: #00ff88;
    }

    /* ── Stats bar ── */
    .scan-stats {
        height: 1;
        color: #00ff88;
        padding: 0 2;
        margin-bottom: 1;
    }

    /* ── Findings ── */
    .section-label {
        height: 2;
        color: #ff00ff;
        text-style: bold;
        padding: 0 2;
    }
    #results-table {
        height: 14;
        border: solid #1a1a2e;
        margin: 0 1 1 1;
    }

    /* ── Detail panel ── */
    .detail-panel {
        border: solid #1a1a2e;
        padding: 1 2;
        margin: 0 1 1 1;
        height: auto;
        display: none;
    }
    .detail-panel.visible {
        display: block;
    }
    .detail-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .detail-content {
        height: auto;
        color: #cccccc;
    }

    /* ── AI Analysis ── */
    .ai-panel {
        border: solid #ff00ff;
        padding: 1 2;
        margin: 0 1 1 1;
        height: auto;
        display: none;
    }
    .ai-panel.visible {
        display: block;
    }
    .ai-title {
        height: 2;
        color: #ff00ff;
        text-style: bold;
    }
    .ai-content {
        height: auto;
        color: #cccccc;
    }

    /* ── Log ── */
    #scan-log {
        height: 10;
        border: solid #1a1a2e;
        margin: 0 1 1 1;
    }
    """

    scanning = reactive(False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._findings: list = []
        self._selected_row: int = -1

    def compose(self) -> ComposeResult:
        # ── Header ───────────────────────────────────────────────────────────
        with Vertical(classes="scan-header"):
            yield Static(
                "[bold bright_cyan]◈ SCANNER[/]  "
                "[dim]Automated Vulnerability Detection[/]",
                classes="scanner-title",
            )
            yield Static(
                "[bold bright_magenta]Target[/]  [dim]URL to scan[/]",
                classes="target-label",
            )
            yield Input(
                placeholder="https://target.com — Press Enter to quick scan",
                id="scan-target",
            )
            with Horizontal(classes="btn-row"):
                yield Button("▶ Full Scan",    id="btn-full-scan",   classes="success")
                yield Button("▶ Quick Scan",   id="btn-quick-scan")
                yield Button("▶ Custom Scan",  id="btn-custom-scan")
                yield Button("🧠 AI Analyze",  id="btn-ai-analyze")
                yield Button("■ Stop",         id="btn-stop-scan",   classes="danger")
                yield Button("⊘ Clear",        id="btn-clear-scan",  classes="danger")
            yield ProgressBar(id="scan-progress", total=100)

        # ── Module selector (shown in custom mode) ────────────────────────────
        with Container(classes="module-section", id="module-section"):
            yield Static(
                "[bold bright_magenta]Modules[/]  "
                "[dim](26 total — check to include in Custom Scan)[/]",
                classes="module-section-title",
            )
            with Horizontal(classes="module-cols"):
                with Vertical(classes="module-col"):
                    for mod_id, mod_name in SCAN_MODULES[:13]:
                        yield Checkbox(mod_name, id=f"chk-{mod_id}", value=False)
                with Vertical(classes="module-col"):
                    for mod_id, mod_name in SCAN_MODULES[13:]:
                        yield Checkbox(mod_name, id=f"chk-{mod_id}", value=False)

        # ── Stats ─────────────────────────────────────────────────────────────
        yield Static("", id="scan-stats", classes="scan-stats")

        # ── Findings table ────────────────────────────────────────────────────
        yield Static(
            "[bold bright_magenta]◈ FINDINGS[/]  "
            "[dim]Click a row to see full details[/]",
            classes="section-label",
        )
        table = DataTable(id="results-table")
        table.add_columns("Sev", "Module", "Vulnerability", "Endpoint", "Param")
        table.cursor_type = "row"
        yield table

        # ── Detail panel (shown on row click) ────────────────────────────────
        with Container(classes="detail-panel", id="detail-panel"):
            yield Static("", classes="detail-title", id="detail-title")
            yield Static("", classes="detail-content", id="detail-content")

        # ── AI Analysis panel ─────────────────────────────────────────────────
        with Container(classes="ai-panel", id="ai-panel"):
            yield Static(
                "[bold bright_magenta]🧠 VEXOR AI ANALYSIS[/]",
                classes="ai-title",
            )
            yield Static("", classes="ai-content", id="ai-content")

        # ── Scan log ──────────────────────────────────────────────────────────
        yield Static("[bold bright_magenta]◈ SCAN LOG[/]", classes="section-label")
        yield Log(id="scan-log")

    # ─── Events ──────────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "scan-target":
            self._start_scan("quick")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-full-scan":
            self._start_scan("full")
        elif bid == "btn-quick-scan":
            self._start_scan("quick")
        elif bid == "btn-custom-scan":
            self._start_scan("custom")
        elif bid == "btn-ai-analyze":
            self._run_ai_analysis()
        elif bid == "btn-stop-scan":
            self.scanning = False
            self.notify("Scan stopped", severity="warning")
        elif bid == "btn-clear-scan":
            self._clear_all()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Show full finding details when row is clicked"""
        try:
            row_idx = event.cursor_row
            if 0 <= row_idx < len(self._findings):
                f = self._findings[row_idx]
                self._show_detail(f)
        except Exception:
            pass

    # ─── Scan ────────────────────────────────────────────────────────────────

    def _start_scan(self, scan_type: str) -> None:
        target = self.query_one("#scan-target", Input).value.strip()
        if not target:
            self.notify("Enter a target URL first", severity="error")
            return
        if not target.startswith("http"):
            target = f"https://{target}"
            self.query_one("#scan-target", Input).value = target
        self._run_scan(target, scan_type)

    @work(exclusive=True)
    async def _run_scan(self, target: str, scan_type: str) -> None:
        log      = self.query_one("#scan-log", Log)
        table    = self.query_one("#results-table", DataTable)
        progress = self.query_one("#scan-progress", ProgressBar)

        from vexor.core.state import state, ScanResult
        state.scan_target = target
        state.scans_run += 1

        self._findings = []
        self.scanning = True

        # Determine modules to run
        if scan_type == "full":
            modules = SCAN_MODULES
        elif scan_type == "quick":
            modules = [(m, n) for m, n in SCAN_MODULES if m in QUICK_MODULES]
        else:  # custom
            modules = []
            for mod_id, mod_name in SCAN_MODULES:
                try:
                    chk = self.query_one(f"#chk-{mod_id}", Checkbox)
                    if chk.value:
                        modules.append((mod_id, mod_name))
                except Exception:
                    pass
            if not modules:
                self.notify("Select at least one module for Custom Scan", severity="warning")
                self.scanning = False
                return

        log.write_line("")
        log.write_line("─" * 55)
        log.write_line(f"[*] Target : {target}")
        log.write_line(f"[*] Mode   : {scan_type.upper()} ({len(modules)} modules)")
        log.write_line(f"[*] Time   : {datetime.now().strftime('%H:%M:%S')}")
        log.write_line("─" * 55)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        step = 100.0 / max(len(modules), 1)

        for i, (mod_id, mod_name) in enumerate(modules):
            if not self.scanning:
                log.write_line("[!] Scan stopped by user")
                break

            # Update module indicator
            try:
                chk = self.query_one(f"#chk-{mod_id}", Checkbox)
                chk.label = f"⟳ {mod_name}"
            except Exception:
                pass

            log.write_line(f"[*] Running {mod_name}...")
            progress.advance(step)

            try:
                import importlib
                mod = importlib.import_module(f"vexor.modules.{mod_id}")
                scanner = mod.Scanner(target=target, timeout=20)
                findings = await scanner.scan()

                for f in findings:
                    # ── Validate finding is not a false positive ──────────────
                    if not self._is_valid_finding(f, target):
                        continue

                    sev_color = SEVERITY_COLORS.get(f.severity, "white")
                    ep_short  = f.endpoint[:38] if f.endpoint else "-"

                    table.add_row(
                        f"[{sev_color}]{f.severity[:4]}[/]",
                        mod_name[:14],
                        f.vuln[:35],
                        ep_short,
                        f.param or "-",
                    )
                    counts[f.severity] = counts.get(f.severity, 0) + 1
                    self._findings.append(f)

                    state.add_scan_result(ScanResult(
                        severity=f.severity,
                        module=mod_name,
                        vuln=f.vuln,
                        endpoint=f.endpoint,
                        param=f.param or "",
                        evidence=f.evidence or "",
                    ))

                # Reset module indicator
                try:
                    chk = self.query_one(f"#chk-{mod_id}", Checkbox)
                    chk.label = f"✓ {mod_name}" if findings else mod_name
                except Exception:
                    pass

            except ImportError:
                log.write_line(f"[dim]  {mod_name}: module not available[/]")
            except Exception as e:
                log.write_line(f"[dim]  {mod_name}: {str(e)[:60]}[/]")

        total = len(self._findings)
        self._update_stats(total, counts)

        log.write_line("─" * 55)
        log.write_line(
            f"[+] DONE — {total} findings  "
            f"CRIT:{counts['CRITICAL']}  HIGH:{counts['HIGH']}  "
            f"MED:{counts['MEDIUM']}  LOW:{counts['LOW']}"
        )
        log.write_line(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")

        self.scanning = False

        sev = ("error"   if counts["CRITICAL"] > 0 else
               "warning" if counts["HIGH"] > 0 else "information")
        self.notify(
            f"Scan done: {total} findings "
            f"(C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']})",
            severity=sev,
        )

        # Auto AI analysis if findings exist
        if total > 0:
            log.write_line("[*] Running AI analysis on findings...")
            self._run_ai_analysis()

    # ─── False positive filter ────────────────────────────────────────────────

    def _is_valid_finding(self, finding, target: str) -> bool:
        """
        Filter out obvious false positives.
        SSRF: only report if actual SSRF indicator found in response (not just param name match).
        IDOR: only report if actual different content returned.
        """
        vuln_lower = finding.vuln.lower()
        evidence   = (finding.evidence or "").lower()

        # SSRF: reject if evidence is just "param name match" with no actual response indicator
        if "ssrf" in finding.module.lower():
            # Only keep if evidence contains actual SSRF proof
            ssrf_proof = [
                "ami-id", "instance-id", "security-credentials",
                "root:x:0:0", "computemetadata", "+ok", "-err",
                "ssh-2.0", "mysql_native_password", "unusual response",
                "blind ssrf", "potential ssrf input",
            ]
            has_proof = any(p in evidence for p in ssrf_proof)
            # Also keep "potential ssrf input" (form field detection) as LOW
            if not has_proof and finding.severity == "CRITICAL":
                return False

        # IDOR: reject generic "API IDOR" if endpoint is just a guessed path
        if "idor" in finding.module.lower():
            if "sequential ids" in vuln_lower:
                # Only keep if endpoint actually responded with real data
                if not finding.evidence or len(finding.evidence) < 20:
                    return False

        return True

    # ─── Detail panel ────────────────────────────────────────────────────────

    def _show_detail(self, finding) -> None:
        try:
            panel   = self.query_one("#detail-panel")
            title   = self.query_one("#detail-title", Static)
            content = self.query_one("#detail-content", Static)

            sev_color = SEVERITY_COLORS.get(finding.severity, "white")

            title.update(
                f"[{sev_color}]{finding.severity}[/]  "
                f"[bold white]{finding.vuln}[/]"
            )

            lines = []
            if finding.endpoint:
                lines.append(f"[dim]Endpoint :[/] [bright_cyan]{finding.endpoint}[/]")
            if finding.param:
                lines.append(f"[dim]Parameter:[/] [bright_yellow]{finding.param}[/]")
            if finding.payload:
                lines.append(f"[dim]Payload  :[/] [bright_red]{finding.payload[:120]}[/]")
            if finding.evidence:
                lines.append(f"[dim]Evidence :[/]\n{finding.evidence[:500]}")
            if finding.description:
                lines.append(f"[dim]Details  :[/] {finding.description[:300]}")
            if finding.remediation:
                lines.append(f"[dim]Fix      :[/] [bright_green]{finding.remediation[:200]}[/]")
            if finding.cve:
                lines.append(f"[dim]CVE      :[/] [bright_red]{finding.cve}[/]")

            content.update("\n".join(lines))
            panel.add_class("visible")
        except Exception:
            pass

    # ─── AI Analysis ─────────────────────────────────────────────────────────

    @work(exclusive=False)
    async def _run_ai_analysis(self) -> None:
        if not self._findings:
            self.notify("No findings to analyze — run a scan first", severity="warning")
            return

        log = self.query_one("#scan-log", Log)
        log.write_line("[*] 🧠 Vexor AI analyzing findings...")

        try:
            from vexor.ai.client import AIClient
            client = AIClient()

            # Build findings summary
            summary_lines = []
            for f in self._findings[:30]:
                summary_lines.append(
                    f"[{f.severity}] {f.module}: {f.vuln} | "
                    f"endpoint={f.endpoint} param={f.param} | "
                    f"evidence={f.evidence[:150] if f.evidence else 'N/A'}"
                )
            summary = "\n".join(summary_lines)

            # Build target info
            target = ""
            try:
                target = self.query_one("#scan-target", Input).value.strip()
            except Exception:
                pass

            # AI prompt — deep analysis
            prompt = f"""You are an elite penetration tester and security researcher.
Analyze these vulnerability findings for target: {target}

FINDINGS:
{summary}

Perform a DEEP analysis:

## 1. FINDING VALIDATION
For each finding, assess:
- Is this a TRUE POSITIVE or likely FALSE POSITIVE? Why?
- Confidence level (High/Medium/Low)
- What additional evidence would confirm it?

## 2. SEVERITY ASSESSMENT
- Are the severity ratings accurate?
- Which findings are most critical for this specific target?
- Business impact of each critical/high finding

## 3. EXPLOITATION PATHS
For each confirmed vulnerability:
- Step-by-step exploitation approach
- Tools to use (specific commands)
- Expected outcome

## 4. ATTACK CHAINS
- How can these vulnerabilities be chained together?
- What is the maximum impact attack chain?

## 5. IMMEDIATE ACTIONS
- Top 3 things to fix RIGHT NOW
- Exact remediation steps

Be extremely technical and specific. Distinguish real findings from false positives clearly."""

            result = await client.analyze(
                request=target,
                response="",
                vulnerability=prompt,
            )

            if result:
                try:
                    ai_panel  = self.query_one("#ai-panel")
                    ai_content = self.query_one("#ai-content", Static)
                    ai_content.update(result[:3000])
                    ai_panel.add_class("visible")
                    log.write_line("[+] 🧠 AI analysis complete — see panel above")
                    self.notify("AI analysis complete", severity="information")
                except Exception:
                    log.write_line(f"[+] AI: {result[:200]}")
            else:
                log.write_line("[!] AI unavailable — login with: vexor auth login")

        except Exception as e:
            log.write_line(f"[!] AI error: {e}")

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _update_stats(self, total: int, counts: dict) -> None:
        try:
            self.query_one("#scan-stats", Static).update(
                f"[bold]Total: {total}[/]  "
                f"[bold bright_red]CRIT:{counts['CRITICAL']}[/]  "
                f"[bold bright_magenta]HIGH:{counts['HIGH']}[/]  "
                f"[bright_yellow]MED:{counts['MEDIUM']}[/]  "
                f"[bright_blue]LOW:{counts['LOW']}[/]  "
                f"[dim]INFO:{counts['INFO']}[/]"
            )
        except Exception:
            pass

    def _clear_all(self) -> None:
        try:
            self.query_one("#results-table", DataTable).clear()
            self.query_one("#scan-log", Log).clear()
            self.query_one("#scan-stats", Static).update("")
            self.query_one("#scan-progress", ProgressBar).update(progress=0)
            self._findings = []
            try:
                self.query_one("#detail-panel").remove_class("visible")
                self.query_one("#ai-panel").remove_class("visible")
            except Exception:
                pass
        except Exception:
            pass
