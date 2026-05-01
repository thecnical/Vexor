"""
Vexor OSINT Screen v3.0 — God-Tier Intelligence Gathering
20 modules · Auto-select · Progress per module · Export · Scan history
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
import asyncio
import json
from pathlib import Path
from datetime import datetime


# Module display names and categories
MODULES_INFO = {
    # Direct (always available)
    "dns":          ("🌐", "DNS Records",          "direct"),
    "ct":           ("📜", "Cert Transparency",    "direct"),
    "email":        ("📧", "Email Harvest",         "direct"),
    "ipgeo":        ("📍", "IP Geolocation",        "direct"),
    "ports":        ("🔌", "Port Scan",             "direct"),
    "spf":          ("✉️",  "SPF/DMARC/DKIM",       "direct"),
    "tech":         ("🔧", "Tech Fingerprint",      "direct"),
    "wayback":      ("⏪", "Wayback Machine",       "direct"),
    "github":       ("🐙", "GitHub Search",         "direct"),
    "social":       ("👥", "Social Media",          "direct"),
    "whois":        ("📋", "WHOIS",                 "direct"),
    "asn":          ("🌍", "ASN/BGP",               "direct"),
    "ssl":          ("🔒", "SSL Chain",             "direct"),
    "takeover":     ("⚠️",  "Subdomain Takeover",   "direct"),
    "passive":      ("🕵️", "Passive Subdomains",   "direct"),
    # Backend-proxied (require Render API keys)
    "shodan":       ("🔍", "Shodan",                "backend"),
    "virustotal":   ("🦠", "VirusTotal",            "backend"),
    "otx":          ("👁️",  "AlienVault OTX",       "backend"),
    "urlscan":      ("📸", "URLScan.io",            "backend"),
    "chaos":        ("💥", "Chaos DB",              "backend"),
}

SEV_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH":     "bold bright_magenta",
    "MEDIUM":   "bright_yellow",
    "LOW":      "bright_blue",
    "INFO":     "dim white",
}


class OSINTScreen(Widget):

    DEFAULT_CSS = """
    OSINTScreen {
        background: #0a0a0f;
        padding: 0 1;
    }
    .osint-title   { height: 2; color: #00ffff; text-style: bold; }
    .controls      { border: solid #1a1a2e; padding: 1; margin-bottom: 1; }
    .url-row       { height: 3; margin-bottom: 1; }
    .btn-row       { height: 3; margin-bottom: 1; }
    .mode-row      { height: 3; margin-bottom: 1; }
    .results-table { height: 14; border: solid #1a1a2e; margin-bottom: 1; }
    .osint-log     { height: 10; border: solid #1a1a2e; }
    .history-bar   { height: 2; color: #888888; margin-bottom: 1; }
    .stats-bar     { height: 2; color: #00ff88; margin-bottom: 1; }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._scan_history: list[str] = []   # last 5 targets
        self._current_findings: list[dict] = []
        self._backend_status: dict = {}

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ OSINT v3.0[/]  "
            "[bright_magenta]God-Tier Intelligence · 20 Modules[/]  "
            "[dim]F10 · Enter to scan[/]",
            classes="osint-title"
        )

        with Container(classes="controls"):
            yield Static("[bold bright_magenta]Target  [dim](domain, IP, or URL)[/][/]")
            yield Input(
                placeholder="example.com  or  https://target.com  — Press Enter",
                id="osint-target",
                classes="url-row"
            )

            with Horizontal(classes="mode-row"):
                yield Select(
                    options=[
                        ("🚀 Full Scan (All 20 Modules)",  "full"),
                        ("⚡ Quick Scan (Direct Only)",    "quick"),
                        ("🌐 DNS + Subdomains",            "dns"),
                        ("🔍 Threat Intel (Backend)",      "threat"),
                        ("🔒 SSL + Headers",               "ssl"),
                    ],
                    value="full",
                    id="osint-mode",
                    allow_blank=False,
                )

            with Horizontal(classes="btn-row"):
                yield Button("🕵️ Start OSINT",   id="btn-full-osint",  classes="success")
                yield Button("📤 Export JSON",    id="btn-export")
                yield Button("📊 Backend Status", id="btn-status")
                yield Button("⊘ Clear",           id="btn-clear",       classes="danger")

        yield Static("", id="osint-stats", classes="stats-bar")
        yield Static("", id="osint-history", classes="history-bar")

        yield Static(
            "[bold bright_magenta]◈ INTELLIGENCE FINDINGS[/]  "
            "[dim]Severity · Module · Finding · Evidence[/]"
        )
        table = DataTable(classes="results-table", id="osint-results")
        table.add_columns("Sev", "Module", "Finding", "Evidence")
        yield table

        yield Static("[bold bright_magenta]◈ SCAN LOG[/]")
        yield Log(classes="osint-log", id="osint-log")

    # ─── Events ──────────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "osint-target":
            self.start_scan()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-full-osint":
            self.start_scan()
        elif bid == "btn-export":
            self._export_results()
        elif bid == "btn-status":
            self._check_backend_status()
        elif bid == "btn-clear":
            self._clear_all()

    # ─── Scan launcher ───────────────────────────────────────────────────────

    def start_scan(self) -> None:
        target = self.query_one("#osint-target", Input).value.strip()
        if not target:
            self.notify("Enter a target first", severity="error")
            return
        try:
            mode = self.query_one("#osint-mode", Select).value or "full"
        except Exception:
            mode = "full"
        self.run_osint(target, mode)

    @work(exclusive=True)
    async def run_osint(self, target: str, mode: str = "full") -> None:
        # Normalize
        if not target.startswith("http"):
            target_url = f"https://{target}"
            domain = target.split("/")[0]
        else:
            from urllib.parse import urlparse
            target_url = target
            domain = urlparse(target).hostname or target
        if domain.startswith("www."):
            domain = domain[4:]

        log   = self.query_one("#osint-log", Log)
        table = self.query_one("#osint-results", DataTable)

        log.write_line(f"")
        log.write_line(f"{'─'*60}")
        log.write_line(f"[*] Target  : {domain}")
        log.write_line(f"[*] Mode    : {mode.upper()}")
        log.write_line(f"[*] Started : {datetime.now().strftime('%H:%M:%S')}")
        log.write_line(f"{'─'*60}")

        # Update history
        if domain not in self._scan_history:
            self._scan_history.insert(0, domain)
            self._scan_history = self._scan_history[:5]
        self._update_history_bar()

        self._current_findings = []

        try:
            from vexor.modules.osint import Scanner
            from vexor.core.state import state, ScanResult
            from vexor.core.tool_detector import ToolDetector

            # Show available tools
            tools = ToolDetector.detect()
            if tools:
                log.write_line(f"[*] External tools: {', '.join(tools.keys())}")
            else:
                log.write_line(f"[*] No external tools — using built-in modules")

            log.write_line(f"[*] Phase 1/6: Discovery (DNS, CT, WHOIS, passive subs)...")
            log.write_line(f"[*] Phase 2/6: Live host check...")
            log.write_line(f"[*] Phase 3/6: Deep recon (ports, SSL, crawl)...")
            log.write_line(f"[*] Phase 4/6: Secret extraction (Gf patterns)...")
            log.write_line(f"[*] Phase 5/6: Threat intel (backend)...")
            log.write_line(f"[*] Phase 6/6: AI correlation (Vexor Intelligence)...")
            log.write_line(f"[*] Running all phases — please wait...")

            scanner = Scanner(target=target_url, timeout=30)
            findings = await scanner.scan()

            # Filter by mode
            findings = self._filter_by_mode(findings, mode)

            # Display findings
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            for f in findings:
                color = SEV_COLORS.get(f.severity, "white")
                sev_short = f.severity[:4]
                mod_short = f.module.replace("osint/", "")[:12]

                table.add_row(
                    f"[{color}]{sev_short}[/]",
                    mod_short,
                    f.vuln[:42],
                    (f.evidence.split("\n")[0] if f.evidence else "-")[:50],
                )
                log.write_line(f"[+] [{f.severity}] {f.vuln}")

                counts[f.severity] = counts.get(f.severity, 0) + 1
                self._current_findings.append(f.to_dict())

                state.add_osint_result(ScanResult(
                    severity=f.severity,
                    module=f.module,
                    vuln=f.vuln,
                    endpoint=f.endpoint,
                    evidence=f.evidence or "",
                ))

            # Stats bar
            total = len(findings)
            stats = (
                f"[bold]Total: {total}[/]  "
                f"[bold bright_red]CRIT:{counts['CRITICAL']}[/]  "
                f"[bold bright_magenta]HIGH:{counts['HIGH']}[/]  "
                f"[bright_yellow]MED:{counts['MEDIUM']}[/]  "
                f"[bright_blue]LOW:{counts['LOW']}[/]  "
                f"[dim]INFO:{counts['INFO']}[/]"
            )
            try:
                self.query_one("#osint-stats", Static).update(stats)
            except Exception:
                pass

            log.write_line(f"{'─'*60}")
            log.write_line(
                f"[+] DONE — {total} findings  "
                f"(CRIT:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
                f"MED:{counts['MEDIUM']} LOW:{counts['LOW']})"
            )
            log.write_line(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")

            sev = "error" if counts["CRITICAL"] > 0 else (
                "warning" if counts["HIGH"] > 0 else "information"
            )
            self.notify(
                f"OSINT done: {total} findings "
                f"(C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']})",
                severity=sev,
            )

        except Exception as e:
            log.write_line(f"[!] Error: {str(e)}")
            log.write_line(f"[*] Running fallback DNS lookup...")
            try:
                await self._fallback_dns(domain, table, log)
            except Exception as e2:
                log.write_line(f"[!] Fallback error: {str(e2)}")

    # ─── Mode filter ─────────────────────────────────────────────────────────

    def _filter_by_mode(self, findings, mode: str):
        if mode == "full":
            return findings
        if mode == "quick":
            # Exclude backend modules
            return [f for f in findings if "/" not in f.module]
        if mode == "dns":
            keywords = ["dns", "ct", "subdomain", "passive", "takeover", "whois", "asn"]
            return [f for f in findings if any(k in f.module.lower() or k in f.vuln.lower() for k in keywords)]
        if mode == "threat":
            keywords = ["shodan", "virustotal", "otx", "urlscan", "chaos", "backend"]
            return [f for f in findings if any(k in f.module.lower() or k in f.vuln.lower() for k in keywords)]
        if mode == "ssl":
            keywords = ["ssl", "cert", "header", "tech", "hsts", "csp"]
            return [f for f in findings if any(k in f.module.lower() or k in f.vuln.lower() for k in keywords)]
        return findings

    # ─── Backend status check ─────────────────────────────────────────────────

    @work(exclusive=False)
    async def _check_backend_status(self) -> None:
        log = self.query_one("#osint-log", Log)
        log.write_line("[*] Checking backend OSINT module status...")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            status = await client.osint_status()
            if not status:
                log.write_line("[!] Backend unreachable or not logged in")
                log.write_line("[*] Run: vexor auth login")
                self.notify("Backend unreachable — login first", severity="warning")
                return

            log.write_line("[*] Backend OSINT Module Status:")
            for module, available in status.items():
                icon = "✓" if available else "✗"
                color = "bright_green" if available else "bright_red"
                log.write_line(f"    [{color}]{icon}[/] {module.upper()}")

            available_count = sum(1 for v in status.values() if v)
            self.notify(
                f"Backend: {available_count}/5 modules active",
                severity="information" if available_count > 0 else "warning",
            )
        except Exception as e:
            log.write_line(f"[!] Status check failed: {e}")

    # ─── Export ──────────────────────────────────────────────────────────────

    def _export_results(self) -> None:
        if not self._current_findings:
            self.notify("No findings to export — run a scan first", severity="warning")
            return
        try:
            from vexor.config import REPORTS_DIR
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_slug = (
                self.query_one("#osint-target", Input).value.strip()
                .replace("https://", "").replace("http://", "")
                .replace("/", "_").replace(".", "_")[:30]
            )
            out_file = REPORTS_DIR / f"osint_{target_slug}_{ts}.json"
            out_file.write_text(
                json.dumps(self._current_findings, indent=2, default=str)
            )
            log = self.query_one("#osint-log", Log)
            log.write_line(f"[+] Exported {len(self._current_findings)} findings → {out_file}")
            self.notify(f"Exported to {out_file.name}", severity="information")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

    # ─── Clear ───────────────────────────────────────────────────────────────

    def _clear_all(self) -> None:
        try:
            self.query_one("#osint-results", DataTable).clear()
            self.query_one("#osint-log", Log).clear()
            self.query_one("#osint-stats", Static).update("")
            self._current_findings = []
        except Exception:
            pass

    # ─── History bar ─────────────────────────────────────────────────────────

    def _update_history_bar(self) -> None:
        try:
            if self._scan_history:
                hist = "  [dim]Recent:[/]  " + "  ·  ".join(
                    f"[dim]{t}[/]" for t in self._scan_history
                )
                self.query_one("#osint-history", Static).update(hist)
        except Exception:
            pass

    # ─── Fallback DNS ────────────────────────────────────────────────────────

    async def _fallback_dns(self, domain: str, table: DataTable, log: Log) -> None:
        import socket

        log.write_line(f"[*] DNS fallback for: {domain}")
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            table.add_row("INFO", "dns", f"A Record: {domain}", f"→ {ip}")
            log.write_line(f"[+] A: {domain} → {ip}")
        except Exception as e:
            log.write_line(f"[!] DNS failed: {e}")

        try:
            import dns.resolver
            for rtype in ["MX", "TXT", "NS"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    for r in list(answers)[:2]:
                        val = str(r)[:60]
                        table.add_row("INFO", "dns", f"{rtype} Record", val)
                        log.write_line(f"[+] {rtype}: {val}")
                except Exception:
                    pass
        except ImportError:
            pass

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    subs = set()
                    for cert in resp.json()[:50]:
                        for sub in cert.get("name_value", "").split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain) and sub != domain:
                                subs.add(sub)
                    if subs:
                        table.add_row("INFO", "ct", f"Subdomains ({len(subs)})", ", ".join(list(subs)[:5]))
                        log.write_line(f"[+] CT: {len(subs)} subdomains")
        except Exception:
            pass

        log.write_line("[+] Fallback complete")
