"""
Vexor OSINT Screen v4.0 — Fully Responsive, God-Tier Intelligence
Target input always visible · Phase progress · Export · Backend status
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, Select
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual import work
import asyncio
import json
from datetime import datetime


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
        height: 100%;
        overflow-y: auto;
    }

    /* ── Top bar: title + target input always visible ── */
    .osint-header {
        height: auto;
        background: #0d0d1a;
        border-bottom: solid #1a1a2e;
        padding: 1 2;
    }
    .osint-title {
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
    #osint-target {
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #00ffff;
        margin-bottom: 1;
    }
    #osint-target:focus {
        border: solid #00ff88;
    }

    /* ── Mode + buttons row ── */
    .controls-row {
        height: 3;
        margin-bottom: 1;
    }
    #osint-mode {
        width: 1fr;
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #333355;
        margin-right: 1;
    }

    /* ── Buttons ── */
    .osint-btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .osint-btn-row Button {
        height: 3;
        margin-right: 1;
    }

    /* ── Stats + history ── */
    .osint-stats {
        height: 1;
        color: #00ff88;
        padding: 0 2;
        margin-bottom: 1;
    }
    .osint-history {
        height: 1;
        color: #444466;
        padding: 0 2;
        margin-bottom: 1;
    }

    /* ── Results section ── */
    .section-label {
        height: 2;
        color: #ff00ff;
        text-style: bold;
        padding: 0 2;
    }
    #osint-results {
        height: 14;
        border: solid #1a1a2e;
        margin: 0 1 1 1;
    }

    /* ── Log ── */
    #osint-log {
        height: 12;
        border: solid #1a1a2e;
        margin: 0 1 1 1;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._scan_history: list[str] = []
        self._current_findings: list[dict] = []

    def compose(self) -> ComposeResult:
        # ── Header: always visible ────────────────────────────────────────────
        with Vertical(classes="osint-header"):
            yield Static(
                "[bold bright_cyan]◈ OSINT v4.0[/]  "
                "[bright_magenta]Vexor Intelligence Engine · 6-Phase Pipeline[/]  "
                "[dim]F10[/]",
                classes="osint-title",
            )
            yield Static(
                "[bold bright_magenta]Target[/]  "
                "[dim]domain · IP · URL[/]",
                classes="target-label",
            )
            yield Input(
                placeholder="example.com  or  https://target.com  — Press Enter to scan",
                id="osint-target",
            )

            # Mode selector + scan button on same row
            with Horizontal(classes="controls-row"):
                yield Select(
                    options=[
                        ("🚀 Full Scan — All 6 Phases",   "full"),
                        ("⚡ Quick — Direct Modules Only", "quick"),
                        ("🌐 DNS + Subdomains",            "dns"),
                        ("🔍 Threat Intel (Backend)",      "threat"),
                        ("🔒 SSL + Headers",               "ssl"),
                    ],
                    value="full",
                    id="osint-mode",
                    allow_blank=False,
                )

            # Action buttons
            with Horizontal(classes="osint-btn-row"):
                yield Button("🕵️ Start OSINT",   id="btn-start",   classes="success")
                yield Button("📊 Backend Status", id="btn-status")
                yield Button("📤 Export JSON",    id="btn-export")
                yield Button("⊘ Clear",           id="btn-clear",   classes="danger")

        # ── Stats + history ───────────────────────────────────────────────────
        yield Static("", id="osint-stats",   classes="osint-stats")
        yield Static("", id="osint-history", classes="osint-history")

        # ── Results table ─────────────────────────────────────────────────────
        yield Static(
            "[bold bright_magenta]◈ INTELLIGENCE FINDINGS[/]  "
            "[dim]Sev · Module · Finding · Evidence[/]",
            classes="section-label",
        )
        table = DataTable(id="osint-results")
        table.add_columns("Sev", "Module", "Finding", "Evidence")
        yield table

        # ── Scan log ──────────────────────────────────────────────────────────
        yield Static("[bold bright_magenta]◈ SCAN LOG[/]", classes="section-label")
        yield Log(id="osint-log")

    # ─── Events ──────────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "osint-target":
            self._start_scan()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-start":
            self._start_scan()
        elif bid == "btn-status":
            self._check_backend_status()
        elif bid == "btn-export":
            self._export_results()
        elif bid == "btn-clear":
            self._clear_all()

    # ─── Scan ────────────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        target = self.query_one("#osint-target", Input).value.strip()
        if not target:
            self.notify("Enter a target domain or URL first", severity="error")
            return
        try:
            mode = str(self.query_one("#osint-mode", Select).value or "full")
        except Exception:
            mode = "full"
        self._run_osint(target, mode)

    @work(exclusive=True)
    async def _run_osint(self, target: str, mode: str = "full") -> None:
        # Normalize target
        if not target.startswith("http"):
            target_url = f"https://{target}"
            domain = target.split("/")[0].split("?")[0]
        else:
            from urllib.parse import urlparse
            target_url = target
            domain = urlparse(target).hostname or target
        if domain.startswith("www."):
            domain = domain[4:]

        log   = self.query_one("#osint-log", Log)
        table = self.query_one("#osint-results", DataTable)

        log.write_line("")
        log.write_line("─" * 58)
        log.write_line(f"[*] Target  : {domain}")
        log.write_line(f"[*] Mode    : {mode.upper()}")
        log.write_line(f"[*] Time    : {datetime.now().strftime('%H:%M:%S')}")
        log.write_line("─" * 58)

        # Update history bar
        if domain not in self._scan_history:
            self._scan_history.insert(0, domain)
            self._scan_history = self._scan_history[:5]
        self._update_history()

        self._current_findings = []

        try:
            from vexor.modules.osint import Scanner
            from vexor.core.state import state, ScanResult
            from vexor.core.tool_detector import ToolDetector

            tools = ToolDetector.detect()
            if tools:
                log.write_line(f"[*] External tools: {', '.join(tools.keys())}")

            log.write_line("[*] Phase 1/6 — Discovery (DNS, CT, WHOIS, passive subs)...")
            log.write_line("[*] Phase 2/6 — Live host check on all subdomains...")
            log.write_line("[*] Phase 3/6 — Deep recon (ports, SSL, crawl)...")
            log.write_line("[*] Phase 4/6 — Secret extraction (Gf patterns)...")
            log.write_line("[*] Phase 5/6 — Threat intel (Shodan/VT/OTX)...")
            log.write_line("[*] Phase 6/6 — AI correlation (Vexor Intelligence)...")
            log.write_line("[*] Running — this may take 1-3 minutes...")

            scanner = Scanner(target=target_url, timeout=30)
            findings = await scanner.scan()
            findings = self._filter_by_mode(findings, mode)

            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            for f in findings:
                color     = SEV_COLORS.get(f.severity, "white")
                sev_short = f.severity[:4]
                mod_short = f.module.replace("osint/", "")[:12]
                ev_first  = (f.evidence.split("\n")[0] if f.evidence else "-")[:48]

                table.add_row(
                    f"[{color}]{sev_short}[/]",
                    mod_short,
                    f.vuln[:40],
                    ev_first,
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

            total = len(findings)
            self._update_stats(total, counts)

            log.write_line("─" * 58)
            log.write_line(
                f"[+] DONE — {total} findings  "
                f"CRIT:{counts['CRITICAL']}  HIGH:{counts['HIGH']}  "
                f"MED:{counts['MEDIUM']}  LOW:{counts['LOW']}"
            )
            log.write_line(f"[*] Finished: {datetime.now().strftime('%H:%M:%S')}")

            sev = ("error"   if counts["CRITICAL"] > 0 else
                   "warning" if counts["HIGH"] > 0 else "information")
            self.notify(
                f"OSINT done: {total} findings "
                f"(C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']})",
                severity=sev,
            )

        except Exception as e:
            log.write_line(f"[!] Error: {e}")
            log.write_line("[*] Running fallback DNS lookup...")
            try:
                await self._fallback_dns(domain, table, log)
            except Exception as e2:
                log.write_line(f"[!] Fallback error: {e2}")

    # ─── Mode filter ─────────────────────────────────────────────────────────

    def _filter_by_mode(self, findings, mode: str):
        if mode == "full":
            return findings
        if mode == "quick":
            return [f for f in findings if "/" not in f.module]
        if mode == "dns":
            kw = ["dns", "ct", "subdomain", "passive", "takeover", "whois", "asn"]
            return [f for f in findings
                    if any(k in f.module.lower() or k in f.vuln.lower() for k in kw)]
        if mode == "threat":
            kw = ["shodan", "virustotal", "otx", "urlscan", "chaos", "backend"]
            return [f for f in findings
                    if any(k in f.module.lower() or k in f.vuln.lower() for k in kw)]
        if mode == "ssl":
            kw = ["ssl", "cert", "header", "tech", "hsts", "csp"]
            return [f for f in findings
                    if any(k in f.module.lower() or k in f.vuln.lower() for k in kw)]
        return findings

    # ─── Backend status ───────────────────────────────────────────────────────

    @work(exclusive=False)
    async def _check_backend_status(self) -> None:
        log = self.query_one("#osint-log", Log)
        log.write_line("")
        log.write_line("[*] Checking backend OSINT module status...")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            status = await client.osint_status()

            if not status:
                log.write_line("[!] Backend unreachable or not logged in")
                log.write_line("[*] Fix: vexor auth login")
                self.notify("Not connected — run: vexor auth login", severity="warning")
                return

            log.write_line("[*] Backend OSINT Modules:")
            active = 0
            for module, ok in status.items():
                icon  = "✓" if ok else "✗"
                color = "bright_green" if ok else "bright_red"
                log.write_line(f"    [{color}]{icon}[/] {module.upper()}")
                if ok:
                    active += 1

            log.write_line(f"[*] {active}/5 modules active")
            self.notify(
                f"Backend: {active}/5 modules active",
                severity="information" if active > 0 else "warning",
            )
        except Exception as e:
            log.write_line(f"[!] Status check failed: {e}")

    # ─── Export ──────────────────────────────────────────────────────────────

    def _export_results(self) -> None:
        if not self._current_findings:
            self.notify("No findings — run a scan first", severity="warning")
            return
        try:
            from vexor.config import REPORTS_DIR
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            slug = (
                self.query_one("#osint-target", Input).value.strip()
                .replace("https://", "").replace("http://", "")
                .replace("/", "_").replace(".", "_")[:30]
            )
            out = REPORTS_DIR / f"osint_{slug}_{ts}.json"
            out.write_text(json.dumps(self._current_findings, indent=2, default=str))
            self.query_one("#osint-log", Log).write_line(
                f"[+] Exported {len(self._current_findings)} findings → {out}"
            )
            self.notify(f"Exported: {out.name}", severity="information")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

    # ─── Clear ───────────────────────────────────────────────────────────────

    def _clear_all(self) -> None:
        try:
            self.query_one("#osint-results", DataTable).clear()
            self.query_one("#osint-log", Log).clear()
            self.query_one("#osint-stats",   Static).update("")
            self.query_one("#osint-history", Static).update("")
            self._current_findings = []
        except Exception:
            pass

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _update_stats(self, total: int, counts: dict) -> None:
        try:
            self.query_one("#osint-stats", Static).update(
                f"[bold]Total: {total}[/]  "
                f"[bold bright_red]CRIT:{counts['CRITICAL']}[/]  "
                f"[bold bright_magenta]HIGH:{counts['HIGH']}[/]  "
                f"[bright_yellow]MED:{counts['MEDIUM']}[/]  "
                f"[bright_blue]LOW:{counts['LOW']}[/]  "
                f"[dim]INFO:{counts['INFO']}[/]"
            )
        except Exception:
            pass

    def _update_history(self) -> None:
        try:
            if self._scan_history:
                self.query_one("#osint-history", Static).update(
                    "[dim]Recent:[/]  " +
                    "  ·  ".join(f"[dim]{t}[/]" for t in self._scan_history)
                )
        except Exception:
            pass

    # ─── Fallback DNS ────────────────────────────────────────────────────────

    async def _fallback_dns(self, domain: str, table: DataTable, log: Log) -> None:
        import socket
        log.write_line(f"[*] DNS fallback: {domain}")
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            table.add_row("INFO", "dns", f"A: {domain}", f"→ {ip}")
            log.write_line(f"[+] A: {domain} → {ip}")
        except Exception as e:
            log.write_line(f"[!] DNS failed: {e}")

        try:
            import dns.resolver
            for rtype in ["MX", "TXT", "NS"]:
                try:
                    for r in list(dns.resolver.resolve(domain, rtype, lifetime=5))[:2]:
                        val = str(r)[:60]
                        table.add_row("INFO", "dns", rtype, val)
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
                        table.add_row("INFO", "ct", f"Subdomains ({len(subs)})",
                                      ", ".join(list(subs)[:5]))
                        log.write_line(f"[+] CT: {len(subs)} subdomains")
        except Exception:
            pass

        log.write_line("[+] Fallback complete")
