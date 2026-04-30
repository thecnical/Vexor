"""
Vexor OSINT Screen — SpiderFoot-style intelligence
Enter key triggers scan, button works properly
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log
from textual.containers import Horizontal, Vertical, Container
from textual import work
import asyncio


class OSINTScreen(Widget):

    DEFAULT_CSS = """
    OSINTScreen {
        background: #0a0a0f;
        padding: 0 1;
    }
    .osint-title { height: 2; color: #00ffff; text-style: bold; }
    .controls { border: solid #1a1a2e; padding: 1; margin-bottom: 1; }
    .url-row { height: 3; margin-bottom: 1; }
    .btn-row { height: 3; margin-bottom: 1; }
    .results-table { height: 12; border: solid #1a1a2e; margin-bottom: 1; }
    .osint-log { height: 10; border: solid #1a1a2e; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ OSINT[/]  "
            "[bright_magenta]SpiderFoot-style Intelligence Gathering[/]  "
            "[dim]F10 · Press Enter or click Full OSINT[/]",
            classes="osint-title"
        )

        with Container(classes="controls"):
            yield Static("[bold bright_magenta]Target Domain or URL[/]")
            yield Input(
                placeholder="youtube.com or https://target.com — Press Enter to scan",
                id="osint-target",
                classes="url-row"
            )
            with Horizontal(classes="btn-row"):
                yield Button("🕵️ Full OSINT", id="btn-full-osint", classes="success")
                yield Button("🌐 DNS", id="btn-dns")
                yield Button("📜 Cert CT", id="btn-ct")
                yield Button("🔍 Breach", id="btn-breach")
                yield Button("⊘ Clear", id="btn-clear")

        yield Static(
            "[bold bright_magenta]◈ INTELLIGENCE FINDINGS[/]  "
            "[dim]DNS · Subdomains · Emails · IPs · Breaches · Social Media[/]"
        )
        table = DataTable(classes="results-table", id="osint-results")
        table.add_columns("Severity", "Type", "Finding", "Evidence")
        yield table

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(classes="osint-log", id="osint-log")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter key in input field triggers full OSINT"""
        if event.input.id == "osint-target":
            self.run_osint("full")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-full-osint":
            self.run_osint("full")
        elif event.button.id == "btn-dns":
            self.run_osint("dns")
        elif event.button.id == "btn-ct":
            self.run_osint("ct")
        elif event.button.id == "btn-breach":
            self.run_osint("breach")
        elif event.button.id == "btn-clear":
            try:
                self.query_one("#osint-results", DataTable).clear()
                self.query_one("#osint-log", Log).clear()
            except Exception:
                pass

    @work(exclusive=True)
    async def run_osint(self, scan_type: str) -> None:
        target = self.query_one("#osint-target", Input).value.strip()
        if not target:
            self.notify("Enter a target domain or URL first", severity="error")
            return

        # Normalize target
        if not target.startswith("http"):
            target_url = f"https://{target}"
            domain = target
        else:
            from urllib.parse import urlparse
            target_url = target
            domain = urlparse(target).hostname or target
            if domain.startswith("www."):
                domain = domain[4:]

        log = self.query_one("#osint-log", Log)
        table = self.query_one("#osint-results", DataTable)

        log.write_line(f"[*] Starting OSINT on: {domain}")
        log.write_line(f"[*] Modules: DNS, CT logs, emails, IPs, breaches, social media")
        log.write_line(f"[*] Please wait...")

        try:
            from vexor.modules.osint import Scanner
            from vexor.core.state import state, ScanResult

            scanner = Scanner(target=target_url, timeout=30)
            findings = await scanner.scan()

            sev_colors = {
                "CRITICAL": "bold bright_red",
                "HIGH": "bold bright_magenta",
                "MEDIUM": "bright_yellow",
                "LOW": "bright_blue",
                "INFO": "dim white",
            }

            if findings:
                for f in findings:
                    color = sev_colors.get(f.severity, "white")
                    table.add_row(
                        f"[{color}]{f.severity}[/]",
                        f.module[:12],
                        f.vuln[:40],
                        (f.evidence or "-")[:55]
                    )
                    log.write_line(f"[+] {f.severity}: {f.vuln}")
                    state.add_osint_result(ScanResult(
                        severity=f.severity,
                        module=f.module,
                        vuln=f.vuln,
                        endpoint=f.endpoint,
                        evidence=f.evidence or "",
                    ))
            else:
                # Run basic DNS directly as fallback
                log.write_line(f"[*] Running direct DNS lookup for {domain}...")
                await self._direct_dns_lookup(domain, table, log)

            log.write_line(f"[+] OSINT complete! {len(findings)} findings.")
            self.notify(f"OSINT done: {len(findings)} findings", severity="information")

        except Exception as e:
            log.write_line(f"[!] Module error: {str(e)}")
            log.write_line(f"[*] Running fallback DNS lookup...")
            try:
                from urllib.parse import urlparse
                d = urlparse(target_url).hostname or domain
                await self._direct_dns_lookup(d, table, log)
            except Exception as e2:
                log.write_line(f"[!] Fallback error: {str(e2)}")

    async def _direct_dns_lookup(self, domain: str, table: DataTable, log: Log) -> None:
        """Direct DNS lookup without module dependency"""
        import socket
        import asyncio

        log.write_line(f"[*] DNS lookup: {domain}")

        # A record
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            table.add_row("INFO", "dns", f"A Record: {domain}", f"→ {ip}")
            log.write_line(f"[+] A Record: {domain} → {ip}")
        except Exception as e:
            log.write_line(f"[!] DNS A lookup failed: {e}")

        # MX records
        try:
            import dns.resolver
            mx = dns.resolver.resolve(domain, 'MX', lifetime=5)
            for r in mx:
                table.add_row("INFO", "dns", f"MX Record", f"{str(r.exchange)}")
                log.write_line(f"[+] MX: {str(r.exchange)}")
        except Exception:
            pass

        # TXT/SPF
        try:
            import dns.resolver
            txt = dns.resolver.resolve(domain, 'TXT', lifetime=5)
            for r in txt:
                val = str(r)
                if 'spf' in val.lower() or 'dmarc' in val.lower() or 'google' in val.lower():
                    table.add_row("INFO", "dns", "TXT Record", val[:60])
                    log.write_line(f"[+] TXT: {val[:60]}")
        except Exception:
            pass

        # Certificate Transparency
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    subs = set()
                    for cert in data[:50]:
                        name = cert.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain) and sub != domain:
                                subs.add(sub)
                    if subs:
                        table.add_row(
                            "INFO", "ct_logs",
                            f"Subdomains Found ({len(subs)})",
                            ", ".join(list(subs)[:5])
                        )
                        log.write_line(f"[+] CT Logs: {len(subs)} subdomains found")
                        for s in list(subs)[:10]:
                            log.write_line(f"    → {s}")
        except Exception as e:
            log.write_line(f"[!] CT lookup: {e}")

        log.write_line(f"[+] Direct lookup complete")
