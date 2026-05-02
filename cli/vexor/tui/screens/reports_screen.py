"""
Vexor Reports Screen v3.0 — Professional Templates
HTML · PDF · JSON · Executive Summary · Bug Bounty · Technical
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Select, Log
from textual.containers import Horizontal, Vertical, Container
from textual import work
import asyncio
from pathlib import Path
import datetime


REPORT_TEMPLATES = [
    ("full",       "Full Technical Report"),
    ("executive",  "Executive Summary"),
    ("bugbounty",  "Bug Bounty (HackerOne/Bugcrowd)"),
    ("pentest",    "Pentest Report"),
    ("osint",      "OSINT Intelligence Report"),
]


class ReportsScreen(Widget):

    DEFAULT_CSS = """
    ReportsScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .reports-title { height: 2; color: #00ffff; text-style: bold; }
    .config-section { border: solid #1a1a2e; padding: 1; margin-bottom: 1; height: auto; }
    .title-row { height: 3; margin-bottom: 1; }
    .btn-row { height: 3; margin-bottom: 1; }
    .btn-row Button { height: 3; margin-right: 1; }
    .reports-table { height: 14; border: solid #1a1a2e; margin-bottom: 1; }
    .report-log { height: 8; border: solid #1a1a2e; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ REPORTS[/]  [dim]Professional Security Reports[/]",
            classes="reports-title"
        )

        with Container(classes="config-section"):
            yield Static("[bold bright_magenta]Report Configuration[/]")
            yield Input(placeholder="Report title...", id="report-title", classes="title-row")

            with Horizontal(classes="btn-row"):
                yield Select(
                    [(label, val) for val, label in REPORT_TEMPLATES],
                    id="report-template",
                    value="full",
                )
                yield Select(
                    [("HTML Report", "html"), ("PDF Report", "pdf"), ("JSON Export", "json")],
                    id="report-format",
                    value="html",
                )

            with Horizontal(classes="btn-row"):
                yield Button("📄 Generate",      id="btn-generate",    classes="success")
                yield Button("🤖 AI Enhance",    id="btn-ai-enhance")
                yield Button("📊 From DB",       id="btn-from-db")
                yield Button("📂 Open Dir",      id="btn-open-dir")

            yield Static("[dim]Reports saved to: ~/.vexor/reports/[/]", id="report-path")

        yield Static("[bold bright_magenta]◈ GENERATED REPORTS[/]")
        table = DataTable(classes="reports-table", id="reports-table")
        table.add_columns("Date", "Template", "Format", "Findings", "Critical", "High")
        yield table

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(classes="report-log", id="report-log")

    def on_mount(self) -> None:
        self._load_existing_reports()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-generate":
            self.generate_report()
        elif bid == "btn-ai-enhance":
            self.ai_enhance_report()
        elif bid == "btn-from-db":
            self._generate_from_db()
        elif bid == "btn-open-dir":
            self._show_reports_dir()

    @work(exclusive=True)
    async def generate_report(self) -> None:
        title    = self.query_one("#report-title",    Input).value or "Vexor Security Report"
        fmt      = str(self.query_one("#report-format",   Select).value or "html")
        template = str(self.query_one("#report-template", Select).value or "full")
        log      = self.query_one("#report-log", Log)

        log.write_line(f"[*] Generating {template} {fmt.upper()} report...")

        try:
            from vexor.config import REPORTS_DIR
            from vexor.core.state import state

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename  = f"vexor_{template}_{timestamp}.{fmt}"
            output_path = REPORTS_DIR / filename

            findings = [r.__dict__ for r in state.scan_results]

            if fmt == "html":
                from vexor.reports.html import HTMLReport
                report = HTMLReport(title=title, template=template)
                await report.generate(str(output_path), findings=findings)
            elif fmt == "pdf":
                from vexor.reports.pdf import PDFReport
                report = PDFReport(title=title)
                await report.generate(str(output_path), findings=findings)
            elif fmt == "json":
                import json
                output_path.write_text(json.dumps({
                    "title": title,
                    "template": template,
                    "generated": datetime.datetime.now().isoformat(),
                    "findings": findings,
                    "stats": state.get_stats(),
                }, indent=2, default=str))

            log.write_line(f"[+] Saved: {output_path}")
            self.notify(f"Report saved: {filename}", severity="information")

            # Add to table
            stats = state.get_stats()
            table = self.query_one("#reports-table", DataTable)
            table.add_row(
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                template,
                fmt.upper(),
                str(stats["total"]),
                str(stats["critical"]),
                str(stats["high"]),
            )

            state.reports_generated += 1

        except Exception as e:
            log.write_line(f"[!] Error: {e}")
            self.notify(f"Report error: {str(e)[:60]}", severity="error")

    @work(exclusive=False)
    async def _generate_from_db(self) -> None:
        """Generate report from persisted DB findings"""
        log = self.query_one("#report-log", Log)
        log.write_line("[*] Loading findings from database...")
        try:
            from vexor.core.db import get_all_findings, init_db
            await init_db()
            findings = await get_all_findings(limit=200)
            if not findings:
                log.write_line("[!] No findings in database — run a scan first")
                self.notify("No findings in DB", severity="warning")
                return

            from vexor.config import REPORTS_DIR
            import json
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = REPORTS_DIR / f"vexor_db_report_{ts}.json"
            out.write_text(json.dumps(findings, indent=2, default=str))
            log.write_line(f"[+] DB report: {out} ({len(findings)} findings)")
            self.notify(f"DB report: {out.name}", severity="information")
        except Exception as e:
            log.write_line(f"[!] DB error: {e}")

    @work(exclusive=False)
    async def ai_enhance_report(self) -> None:
        log = self.query_one("#report-log", Log)
        log.write_line("[*] AI enhancing report...")
        try:
            from vexor.ai.client import AIClient
            from vexor.core.state import state
            client = AIClient()
            findings_text = "\n".join(
                f"[{r.severity}] {r.module}: {r.vuln} @ {r.endpoint}"
                for r in state.scan_results[:20]
            )
            if not findings_text:
                log.write_line("[!] No findings to enhance")
                return
            result = await client.write_report_section(findings=findings_text)
            log.write_line(f"[🤖 AI] {result[:300]}")
            self.notify("AI enhancement complete — see log", severity="information")
        except Exception as e:
            log.write_line(f"[!] AI error: {e}")

    def _load_existing_reports(self) -> None:
        try:
            from vexor.config import REPORTS_DIR
            table = self.query_one("#reports-table", DataTable)
            reports = sorted(REPORTS_DIR.glob("vexor_*.{html,pdf,json}"), reverse=True)[:10]
            for r in reports:
                stat = r.stat()
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                table.add_row(mtime, "—", r.suffix[1:].upper(), "—", "—", "—")
        except Exception:
            pass

    def _show_reports_dir(self) -> None:
        try:
            from vexor.config import REPORTS_DIR
            log = self.query_one("#report-log", Log)
            log.write_line(f"[*] Reports directory: {REPORTS_DIR}")
            reports = list(REPORTS_DIR.glob("*.html")) + list(REPORTS_DIR.glob("*.pdf")) + list(REPORTS_DIR.glob("*.json"))
            log.write_line(f"[*] {len(reports)} report(s) found")
            for r in sorted(reports, reverse=True)[:5]:
                log.write_line(f"    {r.name}")
        except Exception:
            pass
