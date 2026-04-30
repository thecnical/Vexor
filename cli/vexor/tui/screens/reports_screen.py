"""
Vexor Reports Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
import asyncio
from pathlib import Path


class ReportsScreen(Widget):
    """Reports Generation Screen"""

    DEFAULT_CSS = """
    ReportsScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .report-controls {
        height: 10;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .reports-table {
        height: 20;
        border: solid #1a1a2e;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_cyan]◈ REPORTS[/]  [dim]Generate Professional Security Reports[/]")

        with Container(classes="report-controls"):
            yield Static("[bold bright_magenta]Report Configuration[/]")
            yield Input(placeholder="Report title...", id="report-title")
            with Horizontal():
                yield Select(
                    [("HTML Report", "html"), ("PDF Report", "pdf"), ("JSON Export", "json")],
                    id="report-format",
                    value="html"
                )
                yield Button("📄 Generate Report", id="btn-generate", classes="success")
                yield Button("🤖 AI Enhance", id="btn-ai-enhance")
                yield Button("📂 Open Reports Dir", id="btn-open-dir")
            yield Static(
                "[dim]Reports saved to: ~/.vexor/reports/[/]",
                id="report-path"
            )

        yield Static("[bold bright_magenta]◈ GENERATED REPORTS[/]")
        table = DataTable(classes="reports-table", id="reports-table")
        table.add_columns(
            "Date", "Title", "Format", "Findings",
            "Critical", "High", "Medium", "Low", "Actions"
        )
        yield table

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-generate":
            self.generate_report()
        elif event.button.id == "btn-ai-enhance":
            self.ai_enhance_report()

    @work(exclusive=True)
    async def generate_report(self) -> None:
        """Generate security report"""
        title = self.query_one("#report-title", Input).value or "Vexor Security Report"
        fmt = self.query_one("#report-format", Select).value

        self.notify(f"Generating {fmt.upper()} report...", severity="information")

        try:
            from vexor.reports.html import HTMLReport
            from vexor.reports.pdf import PDFReport
            from vexor.config import REPORTS_DIR
            import datetime

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vexor_report_{timestamp}.{fmt}"
            output_path = REPORTS_DIR / filename

            if fmt == "html":
                report = HTMLReport(title=title)
                await report.generate(output_path)
            elif fmt == "pdf":
                report = PDFReport(title=title)
                await report.generate(output_path)

            self.notify(f"Report saved: {filename}", severity="information")

            table = self.query_one("#reports-table", DataTable)
            table.add_row(
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                title,
                fmt.upper(),
                "0", "0", "0", "0", "0",
                f"[bright_cyan]Open[/]"
            )

        except Exception as e:
            self.notify(f"Report error: {str(e)}", severity="error")

    @work(exclusive=True)
    async def ai_enhance_report(self) -> None:
        """AI enhance report"""
        self.notify("AI enhancing report...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            result = await client.write_report_section(findings="Current scan findings")
            self.notify("Report enhanced with AI!", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
