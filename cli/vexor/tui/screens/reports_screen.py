"""
Vexor Reports Screen — Fixed responsive layout
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Select
from textual.containers import Horizontal, Vertical, Container
from textual import work
import asyncio
from pathlib import Path


class ReportsScreen(Widget):

    DEFAULT_CSS = """
    ReportsScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .reports-title {
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
    .title-row {
        height: 3;
        margin-bottom: 1;
    }
    .btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .reports-table {
        height: 20;
        border: solid #1a1a2e;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ REPORTS[/]  [dim]Generate Professional Security Reports[/]",
            classes="reports-title"
        )

        with Container(classes="config-section"):
            yield Static("[bold bright_magenta]Report Configuration[/]")
            yield Input(placeholder="Report title...", id="report-title", classes="title-row")
            with Horizontal(classes="btn-row"):
                yield Select(
                    [("HTML Report", "html"), ("PDF Report", "pdf"), ("JSON Export", "json")],
                    id="report-format",
                    value="html"
                )
                yield Button("📄 Generate", id="btn-generate", classes="success")
                yield Button("🤖 AI Enhance", id="btn-ai-enhance")
                yield Button("📂 Open Dir", id="btn-open-dir")
            yield Static(
                "[dim]Reports saved to: ~/.vexor/reports/[/]",
                id="report-path"
            )

        yield Static("[bold bright_magenta]◈ GENERATED REPORTS[/]")
        table = DataTable(classes="reports-table", id="reports-table")
        table.add_columns(
            "Date", "Title", "Format", "Findings",
            "Critical", "High", "Medium", "Low"
        )
        yield table

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-generate":
            self.generate_report()
        elif event.button.id == "btn-ai-enhance":
            self.ai_enhance_report()

    @work(exclusive=True)
    async def generate_report(self) -> None:
        title = self.query_one("#report-title", Input).value or "Vexor Security Report"
        fmt = self.query_one("#report-format", Select).value
        self.notify(f"Generating {fmt.upper()} report...", severity="information")
        try:
            from vexor.config import REPORTS_DIR
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vexor_report_{timestamp}.{fmt}"
            output_path = REPORTS_DIR / filename

            if fmt == "html":
                from vexor.reports.html import HTMLReport
                report = HTMLReport(title=title)
                await report.generate(str(output_path))
            elif fmt == "pdf":
                from vexor.reports.pdf import PDFReport
                report = PDFReport(title=title)
                await report.generate(str(output_path))
            elif fmt == "json":
                import json
                output_path.write_text(json.dumps({"title": title, "findings": []}, indent=2))

            self.notify(f"Saved: {filename}", severity="information")
            table = self.query_one("#reports-table", DataTable)
            table.add_row(
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                title[:30], fmt.upper(), "0", "0", "0", "0", "0"
            )
        except Exception as e:
            self.notify(f"Error: {str(e)}", severity="error")

    @work(exclusive=True)
    async def ai_enhance_report(self) -> None:
        self.notify("AI enhancing...", severity="information")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            await client.write_report_section(findings="Current scan findings")
            self.notify("Report enhanced!", severity="information")
        except Exception as e:
            self.notify(f"AI error: {str(e)}", severity="error")
