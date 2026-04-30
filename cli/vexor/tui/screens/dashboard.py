"""
Vexor Dashboard Screen — Fixed responsive layout
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, DataTable
from textual.containers import Horizontal, Vertical, Container
import datetime


class DashboardScreen(Widget):

    DEFAULT_CSS = """
    DashboardScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .dash-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .stats-row {
        height: 6;
        margin-bottom: 1;
    }
    .stat-card {
        border: solid #1a1a2e;
        padding: 1;
        margin-right: 1;
        content-align: center middle;
    }
    .stat-value {
        text-style: bold;
        color: #00ffff;
    }
    .activity-table {
        height: 12;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .quickstart {
        border: solid #1a1a2e;
        padding: 1;
        height: auto;
    }
    .section-label {
        color: #ff00ff;
        text-style: bold;
        height: 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ DASHBOARD[/]  [dim]Welcome to Vexor — AI-Powered Security Toolkit[/]",
            classes="dash-title"
        )

        with Horizontal(classes="stats-row"):
            yield Static(
                "[dim]SCANS RUN[/]\n[bold bright_cyan]0[/]",
                classes="stat-card"
            )
            yield Static(
                "[dim]VULNS FOUND[/]\n[bold bright_red]0[/]",
                classes="stat-card"
            )
            yield Static(
                "[dim]HIGH SEVERITY[/]\n[bold bright_magenta]0[/]",
                classes="stat-card"
            )
            yield Static(
                "[dim]AI ANALYSES[/]\n[bold bright_green]0[/]",
                classes="stat-card"
            )
            yield Static(
                "[dim]REPORTS[/]\n[bold bright_yellow]0[/]",
                classes="stat-card"
            )

        yield Static("[bold bright_magenta]◈ RECENT ACTIVITY[/]", classes="section-label")
        table = DataTable(classes="activity-table")
        table.add_columns("Time", "Module", "Target", "Status", "Findings")
        table.add_row("--:--:--", "---", "No activity yet", "---", "---")
        yield table

        yield Static("[bold bright_magenta]◈ QUICK START[/]", classes="section-label")
        with Container(classes="quickstart"):
            with Horizontal():
                yield Static(
                    "[bright_cyan]F2[/] [white]Proxy[/]    "
                    "[bright_cyan]F3[/] [white]Scanner[/]  "
                    "[bright_cyan]F4[/] [white]Intruder[/]\n"
                    "[bright_cyan]F5[/] [white]Repeater[/] "
                    "[bright_cyan]F6[/] [white]AI Panel[/] "
                    "[bright_cyan]F7[/] [white]Reports[/]\n"
                    "[bright_magenta]Ctrl+H[/] [white]Help[/]  "
                    "[bright_magenta]Ctrl+O[/] [white]Offline[/]  "
                    "[bright_magenta]Ctrl+Q[/] [white]Quit[/]"
                )

        yield Static(
            f"\n[dim]Ready | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"All modules loaded[/]"
        )
