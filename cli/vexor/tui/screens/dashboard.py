"""
Vexor Dashboard Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, DataTable, Label
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
import asyncio
import datetime


class StatCard(Static):
    """A stat card widget"""

    def __init__(self, title: str, value: str, color: str = "bright_cyan"):
        self._title = title
        self._value = value
        self._color = color
        super().__init__(self._render())

    def _render(self) -> str:
        return (
            f"[dim]┌─────────────────┐[/]\n"
            f"[dim]│[/] [{self._color}]{self._title:<15}[/] [dim]│[/]\n"
            f"[dim]│[/] [bold {self._color}]{self._value:<15}[/] [dim]│[/]\n"
            f"[dim]└─────────────────┘[/]"
        )

    def update_value(self, value: str) -> None:
        self._value = value
        self.update(self._render())


class DashboardScreen(Widget):
    """Main Dashboard"""

    DEFAULT_CSS = """
    DashboardScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .stats-row {
        height: 6;
        margin-bottom: 1;
    }
    .section-title {
        color: #00ffff;
        text-style: bold;
        padding: 1 0;
    }
    .recent-table {
        height: 15;
        border: solid #1a1a2e;
    }
    .quick-actions {
        height: 8;
        border: solid #1a1a2e;
        padding: 1;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        # Welcome banner
        yield Static(
            "[bold bright_cyan]◈ DASHBOARD[/]  "
            "[dim]Welcome to Vexor — AI-Powered Security Toolkit[/]",
            classes="section-title"
        )

        # Stats row
        with Horizontal(classes="stats-row"):
            yield StatCard("SCANS RUN", "0", "bright_cyan")
            yield StatCard("VULNS FOUND", "0", "bright_red")
            yield StatCard("HIGH SEVERITY", "0", "bright_magenta")
            yield StatCard("AI ANALYSES", "0", "bright_green")
            yield StatCard("REPORTS", "0", "bright_yellow")

        # Recent activity
        yield Static("[bold bright_magenta]◈ RECENT ACTIVITY[/]", classes="section-title")
        table = DataTable(classes="recent-table")
        table.add_columns("Time", "Module", "Target", "Status", "Findings")
        table.add_row(
            "[dim]--:--:--[/]",
            "[dim]---[/]",
            "[dim]No activity yet[/]",
            "[dim]---[/]",
            "[dim]---[/]"
        )
        yield table

        # Quick actions
        yield Static("[bold bright_magenta]◈ QUICK START[/]", classes="section-title")
        with Horizontal(classes="quick-actions"):
            yield Static(
                "[bright_cyan]F2[/] [white]→ Start Proxy[/]\n"
                "[bright_cyan]F3[/] [white]→ Run Scanner[/]\n"
                "[bright_cyan]F4[/] [white]→ Intruder[/]",
            )
            yield Static(
                "[bright_cyan]F5[/] [white]→ Repeater[/]\n"
                "[bright_cyan]F6[/] [white]→ AI Panel[/]\n"
                "[bright_cyan]F7[/] [white]→ Reports[/]",
            )
            yield Static(
                "[bright_magenta]Ctrl+H[/] [white]→ Help[/]\n"
                "[bright_magenta]Ctrl+O[/] [white]→ Offline Mode[/]\n"
                "[bright_magenta]Ctrl+Q[/] [white]→ Quit[/]",
            )

        # System info
        yield Static(
            f"\n[dim]System ready | "
            f"Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"All modules loaded | Offline mode available[/]"
        )
