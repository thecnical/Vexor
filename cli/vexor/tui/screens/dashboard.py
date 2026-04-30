"""
Vexor Dashboard v2.0.0 — Live stats from global state
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, DataTable
from textual.containers import Horizontal, Container
from textual.reactive import reactive
from textual import work
import asyncio
import datetime


class DashboardScreen(Widget):

    DEFAULT_CSS = """
    DashboardScreen {
        background: #0a0a0f;
        padding: 0 1;
    }
    .dash-title { height: 2; color: #00ffff; text-style: bold; }
    .stats-row { height: 5; margin-bottom: 1; }
    .stat-card {
        border: solid #1a1a2e;
        padding: 0 1;
        margin-right: 1;
        height: 5;
        content-align: center middle;
    }
    .activity-table { height: 10; border: solid #1a1a2e; margin-bottom: 1; }
    .quickstart { border: solid #1a1a2e; padding: 1; height: 7; }
    .section-label { color: #ff00ff; text-style: bold; height: 2; }
    .backend-status { height: 2; margin-bottom: 1; }
    .whats-new {
        border: solid #ff00ff;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ DASHBOARD[/]  "
            "[dim]Welcome to Vexor — AI-Powered Security Toolkit[/]  "
            "[bold bright_magenta on #1a0030] v2.0.0 [/]",
            classes="dash-title"
        )

        # Backend status
        yield Static(
            "[dim]Checking backend...[/]",
            id="backend-status",
            classes="backend-status"
        )

        # Live stats — v2.0.0 badge in stats area
        with Horizontal(classes="stats-row"):
            yield Static(
                "[dim]VERSION[/]\n[bold bright_magenta]v2.0.0[/]",
                classes="stat-card",
                id="stat-version"
            )
            yield Static("[dim]SCANS RUN[/]\n[bold bright_cyan]0[/]", classes="stat-card", id="stat-scans")
            yield Static("[dim]VULNS FOUND[/]\n[bold bright_red]0[/]", classes="stat-card", id="stat-vulns")
            yield Static("[dim]HIGH+CRIT[/]\n[bold bright_magenta]0[/]", classes="stat-card", id="stat-high")
            yield Static("[dim]AI ANALYSES[/]\n[bold bright_green]0[/]", classes="stat-card", id="stat-ai")
            yield Static("[dim]PROXY REQS[/]\n[bold bright_yellow]0[/]", classes="stat-card", id="stat-proxy")

        # What's New in v2.0
        yield Static("[bold bright_magenta]◈ WHAT'S NEW IN v2.0[/]", classes="section-label")
        with Container(classes="whats-new"):
            yield Static(
                "[bold bright_cyan]🔥 Scanner[/]  50+ SQLi payloads · WAF bypass · MySQL/PG/MSSQL/Oracle · Header injection\n"
                "[bold bright_cyan]⚡ Intruder[/]  50 parallel requests · req/s counter · smart interesting detection · progress bar\n"
                "[bold bright_cyan]🌐 Proxy[/]    Match & replace rules · JWT/Bearer detection · WebSocket support · history search\n"
                "[bold bright_cyan]🕵 OSINT[/]    10 modules: DNS · CT logs · email harvest · IP geo · port scan · Wayback · GitHub\n"
                "[bold bright_cyan]🤖 AI Panel[/] Auto Exploit chain · CVSS Risk Score · Translate · provider info · chat history\n"
                "[bold bright_cyan]📄 Reports[/]  Executive summary · risk gauge · severity charts · CVSS scores · PoC sections\n"
                "[bold bright_cyan]◈ Sidebar[/]   Collapsible sections · item count · smooth toggle"
            )

        yield Static("[bold bright_magenta]◈ RECENT FINDINGS[/]", classes="section-label")
        table = DataTable(classes="activity-table", id="recent-table")
        table.add_columns("Time", "Severity", "Module", "Vulnerability", "Target")
        yield table

        yield Static("[bold bright_magenta]◈ QUICK START[/]", classes="section-label")
        with Container(classes="quickstart"):
            yield Static(
                "[bright_cyan]F2[/] Proxy  "
                "[bright_cyan]F3[/] Scanner  "
                "[bright_cyan]F4[/] Intruder  "
                "[bright_cyan]F5[/] Repeater  "
                "[bright_cyan]F6[/] AI Panel  "
                "[bright_cyan]F7[/] Reports\n"
                "[bright_cyan]F8[/] Decoder  "
                "[bright_cyan]F9[/] Comparer  "
                "[bright_cyan]F10[/] OSINT/SpiderFoot  "
                "[bright_magenta]Ctrl+H[/] Help  "
                "[bright_magenta]Ctrl+Q[/] Quit"
            )
            yield Static(
                f"[dim]Vexor v2.0.0 · {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} · "
                f"28 modules · F10 = SpiderFoot OSINT[/]",
                id="dash-footer"
            )

    def on_mount(self) -> None:
        """Start live updates when dashboard is shown"""
        self.refresh_stats()
        self.check_backend()

    def on_show(self) -> None:
        """Called every time dashboard becomes visible"""
        self.refresh_stats()

    def refresh_stats(self) -> None:
        """Update stats from global state"""
        try:
            from vexor.core.state import state
            stats = state.get_stats()

            self.query_one("#stat-scans").update(
                f"[dim]SCANS RUN[/]\n[bold bright_cyan]{stats['scans_run']}[/]"
            )
            self.query_one("#stat-vulns").update(
                f"[dim]VULNS FOUND[/]\n[bold bright_red]{stats['total']}[/]"
            )
            self.query_one("#stat-high").update(
                f"[dim]HIGH+CRIT[/]\n[bold bright_magenta]{stats['critical'] + stats['high']}[/]"
            )
            self.query_one("#stat-ai").update(
                f"[dim]AI ANALYSES[/]\n[bold bright_green]{stats['ai_analyses']}[/]"
            )
            self.query_one("#stat-proxy").update(
                f"[dim]PROXY REQS[/]\n[bold bright_yellow]{stats['proxy_requests']}[/]"
            )

            # Update recent findings table
            table = self.query_one("#recent-table", DataTable)
            table.clear()

            recent = state.scan_results[-10:]  # Last 10
            if recent:
                sev_colors = {
                    "CRITICAL": "bold bright_red",
                    "HIGH": "bold bright_magenta",
                    "MEDIUM": "bright_yellow",
                    "LOW": "bright_blue",
                    "INFO": "dim white",
                }
                for r in reversed(recent):
                    color = sev_colors.get(r.severity, "white")
                    table.add_row(
                        r.timestamp,
                        f"[{color}]{r.severity}[/]",
                        r.module,
                        r.vuln[:35],
                        r.endpoint[:30],
                    )
            else:
                table.add_row("--:--:--", "---", "---", "No findings yet", "---")

        except Exception:
            pass

    @work(exclusive=True)
    async def check_backend(self) -> None:
        """Check backend connectivity"""
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            connected = await client.health_check()
            status_widget = self.query_one("#backend-status")
            if connected:
                status_widget.update(
                    "[bright_green]● Backend CONNECTED[/]  "
                    "[dim]AI features available[/]"
                )
            else:
                status_widget.update(
                    "[bright_yellow]● Backend OFFLINE[/]  "
                    "[dim]AI features limited — use Ctrl+O for offline mode[/]"
                )
        except Exception:
            pass
