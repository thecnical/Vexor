"""
Vexor Status Bar Widget
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive
import datetime


class VexorStatusBar(Widget):
    """Bottom status bar"""

    DEFAULT_CSS = """
    VexorStatusBar {
        height: 1;
        background: #0d0d1a;
        border-top: solid #1a1a2e;
        padding: 0 2;
    }
    """

    connected = reactive(False)
    mode = reactive("ONLINE")
    target = reactive("")

    def compose(self) -> ComposeResult:
        yield Static(self._render(), id="status-text")

    def _render(self) -> str:
        conn = "[bright_green]● CONNECTED[/]" if self.connected else "[bright_red]● DISCONNECTED[/]"
        mode = "[bright_yellow]OFFLINE[/]" if self.mode == "OFFLINE" else "[bright_cyan]ONLINE[/]"
        target = f"[dim]Target:[/] [bright_cyan]{self.target}[/]" if self.target else "[dim]No target[/]"
        now = datetime.datetime.now().strftime("%H:%M:%S")
        return (
            f"{conn}  [dim]|[/]  Mode: {mode}  [dim]|[/]  "
            f"{target}  [dim]|[/]  "
            f"[dim]F1-F7 Navigate | Ctrl+H Help | Ctrl+Q Quit | {now}[/]"
        )

    def update_connection(self, connected: bool) -> None:
        self.connected = connected
        self.query_one("#status-text").update(self._render())

    def update_mode(self, mode: str) -> None:
        self.mode = mode
        self.query_one("#status-text").update(self._render())

    def update_target(self, target: str) -> None:
        self.target = target
        self.query_one("#status-text").update(self._render())
