"""
Vexor Header Widget v4.1 — Live clock, target, scan count, proxy status
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual import work
from vexor.config import TOOL_VERSION
import datetime
import asyncio


class VexorHeader(Widget):

    can_focus = False

    DEFAULT_CSS = """
    VexorHeader {
        height: 3;
        background: #080810;
        border-bottom: solid #00ffff;
        dock: top;
    }
    #header-left {
        width: 1fr;
        height: 3;
        content-align: left middle;
        padding: 0 2;
    }
    #header-center {
        width: 1fr;
        height: 3;
        content-align: center middle;
    }
    #header-right {
        width: 1fr;
        height: 3;
        content-align: right middle;
        padding: 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        from textual.containers import Horizontal
        with Horizontal():
            yield Static(
                f"[bold bright_cyan]◈ VEXOR[/] [bright_magenta]v{TOOL_VERSION}[/]",
                id="header-left",
            )
            yield Static(
                "[dim]Penetrate · Analyze · Dominate[/]",
                id="header-center",
            )
            yield Static(
                datetime.datetime.now().strftime("[dim]%H:%M:%S[/]"),
                id="header-right",
            )

    def on_mount(self) -> None:
        self._tick()

    @work(exclusive=False)
    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                now = datetime.datetime.now().strftime("%H:%M:%S")
                self.query_one("#header-right", Static).update(f"[dim]{now}[/]")
            except Exception:
                break

    def update_target(self, target: str) -> None:
        try:
            short = target[:30] if target else "No target"
            self.query_one("#header-center", Static).update(
                f"[dim]▶[/] [bright_cyan]{short}[/]"
            )
        except Exception:
            pass
