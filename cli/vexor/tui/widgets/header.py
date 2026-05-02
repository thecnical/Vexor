"""
Vexor Header Widget v4.0 — Dynamic with live clock and status indicators
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive
from textual import work
from vexor.config import TOOL_VERSION, TOOL_AUTHOR, TOOL_TAGLINE
import datetime
import asyncio


class VexorHeader(Widget):

    can_focus = False

    DEFAULT_CSS = """
    VexorHeader {
        height: 3;
        background: #0d0d1a;
        border-bottom: solid #00ffff;
        dock: top;
    }
    #header-main {
        width: 100%;
        height: 3;
        content-align: center middle;
        text-align: center;
        background: #0d0d1a;
    }
    """

    _clock: str = reactive("")

    def compose(self) -> ComposeResult:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        yield Static(
            self._build(now),
            id="header-main",
        )

    def on_mount(self) -> None:
        self._tick()

    @work(exclusive=False)
    async def _tick(self) -> None:
        """Update clock every second"""
        while True:
            await asyncio.sleep(1)
            try:
                now = datetime.datetime.now().strftime("%H:%M:%S")
                self.query_one("#header-main", Static).update(self._build(now))
            except Exception:
                break

    def _build(self, now: str) -> str:
        return (
            f"[bold bright_cyan]V E X O R[/]  "
            f"[bright_magenta]v{TOOL_VERSION}[/]"
            f"[dim]  ·  {TOOL_TAGLINE}  ·  {TOOL_AUTHOR}  ·  [/]"
            f"[dim]{now}[/]"
        )
