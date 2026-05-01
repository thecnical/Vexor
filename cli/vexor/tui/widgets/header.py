"""
Vexor Header Widget — Simple centered, never cuts
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from vexor.config import TOOL_VERSION, TOOL_AUTHOR, TOOL_TAGLINE


class VexorHeader(Widget):

    can_focus = False  # Prevent header from intercepting keyboard shortcuts

    DEFAULT_CSS = """
    VexorHeader {
        height: 4;
        background: #0d0d1a;
        border-bottom: solid #00ffff;
    }
    #header-top {
        width: 100%;
        height: 2;
        content-align: center middle;
        text-align: center;
        background: #0d0d1a;
    }
    #header-bottom {
        width: 100%;
        height: 2;
        content-align: center middle;
        text-align: center;
        background: #0d0d1a;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]V E X O R[/]",
            id="header-top"
        )
        yield Static(
            f"[bright_magenta]v{TOOL_VERSION}[/]"
            f"[dim]  ·  [/]"
            f"[dim]{TOOL_TAGLINE}[/]"
            f"[dim]  ·  [/]"
            f"[dim]{TOOL_AUTHOR}[/]",
            id="header-bottom"
        )
