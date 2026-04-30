"""
Vexor Header Widget — Centered logo
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from vexor.config import TOOL_VERSION, TOOL_AUTHOR, TOOL_TAGLINE


class VexorHeader(Widget):
    """Centered Vexor Header"""

    DEFAULT_CSS = """
    VexorHeader {
        height: 5;
        background: #0d0d1a;
        border-bottom: solid #00ffff;
        align: center middle;
        content-align: center middle;
    }
    #header-content {
        width: 100%;
        content-align: center middle;
        text-align: center;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            f"[bold bright_cyan]██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗[/]\n"
            f"[bold bright_cyan]╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║[/]\n"
            f"[bold bright_magenta] v{TOOL_VERSION}  ·  {TOOL_TAGLINE}  ·  {TOOL_AUTHOR}[/]",
            id="header-content"
        )
