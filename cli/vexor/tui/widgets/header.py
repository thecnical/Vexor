"""
Vexor Header Widget — Beautiful ASCII logo + info
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.console import Console
from rich.align import Align
import datetime

from vexor.config import TOOL_VERSION, TOOL_AUTHOR, TOOL_TAGLINE


LOGO = """[bold bright_cyan]██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ [/]
[bold bright_cyan]██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗[/]
[bold bright_cyan]██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝[/]
[bold bright_magenta]╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗[/]
[bold bright_magenta] ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║[/]
[bold bright_magenta]  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝[/]"""


class VexorHeader(Widget):
    """Beautiful Vexor Header with logo"""

    DEFAULT_CSS = """
    VexorHeader {
        height: 8;
        background: #0d0d1a;
        border-bottom: solid #00ffff;
        padding: 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        yield Static(
            f"{LOGO}\n"
            f"[dim]  AI-Powered CLI Security Toolkit[/]  "
            f"[bright_cyan]v{TOOL_VERSION}[/]  "
            f"[dim]|[/]  [bright_magenta]{TOOL_TAGLINE}[/]  "
            f"[dim]|[/]  [dim]by {TOOL_AUTHOR}[/]  "
            f"[dim]|[/]  [dim]{now}[/]",
            id="header-content"
        )
