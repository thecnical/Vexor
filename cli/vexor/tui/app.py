"""
Vexor TUI - Main Application
"""
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Static, Markdown
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual import work
import asyncio

from vexor.config import TOOL_VERSION, TOOL_TAGLINE
from vexor.tui.screens.dashboard import DashboardScreen
from vexor.tui.screens.proxy_screen import ProxyScreen
from vexor.tui.screens.scanner_screen import ScannerScreen
from vexor.tui.screens.intruder_screen import IntruderScreen
from vexor.tui.screens.repeater_screen import RepeaterScreen
from vexor.tui.screens.ai_screen import AIScreen
from vexor.tui.screens.reports_screen import ReportsScreen
from vexor.tui.screens.decoder_screen import DecoderScreen
from vexor.tui.screens.comparer_screen import ComparerScreen
from vexor.tui.widgets.header import VexorHeader
from vexor.tui.widgets.sidebar import VexorSidebar
from vexor.tui.widgets.status_bar import VexorStatusBar


VEXOR_CSS = """
Screen {
    background: #0a0a0f;
}

VexorHeader {
    height: 4;
    background: #0d0d1a;
    border-bottom: solid #00ffff;
}

VexorSidebar {
    width: 20;
    background: #0d0d1a;
    border-right: solid #1a1a2e;
}

.sidebar-item {
    padding: 0 2;
    color: #888888;
    height: 3;
}
.sidebar-item:hover {
    background: #1a1a2e;
    color: #00ffff;
}
.sidebar-item.active {
    background: #1a1a2e;
    color: #00ffff;
}
.sidebar-section {
    color: #ff00ff;
    padding: 0 2;
    text-style: bold;
    height: 2;
}

#main-content {
    background: #0a0a0f;
    padding: 0 1;
    overflow-y: scroll;
}

VexorStatusBar {
    height: 1;
    background: #0d0d1a;
    border-top: solid #1a1a2e;
    color: #888888;
}

Button {
    background: #1a1a2e;
    color: #00ffff;
    border: solid #00ffff;
    height: 3;
}
Button:hover {
    background: #00ffff;
    color: #0a0a0f;
}
Button.danger {
    border: solid #ff0055;
    color: #ff0055;
}
Button.danger:hover {
    background: #ff0055;
    color: #0a0a0f;
}
Button.success {
    border: solid #00ff88;
    color: #00ff88;
}
Button.success:hover {
    background: #00ff88;
    color: #0a0a0f;
}

Input {
    background: #1a1a2e;
    color: #ffffff;
    border: solid #333355;
    height: 3;
}
Input:focus {
    border: solid #00ffff;
}

DataTable {
    background: #0d0d1a;
    color: #cccccc;
}
DataTable > .datatable--header {
    background: #1a1a2e;
    color: #00ffff;
    text-style: bold;
}
DataTable > .datatable--cursor {
    background: #1a1a2e;
    color: #ffffff;
}

Log {
    background: #050508;
    color: #00ff88;
    border: solid #1a1a2e;
}

TextArea {
    background: #0d0d1a;
    color: #cccccc;
    border: solid #1a1a2e;
}
TextArea:focus {
    border: solid #00ffff;
}

ProgressBar {
    color: #00ffff;
}

ScrollableContainer {
    background: #0a0a0f;
}

Select {
    background: #1a1a2e;
    color: #ffffff;
    border: solid #333355;
}

.critical { color: #ff0000; text-style: bold; }
.high { color: #ff4400; text-style: bold; }
.medium { color: #ffaa00; }
.low { color: #00aaff; }
.info { color: #888888; }

.section-title {
    color: #ff00ff;
    text-style: bold;
    height: 2;
    padding: 0;
}

.panel-cyan {
    border: solid #00ffff;
    padding: 1;
}
.panel-magenta {
    border: solid #ff00ff;
    padding: 1;
}
.panel-dim {
    border: solid #1a1a2e;
    padding: 1;
}
"""


class VexorApp(App):
    """Main Vexor TUI Application"""

    CSS = VEXOR_CSS
    TITLE = f"VEXOR v{TOOL_VERSION}"
    SUB_TITLE = TOOL_TAGLINE

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("f1", "show_dashboard", "Dashboard"),
        Binding("f2", "show_proxy", "Proxy"),
        Binding("f3", "show_scanner", "Scanner"),
        Binding("f4", "show_intruder", "Intruder"),
        Binding("f5", "show_repeater", "Repeater"),
        Binding("f6", "show_ai", "AI Panel"),
        Binding("f7", "show_reports", "Reports"),
        Binding("f8", "show_decoder", "Decoder"),
        Binding("f9", "show_comparer", "Comparer"),
        Binding("ctrl+h", "show_help", "Help"),
        Binding("ctrl+o", "toggle_offline", "Offline"),
    ]

    def __init__(self):
        super().__init__()
        self.current_screen_name = "dashboard"
        self.is_offline = False
        self.is_connected = False

    def compose(self) -> ComposeResult:
        yield VexorHeader()
        with Horizontal():
            yield VexorSidebar()
            with Container(id="main-content"):
                yield DashboardScreen()
        yield VexorStatusBar()

    def on_mount(self) -> None:
        self.check_connection()

    @work(exclusive=True)
    async def check_connection(self) -> None:
        from vexor.ai.client import AIClient
        client = AIClient()
        self.is_connected = await client.health_check()
        try:
            self.query_one(VexorStatusBar).update_connection(self.is_connected)
        except Exception:
            pass

    def action_show_dashboard(self) -> None:
        self._switch_screen("dashboard", DashboardScreen)

    def action_show_proxy(self) -> None:
        self._switch_screen("proxy", ProxyScreen)

    def action_show_scanner(self) -> None:
        self._switch_screen("scanner", ScannerScreen)

    def action_show_intruder(self) -> None:
        self._switch_screen("intruder", IntruderScreen)

    def action_show_repeater(self) -> None:
        self._switch_screen("repeater", RepeaterScreen)

    def action_show_ai(self) -> None:
        self._switch_screen("ai", AIScreen)

    def action_show_reports(self) -> None:
        self._switch_screen("reports", ReportsScreen)

    def action_show_decoder(self) -> None:
        self._switch_screen("decoder", DecoderScreen)

    def action_show_comparer(self) -> None:
        self._switch_screen("comparer", ComparerScreen)

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_offline(self) -> None:
        self.is_offline = not self.is_offline
        mode = "OFFLINE" if self.is_offline else "ONLINE"
        try:
            self.query_one(VexorStatusBar).update_mode(mode)
        except Exception:
            pass
        self.notify(f"Mode: {mode}", severity="warning" if self.is_offline else "information")

    def _switch_screen(self, name: str, screen_class) -> None:
        try:
            main = self.query_one("#main-content")
            main.remove_children()
            main.mount(screen_class())
            self.current_screen_name = name
            self.query_one(VexorSidebar).set_active(name)
        except Exception as e:
            self.notify(f"Error: {str(e)}", severity="error")


class HelpScreen(Screen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    CSS = """
    HelpScreen {
        background: #0a0a0f;
        align: center middle;
    }
    #help-container {
        width: 90%;
        height: 90%;
        background: #0d0d1a;
        border: solid #00ffff;
        padding: 2;
    }
    """

    HELP_TEXT = """
# VEXOR Help

## Keys
| Key | Action |
|-----|--------|
| F1 | Dashboard |
| F2 | Proxy |
| F3 | Scanner |
| F4 | Intruder |
| F5 | Repeater |
| F6 | AI Panel |
| F7 | Reports |
| F8 | Decoder |
| F9 | Comparer |
| Ctrl+H | Help |
| Ctrl+O | Offline Mode |
| Ctrl+Q | Quit |

## Commands
```
vexor                    # TUI
vexor scan <url>         # Quick scan
vexor scan <url> --full  # Full scan
vexor proxy              # Proxy
vexor auth login         # Login
vexor update             # Update
```

*Created by Chandan Pandey (Technical)*
"""

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="help-container"):
            yield Markdown(self.HELP_TEXT)
