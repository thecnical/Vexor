"""
Vexor TUI - Main Application
Persistent screens — state survives navigation
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
from vexor.tui.screens.osint_screen import OSINTScreen
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
    padding: 0;
}

/* Hide all screens by default */
.screen-panel {
    display: none;
    padding: 0 1;
    overflow-y: scroll;
    height: 100%;
}

/* Show active screen */
.screen-panel.active {
    display: block;
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
}
.panel-cyan { border: solid #00ffff; padding: 1; }
.panel-magenta { border: solid #ff00ff; padding: 1; }
.panel-dim { border: solid #1a1a2e; padding: 1; }
"""

SCREEN_MAP = {
    "dashboard": ("dashboard-panel", DashboardScreen),
    "proxy": ("proxy-panel", ProxyScreen),
    "scanner": ("scanner-panel", ScannerScreen),
    "intruder": ("intruder-panel", IntruderScreen),
    "repeater": ("repeater-panel", RepeaterScreen),
    "ai": ("ai-panel", AIScreen),
    "reports": ("reports-panel", ReportsScreen),
    "decoder": ("decoder-panel", DecoderScreen),
    "comparer": ("comparer-panel", ComparerScreen),
    "osint": ("osint-panel", OSINTScreen),
}


class VexorApp(App):
    """Main Vexor TUI — Persistent screens, state preserved"""

    CSS = VEXOR_CSS
    TITLE = f"VEXOR v{TOOL_VERSION}"
    SUB_TITLE = TOOL_TAGLINE

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("escape", "quit", "Quit", priority=True),
        Binding("f1", "show_screen('dashboard')", "Dashboard"),
        Binding("f2", "show_screen('proxy')", "Proxy"),
        Binding("f3", "show_screen('scanner')", "Scanner"),
        Binding("f4", "show_screen('intruder')", "Intruder"),
        Binding("f5", "show_screen('repeater')", "Repeater"),
        Binding("f6", "show_screen('ai')", "AI Panel"),
        Binding("f7", "show_screen('reports')", "Reports"),
        Binding("f8", "show_screen('decoder')", "Decoder"),
        Binding("f9", "show_screen('comparer')", "Comparer"),
        Binding("f10", "show_screen('osint')", "OSINT"),
        Binding("ctrl+h", "show_help", "Help", priority=True),
        Binding("ctrl+o", "toggle_offline", "Offline"),
    ]

    def __init__(self):
        super().__init__()
        self.current_screen = "dashboard"
        self.is_offline = False
        self.is_connected = False

    def compose(self) -> ComposeResult:
        yield VexorHeader()
        with Horizontal():
            yield VexorSidebar()
            with Container(id="main-content"):
                # All screens mounted at once — hidden/shown via CSS
                for name, (panel_id, screen_class) in SCREEN_MAP.items():
                    active = "active" if name == "dashboard" else ""
                    widget = screen_class()
                    widget.add_class("screen-panel")
                    if active:
                        widget.add_class("active")
                    widget.id = panel_id
                    yield widget
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

    def action_show_screen(self, name: str) -> None:
        """Switch to a screen without destroying it"""
        if name not in SCREEN_MAP:
            return

        # Hide all screens
        for n, (panel_id, _) in SCREEN_MAP.items():
            try:
                panel = self.query_one(f"#{panel_id}")
                panel.remove_class("active")
            except Exception:
                pass

        # Show target screen
        panel_id = SCREEN_MAP[name][0]
        try:
            panel = self.query_one(f"#{panel_id}")
            panel.add_class("active")
        except Exception:
            pass

        self.current_screen = name

        # Update sidebar
        try:
            self.query_one(VexorSidebar).set_active(name)
        except Exception:
            pass

        # Update status bar target
        try:
            from vexor.core.state import state
            self.query_one(VexorStatusBar).update_target(state.scan_target)
        except Exception:
            pass

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

        # Update state
        from vexor.core.state import state
        state.is_offline = self.is_offline


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
# VEXOR — Help

## Navigation Keys
| Key | Screen |
|-----|--------|
| F1 | Dashboard |
| F2 | Proxy Interceptor |
| F3 | Scanner |
| F4 | Intruder |
| F5 | Repeater |
| F6 | AI Panel |
| F7 | Reports |
| F8 | Decoder |
| F9 | Comparer |
| F10 | OSINT / SpiderFoot |
| Ctrl+H | This Help |
| Ctrl+O | Toggle Offline Mode |
| Ctrl+Q | Quit |

## Note
**Results are preserved** when switching screens.
Scanner results stay when you go to Intruder and come back.

## CLI Commands
```
vexor                    # Launch TUI
vexor scan <url>         # Quick scan
vexor scan <url> --full  # Full scan (28 modules)
vexor proxy              # Start proxy
vexor auth login         # Login
vexor update             # Update Vexor
vexor --offline          # Offline mode
```

*Created by Chandan Pandey (Technical)*
"""

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="help-container"):
            yield Markdown(self.HELP_TEXT)
