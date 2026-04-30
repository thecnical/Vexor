"""
Vexor TUI - Main Application
Beautiful, colorful, responsive terminal UI
"""
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import (
    Static, Button, Input, DataTable, Log, ProgressBar,
    Markdown
)
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
from vexor.tui.widgets.header import VexorHeader
from vexor.tui.widgets.sidebar import VexorSidebar
from vexor.tui.widgets.status_bar import VexorStatusBar


VEXOR_CSS = """
/* Global Styles */
Screen {
    background: #0a0a0f;
}

/* Header */
VexorHeader {
    height: 7;
    background: #0d0d1a;
    border-bottom: solid #00ffff;
}

/* Sidebar */
VexorSidebar {
    width: 22;
    background: #0d0d1a;
    border-right: solid #1a1a2e;
}

.sidebar-item {
    padding: 1 2;
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
    border-left: solid #00ffff;
}

.sidebar-section {
    color: #ff00ff;
    padding: 1 2;
    text-style: bold;
}

/* Main Content */
#main-content {
    background: #0a0a0f;
    padding: 1 2;
}

/* Status Bar */
VexorStatusBar {
    height: 1;
    background: #0d0d1a;
    border-top: solid #1a1a2e;
    color: #888888;
}

/* Buttons */
Button {
    background: #1a1a2e;
    color: #00ffff;
    border: solid #00ffff;
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

/* Input */
Input {
    background: #1a1a2e;
    color: #ffffff;
    border: solid #333355;
}

Input:focus {
    border: solid #00ffff;
}

/* DataTable */
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

/* Log */
Log {
    background: #050508;
    color: #00ff88;
    border: solid #1a1a2e;
}

/* Labels */
.label-cyan { color: #00ffff; }
.label-magenta { color: #ff00ff; }
.label-green { color: #00ff88; }
.label-red { color: #ff0055; }
.label-yellow { color: #ffff00; }
.label-orange { color: #ff8800; }
.label-white { color: #ffffff; }
.label-dim { color: #555555; }

/* Panels */
.panel {
    background: #0d0d1a;
    border: solid #1a1a2e;
    padding: 1;
    margin: 1;
}

.panel-title {
    color: #00ffff;
    text-style: bold;
    padding-bottom: 1;
}

/* Progress */
ProgressBar {
    color: #00ffff;
}

/* Scrollable */
ScrollableContainer {
    background: #0a0a0f;
}

/* TabbedContent */
TabbedContent {
    background: #0a0a0f;
}

TabPane {
    background: #0a0a0f;
    padding: 1;
}

/* Severity badges */
.critical { color: #ff0000; text-style: bold; }
.high { color: #ff4400; text-style: bold; }
.medium { color: #ffaa00; }
.low { color: #00aaff; }
.info { color: #888888; }
"""


class VexorApp(App):
    """Main Vexor TUI Application"""

    CSS = VEXOR_CSS
    TITLE = f"VEXOR v{TOOL_VERSION}"
    SUB_TITLE = TOOL_TAGLINE

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark"),
        Binding("f1", "show_dashboard", "Dashboard"),
        Binding("f2", "show_proxy", "Proxy"),
        Binding("f3", "show_scanner", "Scanner"),
        Binding("f4", "show_intruder", "Intruder"),
        Binding("f5", "show_repeater", "Repeater"),
        Binding("f6", "show_ai", "AI Panel"),
        Binding("f7", "show_reports", "Reports"),
        Binding("ctrl+h", "show_help", "Help"),
        Binding("ctrl+o", "toggle_offline", "Offline Mode"),
    ]

    def __init__(self):
        super().__init__()
        self.current_screen_name = "dashboard"
        self.is_offline = False
        self.is_connected = False
        self.target_url = ""

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
        """Check backend connection"""
        from vexor.ai.client import AIClient
        client = AIClient()
        self.is_connected = await client.health_check()
        self.query_one(VexorStatusBar).update_connection(self.is_connected)

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

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_offline(self) -> None:
        self.is_offline = not self.is_offline
        mode = "OFFLINE" if self.is_offline else "ONLINE"
        self.query_one(VexorStatusBar).update_mode(mode)
        self.notify(
            f"Switched to {mode} mode",
            severity="warning" if self.is_offline else "information"
        )

    def _switch_screen(self, name: str, screen_class) -> None:
        main = self.query_one("#main-content")
        main.remove_children()
        main.mount(screen_class())
        self.current_screen_name = name
        self.query_one(VexorSidebar).set_active(name)


class HelpScreen(Screen):
    """Detailed Help Screen with AI"""

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
# 🔥 VEXOR — Help Guide

## Navigation
| Key | Action |
|-----|--------|
| F1 | Dashboard |
| F2 | Proxy Interceptor |
| F3 | Scanner |
| F4 | Intruder |
| F5 | Repeater |
| F6 | AI Panel |
| F7 | Reports |
| Ctrl+H | This Help |
| Ctrl+O | Toggle Offline Mode |
| Ctrl+Q | Quit |

## Commands (CLI)
```bash
vexor                    # Launch TUI
vexor scan <url>         # Quick scan
vexor proxy              # Start proxy
vexor fuzz <url>         # Fuzz target
vexor ai analyze         # AI analysis
vexor report             # Generate report
vexor --offline          # Offline mode
vexor --help             # Full help
```

## Modules
| Module | Description |
|--------|-------------|
| SQLi | SQL Injection detection |
| XSS | Cross-Site Scripting |
| CSRF | CSRF vulnerability |
| IDOR | Insecure Direct Object Reference |
| SSRF | Server-Side Request Forgery |
| XXE | XML External Entity |
| LFI | Local File Inclusion |
| JWT | JWT token analysis & attacks |
| SSL | SSL/TLS misconfiguration |
| CORS | CORS misconfiguration |
| Headers | Security headers check |
| WebSocket | WebSocket security test |
| API | REST/GraphQL testing |
| Subdomain | Subdomain enumeration |
| DirBust | Directory bruteforce |
| CVE | CVE lookup & matching |
| Wayback | Historical endpoints |
| GitHub | GitHub secret dorking |
| Fingerprint | Technology detection |
| RateLimit | Rate limit testing |
| FileUpload | File upload bypass |
| Redirect | Open redirect finder |
| Session | Session/cookie analysis |
| SensData | Sensitive data exposure |

## AI Features (Online Mode)
- **Analyze**: Deep vulnerability analysis
- **Explain**: Explain any request/response
- **Suggest**: Next attack suggestions
- **Payload**: AI-generated payloads
- **Filter**: False positive removal
- **Report**: AI-written reports

## Offline Mode
All scanning modules work without internet.
AI features disabled in offline mode.
Use `Ctrl+O` to toggle.

---
*Created by Chandan Pandey (Technical)*
*Version 1.0.0 | vexor --version*
"""

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="help-container"):
            yield Markdown(self.HELP_TEXT)
