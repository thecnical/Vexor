"""
Vexor TUI - Main Application
Persistent screens — state survives navigation
"""
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Static, Markdown, ContentSwitcher
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
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
from vexor.tui.screens.config_screen import ConfigScreen
from vexor.tui.screens.plugins_screen import PluginsScreen
from vexor.tui.screens.notes_screen import NotesScreen
from vexor.tui.screens.spider_screen import SpiderScreen
from vexor.tui.screens.history_screen import HistoryScreen
from vexor.tui.widgets.header import VexorHeader
from vexor.tui.widgets.sidebar import VexorSidebar
from vexor.tui.widgets.status_bar import VexorStatusBar


VEXOR_CSS = """
Screen {
    background: #0a0a0f;
}

VexorHeader {
    height: 3;
    background: #0d0d1a;
    border-bottom: solid #00ffff;
}

VexorStatusBar {
    height: 1;
    background: #0d0d1a;
    border-top: solid #1a1a2e;
    color: #888888;
}

#body-row {
    height: 1fr;
}

VexorSidebar {
    width: 22;
    background: #0d0d1a;
    border-right: solid #1a1a2e;
    height: 1fr;
    overflow-y: auto;
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

ContentSwitcher {
    height: 1fr;
    width: 1fr;
    background: #0a0a0f;
}

/* Each screen inside ContentSwitcher */
DashboardScreen, ProxyScreen, ScannerScreen, IntruderScreen,
RepeaterScreen, AIScreen, ReportsScreen, DecoderScreen,
ComparerScreen, OSINTScreen, ConfigScreen, PluginsScreen, NotesScreen,
SpiderScreen, HistoryScreen {
    height: 1fr;
    overflow-y: auto;
    padding: 0 1;
    background: #0a0a0f;
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

.section-title { color: #ff00ff; text-style: bold; height: 2; }
.panel-cyan { border: solid #00ffff; padding: 1; }
.panel-magenta { border: solid #ff00ff; padding: 1; }
.panel-dim { border: solid #1a1a2e; padding: 1; }
"""

SCREEN_MAP = {
    "dashboard": ("dashboard", DashboardScreen),
    "proxy":     ("proxy",     ProxyScreen),
    "scanner":   ("scanner",   ScannerScreen),
    "intruder":  ("intruder",  IntruderScreen),
    "repeater":  ("repeater",  RepeaterScreen),
    "ai":        ("ai",        AIScreen),
    "reports":   ("reports",   ReportsScreen),
    "decoder":   ("decoder",   DecoderScreen),
    "comparer":  ("comparer",  ComparerScreen),
    "osint":     ("osint",     OSINTScreen),
    "config":    ("config",    ConfigScreen),
    "plugins":   ("plugins",   PluginsScreen),
    "notes":     ("notes",     NotesScreen),
    "spider":    ("spider",    SpiderScreen),
    "history":   ("history",   HistoryScreen),
}


class VexorApp(App):
    """Main Vexor TUI — ContentSwitcher for reliable screen switching"""

    CSS = VEXOR_CSS
    TITLE = f"VEXOR v{TOOL_VERSION}"
    SUB_TITLE = TOOL_TAGLINE

    BINDINGS = [
        Binding("ctrl+q", "quit",                   "Quit",    priority=True),
        Binding("escape", "quit",                   "Quit",    priority=True),
        Binding("f1",  "show_screen('dashboard')",  "Dashboard"),
        Binding("f2",  "show_screen('proxy')",      "Proxy"),
        Binding("f3",  "show_screen('scanner')",    "Scanner"),
        Binding("f4",  "show_screen('intruder')",   "Intruder"),
        Binding("f5",  "show_screen('repeater')",   "Repeater"),
        Binding("f6",  "show_screen('ai')",         "AI Panel"),
        Binding("f7",  "show_screen('reports')",    "Reports"),
        Binding("f8",  "show_screen('decoder')",    "Decoder"),
        Binding("f9",  "show_screen('comparer')",   "Comparer"),
        Binding("f10", "show_screen('osint')",      "OSINT"),
        Binding("f11", "show_screen('spider')",     "Spider",  priority=True),
        Binding("grave_accent", "show_screen('config')",   "Config",   priority=True),
        Binding("f12", "show_screen('plugins')",    "Plugins",  priority=True),
        Binding("ctrl+n", "show_screen('notes')",   "Notes",    priority=True),
        Binding("ctrl+g", "show_screen('history')", "History",  priority=True),
        Binding("ctrl+h", "show_help",              "Help",     priority=True),
        Binding("ctrl+o", "toggle_offline",         "Offline"),
    ]

    def __init__(self):
        super().__init__()
        self.current_screen = "dashboard"
        self.is_offline = False
        self.is_connected = False

    def compose(self) -> ComposeResult:
        yield VexorHeader()
        with Horizontal(id="body-row"):
            yield VexorSidebar()
            with ContentSwitcher(initial="dashboard", id="switcher"):
                for name, (panel_id, screen_class) in SCREEN_MAP.items():
                    widget = screen_class()
                    widget.id = panel_id
                    yield widget
        yield VexorStatusBar()

    def on_mount(self) -> None:
        self.check_connection()
        self._init_db()

    @work(exclusive=False)
    async def _init_db(self) -> None:
        try:
            from vexor.core.db import init_db
            await init_db()
        except Exception:
            pass

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
        """Switch screen using ContentSwitcher"""
        if name not in SCREEN_MAP:
            return
        try:
            self.query_one("#switcher", ContentSwitcher).current = name
            self.current_screen = name
        except Exception:
            pass

        # Update sidebar highlight
        try:
            self.query_one(VexorSidebar).set_active(name)
        except Exception:
            pass

        # Update status bar
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
# VEXOR v4.1 — Keyboard Reference

## TUI Navigation
| Key | Screen | What you can do |
|-----|--------|-----------------|
| F1  | Dashboard | Live stats, recent findings, quick start |
| F2  | Proxy | Start/stop HTTP proxy, MITM toggle, intercept, passive scan |
| F3  | Scanner | Full/Quick/Custom scan, 35 modules, AI analysis |
| F4  | Intruder | 4 attack modes, §position§ markers, wordlist |
| F5  | Repeater | Edit raw HTTP request, send, diff responses |
| F6  | AI Panel | Analyze, PoC, CVSS, translate, chat |
| F7  | Reports | Generate HTML/PDF/JSON from session or current scan |
| F8  | Decoder | Base64/URL/Hex/JWT/HTML/ROT13 |
| F9  | Comparer | Diff two requests or responses |
| F10 | OSINT | 6-phase intelligence pipeline |
| F11 | Spider | JS-aware web crawler, send URLs to Scanner |
| ` (backtick) | Config | Login/logout, backend URL, scan settings |
| F12 | Plugins | Plugin manager |
| Ctrl+N | Notes | Pentest notes, tag by target |
| Ctrl+G | History | All past DB sessions, load findings, sync to cloud |
| Ctrl+H | Help | This screen |
| Ctrl+O | Toggle | Online ↔ Offline mode |
| Ctrl+Q / Esc | Quit | Exit Vexor |

## Proxy MITM Setup
1. Press F2 → check ☑ MITM
2. Click ▶ Start
3. Install CA cert shown at top → ~/.vexor/ca/vexor_ca.crt
4. Chrome: Settings → Privacy → Certificates → Import
5. Firefox: Settings → Privacy → Certificates → Import

## Intruder Quick Start
1. Press F2 (Proxy) → select request → → Intruder
2. Wrap injection points: GET /login?user=§admin§ HTTP/1.1
3. Pick attack mode: Sniper / Battering Ram / Pitchfork / Cluster Bomb
4. Load wordlist → Run

## Scan History
Ctrl+G → select session → view findings → Generate Report or Sync to Cloud

*Vexor v4.1 · Created by Chandan Pandey (Technical)*
"""

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="help-container"):
            yield Markdown(self.HELP_TEXT)
