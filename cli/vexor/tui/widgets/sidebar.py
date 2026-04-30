"""
Vexor Sidebar Widget — Collapsible sections
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.containers import Vertical
from textual.reactive import reactive


MENU_ITEMS = [
    ("dashboard", "F1",  "Dashboard"),
    ("proxy",     "F2",  "Proxy"),
    ("scanner",   "F3",  "Scanner"),
    ("intruder",  "F4",  "Intruder"),
    ("repeater",  "F5",  "Repeater"),
    ("ai",        "F6",  "AI Panel"),
    ("reports",   "F7",  "Reports"),
]

TOOL_ITEMS = [
    ("decoder",  "F8",  "Decoder"),
    ("comparer", "F9",  "Comparer"),
    ("osint",    "F10", "SpiderFoot"),
]


class SidebarItem(Static):
    def __init__(self, name: str, key: str, label: str, active: bool = False):
        self._name = name
        self._key = key
        self._label = label
        self._active = active
        super().__init__(self._render(), classes=f"sidebar-item {'active' if active else ''}")

    def _render(self) -> str:
        if self._active:
            return f"[bold bright_cyan]▶ {self._label}[/] [dim]{self._key}[/]"
        return f"[dim]  ○[/] [white]{self._label}[/] [dim]{self._key}[/]"

    def set_active(self, active: bool) -> None:
        self._active = active
        self.update(self._render())
        if active:
            self.add_class("active")
        else:
            self.remove_class("active")


class SectionHeader(Static):
    """Collapsible section header"""
    def __init__(self, title: str, section_id: str, collapsed: bool = False):
        self._title = title
        self._section_id = section_id
        self._collapsed = collapsed
        super().__init__(self._render(), classes="sidebar-section-header")

    def _render(self) -> str:
        arrow = "▼" if not self._collapsed else "▶"
        return f"[bold bright_magenta]{arrow} {self._title}[/]"

    def toggle(self) -> bool:
        self._collapsed = not self._collapsed
        self.update(self._render())
        return self._collapsed


class VexorSidebar(Widget):

    DEFAULT_CSS = """
    VexorSidebar {
        width: 22;
        background: #0d0d1a;
        border-right: solid #1a1a2e;
        padding: 0;
        overflow-y: auto;
    }
    .sidebar-brand {
        height: 2;
        color: #ff00ff;
        text-style: bold;
        padding: 0 2;
        background: #0d0d1a;
    }
    .sidebar-section-header {
        height: 2;
        color: #ff00ff;
        text-style: bold;
        padding: 0 2;
        background: #0d0d1a;
    }
    .sidebar-section-header:hover {
        background: #1a1a2e;
        color: #00ffff;
    }
    .sidebar-item {
        padding: 0 3;
        height: 3;
        color: #888888;
    }
    .sidebar-item:hover {
        background: #1a1a2e;
        color: #00ffff;
    }
    .sidebar-item.active {
        background: #1a1a2e;
        color: #00ffff;
    }
    .sidebar-divider {
        height: 1;
        color: #1a1a2e;
        padding: 0 2;
    }
    .sidebar-footer {
        height: 2;
        color: #444444;
        padding: 0 2;
        font-size: 10;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_magenta]◈ VEXOR MENU[/]", classes="sidebar-brand")
        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # Main menu
        for name, key, label in MENU_ITEMS:
            active = name == "dashboard"
            yield SidebarItem(name, key, label, active)

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # Tools section
        yield Static("[bold bright_magenta]▼ TOOLS[/]", classes="sidebar-section-header", id="tools-header")
        for name, key, label in TOOL_ITEMS:
            color = "bright_magenta" if name == "osint" else "white"
            item = SidebarItem(name, key, label)
            yield item

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # Settings
        yield Static("[bold bright_magenta]▼ SETTINGS[/]", classes="sidebar-section-header")
        yield Static("[dim]  ○[/] [white]Config[/]", classes="sidebar-item")
        yield Static("[dim]  ○[/] [white]Plugins[/]", classes="sidebar-item")

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")
        yield Static(
            "[dim]Ctrl+H Help  Ctrl+Q Quit[/]",
            classes="sidebar-footer"
        )

    def set_active(self, name: str) -> None:
        for item in self.query(SidebarItem):
            item.set_active(item._name == name)
