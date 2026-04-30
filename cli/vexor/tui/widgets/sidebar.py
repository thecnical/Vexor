"""
Vexor Sidebar Widget
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static, Button
from textual.containers import Vertical
from textual.reactive import reactive


MENU_ITEMS = [
    ("dashboard", "F1", "⬡", "Dashboard"),
    ("proxy",     "F2", "⬡", "Proxy"),
    ("scanner",   "F3", "⬡", "Scanner"),
    ("intruder",  "F4", "⬡", "Intruder"),
    ("repeater",  "F5", "⬡", "Repeater"),
    ("ai",        "F6", "⬡", "AI Panel"),
    ("reports",   "F7", "⬡", "Reports"),
]


class SidebarItem(Static):
    """Single sidebar menu item"""

    def __init__(self, name: str, key: str, icon: str, label: str, active: bool = False):
        self._name = name
        self._key = key
        self._icon = icon
        self._label = label
        self._active = active
        super().__init__(self._render_text(), classes=f"sidebar-item {'active' if active else ''}")

    def _render_text(self) -> str:
        if self._active:
            return f"[bold bright_cyan]▶ {self._icon} {self._label}[/] [dim]{self._key}[/]"
        return f"[dim]  {self._icon}[/] [white]{self._label}[/] [dim]{self._key}[/]"

    def set_active(self, active: bool) -> None:
        self._active = active
        self.update(self._render_text())
        if active:
            self.add_class("active")
        else:
            self.remove_class("active")


class VexorSidebar(Widget):
    """Vexor Navigation Sidebar"""

    DEFAULT_CSS = """
    VexorSidebar {
        width: 24;
        background: #0d0d1a;
        border-right: solid #1a1a2e;
        padding: 1 0;
    }
    .sidebar-section {
        color: #ff00ff;
        padding: 1 2;
        text-style: bold;
    }
    .sidebar-item {
        padding: 0 2;
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
        color: #1a1a2e;
        padding: 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_magenta]◈ VEXOR MENU[/]", classes="sidebar-section")
        yield Static("[dim]─────────────────────[/]", classes="sidebar-divider")
        for name, key, icon, label in MENU_ITEMS:
            active = name == "dashboard"
            yield SidebarItem(name, key, icon, label, active)
        yield Static("[dim]─────────────────────[/]", classes="sidebar-divider")
        yield Static("[bold bright_magenta]◈ TOOLS[/]", classes="sidebar-section")
        yield Static("[dim]  ⬡[/] [white]Decoder[/]", classes="sidebar-item")
        yield Static("[dim]  ⬡[/] [white]Comparer[/]", classes="sidebar-item")
        yield Static("[dim]  ⬡[/] [white]Sequencer[/]", classes="sidebar-item")
        yield Static("[dim]─────────────────────[/]", classes="sidebar-divider")
        yield Static("[bold bright_magenta]◈ SETTINGS[/]", classes="sidebar-section")
        yield Static("[dim]  ⬡[/] [white]Config[/]", classes="sidebar-item")
        yield Static("[dim]  ⬡[/] [white]Plugins[/]", classes="sidebar-item")
        yield Static("[dim]─────────────────────[/]", classes="sidebar-divider")
        yield Static(
            "[dim]  Ctrl+H Help | Ctrl+Q Quit[/]",
            classes="sidebar-item"
        )

    def set_active(self, name: str) -> None:
        for item in self.query(SidebarItem):
            item.set_active(item._name == name)
