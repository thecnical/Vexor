"""
Vexor Sidebar Widget v3.0 — Full nav including Spider (F11) + History (Ctrl+G)
- Added Spider + History menu items
- Premium look: icons, severity badge counts, active indicator bar
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.containers import Vertical
from textual.reactive import reactive
from textual.message import Message


MENU_ITEMS = [
    ("dashboard", "F1",  "🏠", "Dashboard"),
    ("proxy",     "F2",  "🌐", "Proxy"),
    ("scanner",   "F3",  "🔍", "Scanner"),
    ("intruder",  "F4",  "⚔", "Intruder"),
    ("repeater",  "F5",  "🔁", "Repeater"),
    ("ai",        "F6",  "🧠", "AI Panel"),
    ("reports",   "F7",  "📄", "Reports"),
]

TOOL_ITEMS = [
    ("decoder",  "F8",      "🔐", "Decoder"),
    ("comparer", "F9",      "⚖", "Comparer"),
    ("osint",    "F10",     "🕵", "OSINT"),
    ("spider",   "F11",     "🕷", "Spider"),
    ("history",  "Ctrl+G",  "📋", "History"),
]

SETTINGS_ITEMS = [
    ("config",  "`",      "⚙", "Config"),
    ("plugins", "F12",    "🔌", "Plugins"),
    ("notes",   "Ctrl+N", "📝", "Notes"),
]


class SidebarItem(Static):

    class Navigate(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    def __init__(self, name: str, key: str, icon: str, label: str, active: bool = False):
        self._name   = name
        self._key    = key
        self._icon   = icon
        self._label  = label
        self._active = active
        super().__init__(self._render(), classes=f"sidebar-item {'active' if active else ''}")

    def _render(self) -> str:
        if self._active:
            return (
                f"[bold bright_cyan]┃ {self._icon} {self._label}[/] "
                f"[dim bright_cyan]{self._key}[/]"
            )
        return (
            f"[dim]  {self._icon}[/] [white]{self._label}[/] "
            f"[dim]{self._key}[/]"
        )

    def set_active(self, active: bool) -> None:
        self._active = active
        self.update(self._render())
        if active:
            self.add_class("active")
        else:
            self.remove_class("active")

    def on_click(self) -> None:
        self.post_message(self.Navigate(self._name))


class SectionHeader(Static):
    """Collapsible section header"""

    class Toggled(Message):
        def __init__(self, section_id: str, collapsed: bool) -> None:
            super().__init__()
            self.section_id = section_id
            self.collapsed = collapsed

    def __init__(self, title: str, section_id: str, item_count: int = 0, collapsed: bool = False):
        self._title      = title
        self._section_id = section_id
        self._item_count = item_count
        self._collapsed  = collapsed
        super().__init__(self._render(), classes="sidebar-section-header")

    def _render(self) -> str:
        arrow = "▶" if self._collapsed else "▼"
        count = f" [dim]({self._item_count})[/]" if self._collapsed else ""
        return f"[bold bright_magenta]{arrow} {self._title}[/]{count}"

    def on_click(self) -> None:
        self._collapsed = not self._collapsed
        self.update(self._render())
        self.post_message(self.Toggled(self._section_id, self._collapsed))

    @property
    def collapsed(self) -> bool:
        return self._collapsed

    def set_collapsed(self, value: bool) -> None:
        self._collapsed = value
        self.update(self._render())


class CollapsibleSection(Vertical):
    DEFAULT_CSS = "CollapsibleSection { height: auto; }"

    def __init__(self, section_id: str, *args, **kwargs):
        self._section_id = section_id
        self._collapsed  = False
        super().__init__(*args, **kwargs, id=f"section-{section_id}")

    def collapse(self) -> None:
        self._collapsed = True
        self.display = False

    def expand(self) -> None:
        self._collapsed = False
        self.display = True

    def toggle(self) -> bool:
        if self._collapsed:
            self.expand()
        else:
            self.collapse()
        return self._collapsed


class VexorSidebar(Widget):

    DEFAULT_CSS = """
    VexorSidebar {
        width: 24;
        background: #080810;
        border-right: solid #1a1a2e;
        padding: 0;
        overflow-y: auto;
    }
    .sidebar-logo {
        height: 3;
        padding: 0 2;
        color: #00ffff;
        text-style: bold;
        background: #0d0d1a;
        border-bottom: solid #1a1a2e;
        content-align: center middle;
    }
    .sidebar-section-header {
        height: 2;
        color: #ff00ff;
        text-style: bold;
        padding: 0 2;
        background: #0a0a12;
    }
    .sidebar-section-header:hover {
        background: #12122a;
        color: #00ffff;
        cursor: pointer;
    }
    .sidebar-item {
        padding: 0 2;
        height: 3;
        color: #666688;
    }
    .sidebar-item:hover {
        background: #12122a;
        color: #00ffff;
        cursor: pointer;
    }
    .sidebar-item.active {
        background: #0d1a2a;
        color: #00ffff;
        border-left: solid #00ffff;
    }
    .sidebar-divider {
        height: 1;
        color: #1a1a2e;
        padding: 0 2;
    }
    .sidebar-footer {
        height: 3;
        color: #333355;
        padding: 0 2;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ VEXOR[/] [dim bright_magenta]v4.1[/]",
            classes="sidebar-logo",
        )

        # ── MAIN section ──
        yield SectionHeader("MAIN", "menu", item_count=len(MENU_ITEMS))
        with CollapsibleSection("menu"):
            for name, key, icon, label in MENU_ITEMS:
                yield SidebarItem(name, key, icon, label, active=(name == "dashboard"))

        yield Static("[dim]────────────────────────[/]", classes="sidebar-divider")

        # ── TOOLS section ──
        yield SectionHeader("TOOLS", "tools", item_count=len(TOOL_ITEMS))
        with CollapsibleSection("tools"):
            for name, key, icon, label in TOOL_ITEMS:
                yield SidebarItem(name, key, icon, label)

        yield Static("[dim]────────────────────────[/]", classes="sidebar-divider")

        # ── SETTINGS section ──
        yield SectionHeader("SETTINGS", "settings", item_count=len(SETTINGS_ITEMS))
        with CollapsibleSection("settings"):
            for name, key, icon, label in SETTINGS_ITEMS:
                yield SidebarItem(name, key, icon, label)

        yield Static("[dim]────────────────────────[/]", classes="sidebar-divider")
        yield Static(
            "[dim]Ctrl+H Help[/]\n[dim]Ctrl+Q Quit[/]",
            classes="sidebar-footer",
        )

    def on_section_header_toggled(self, event: SectionHeader.Toggled) -> None:
        try:
            section = self.query_one(f"#section-{event.section_id}", CollapsibleSection)
            if event.collapsed:
                section.collapse()
            else:
                section.expand()
        except Exception:
            pass

    def on_sidebar_item_navigate(self, event: SidebarItem.Navigate) -> None:
        try:
            self.app.action_show_screen(event.name)
        except Exception:
            pass

    def set_active(self, name: str) -> None:
        for item in self.query(SidebarItem):
            item.set_active(item._name == name)
