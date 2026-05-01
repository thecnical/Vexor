"""
Vexor Sidebar Widget v2.0.0 — Collapsible sections
Click section header to collapse/expand · Item count in collapsed state
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.containers import Vertical
from textual.reactive import reactive
from textual.message import Message


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

SETTINGS_ITEMS = [
    ("config",   "F11", "Config"),
    ("plugins",  "F12", "Plugins"),
]


class SidebarItem(Static):

    class Navigate(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

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

    def on_click(self) -> None:
        self.post_message(self.Navigate(self._name))


class SectionHeader(Static):
    """Collapsible section header — click to toggle"""

    class Toggled(Message):
        def __init__(self, section_id: str, collapsed: bool) -> None:
            super().__init__()
            self.section_id = section_id
            self.collapsed = collapsed

    def __init__(
        self,
        title: str,
        section_id: str,
        item_count: int = 0,
        collapsed: bool = False,
    ):
        self._title = title
        self._section_id = section_id
        self._item_count = item_count
        self._collapsed = collapsed
        super().__init__(self._render(), classes="sidebar-section-header")

    def _render(self) -> str:
        if self._collapsed:
            return (
                f"[bold bright_magenta]▶ {self._title}[/] "
                f"[dim]({self._item_count})[/]"
            )
        return f"[bold bright_magenta]▼ {self._title}[/]"

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
    """A section that can be collapsed/expanded"""

    DEFAULT_CSS = """
    CollapsibleSection {
        height: auto;
    }
    """

    def __init__(self, section_id: str, *args, **kwargs):
        self._section_id = section_id
        self._collapsed = False
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
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold bright_magenta]◈ VEXOR MENU[/]", classes="sidebar-brand")
        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # ── VEXOR MENU section (always visible, collapsible) ──
        yield SectionHeader(
            "VEXOR MENU",
            "menu",
            item_count=len(MENU_ITEMS),
            collapsed=False,
        )
        with CollapsibleSection("menu"):
            for name, key, label in MENU_ITEMS:
                active = name == "dashboard"
                yield SidebarItem(name, key, label, active)

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # ── TOOLS section ──
        yield SectionHeader(
            "TOOLS",
            "tools",
            item_count=len(TOOL_ITEMS),
            collapsed=False,
        )
        with CollapsibleSection("tools"):
            for name, key, label in TOOL_ITEMS:
                yield SidebarItem(name, key, label)

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")

        # ── SETTINGS section ──
        yield SectionHeader(
            "SETTINGS",
            "settings",
            item_count=len(SETTINGS_ITEMS),
            collapsed=False,
        )
        with CollapsibleSection("settings"):
            for name, key, label in SETTINGS_ITEMS:
                yield SidebarItem(name, key, label)

        yield Static("[dim]──────────────────────[/]", classes="sidebar-divider")
        yield Static(
            "[dim]Ctrl+H Help  Ctrl+Q Quit[/]",
            classes="sidebar-footer"
        )

    def on_section_header_toggled(self, event: SectionHeader.Toggled) -> None:
        """Handle section collapse/expand"""
        try:
            section = self.query_one(
                f"#section-{event.section_id}", CollapsibleSection
            )
            if event.collapsed:
                section.collapse()
            else:
                section.expand()
        except Exception:
            pass

    def on_sidebar_item_navigate(self, event: SidebarItem.Navigate) -> None:
        """Route navigation to the app"""
        try:
            self.app.action_show_screen(event.name)
        except Exception:
            pass

    def set_active(self, name: str) -> None:
        for item in self.query(SidebarItem):
            item.set_active(item._name == name)
