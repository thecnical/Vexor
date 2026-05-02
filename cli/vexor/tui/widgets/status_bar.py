"""
Vexor Status Bar Widget v4.0
Live: connection · mode · target · scan stats · shortcuts
"""
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive


class VexorStatusBar(Widget):

    DEFAULT_CSS = """
    VexorStatusBar {
        height: 1;
        background: #0d0d1a;
        border-top: solid #1a1a2e;
        padding: 0 1;
        dock: bottom;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._connected = False
        self._mode = "ONLINE"
        self._target = ""
        self._findings = 0
        self._scans = 0

    def compose(self) -> ComposeResult:
        yield Static(self._render(), id="status-text")

    def _render(self) -> str:
        conn = (
            "[bright_green]● CONNECTED[/]"
            if self._connected else
            "[bright_red]● OFFLINE[/]"
        )
        mode = (
            "[bright_yellow]OFFLINE[/]"
            if self._mode == "OFFLINE" else
            "[bright_cyan]ONLINE[/]"
        )
        target = (
            f"[dim]▶[/] [bright_cyan]{self._target[:30]}[/]"
            if self._target else
            "[dim]No target[/]"
        )
        stats = (
            f"[dim]Findings:[/] [bright_red]{self._findings}[/]  "
            f"[dim]Scans:[/] [bright_cyan]{self._scans}[/]"
        )
        shortcuts = "[dim]F1-F10 Nav · ` Config · Ctrl+N Notes · Ctrl+H Help · Ctrl+Q Quit[/]"

        return (
            f"{conn}  [dim]│[/]  {mode}  [dim]│[/]  "
            f"{target}  [dim]│[/]  {stats}  [dim]│[/]  {shortcuts}"
        )

    def _refresh(self) -> None:
        try:
            self.query_one("#status-text", Static).update(self._render())
        except Exception:
            pass

    def update_connection(self, connected: bool) -> None:
        self._connected = connected
        self._refresh()

    def update_mode(self, mode: str) -> None:
        self._mode = mode
        self._refresh()

    def update_target(self, target: str) -> None:
        self._target = target
        self._refresh()

    def update_stats(self, findings: int = 0, scans: int = 0) -> None:
        self._findings = findings
        self._scans = scans
        self._refresh()
