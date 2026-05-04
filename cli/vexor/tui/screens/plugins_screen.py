"""
Vexor Plugins Screen — View and manage installed plugins
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, DataTable, Log
from textual.containers import Horizontal, Vertical
from textual import work


class PluginsScreen(Widget):

    DEFAULT_CSS = """
    PluginsScreen {
        background: #0a0a0f;
        height: auto;
        overflow-y: auto;
        padding: 1 2;
    }
    .plugins-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
        margin-bottom: 1;
    }
    .plugins-info {
        height: auto;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        color: #888888;
    }
    #plugins-table {
        height: 14;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .plugins-btn-row {
        height: 3;
        margin-bottom: 1;
    }
    #plugins-log {
        height: 10;
        border: solid #1a1a2e;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ PLUGINS[/]  "
            "[bright_magenta]Vexor Plugin Manager[/]",
            classes="plugins-title",
        )

        with Vertical(classes="plugins-info"):
            yield Static(
                "[dim]Plugins extend Vexor with custom scan modules.\n"
                "Place plugin files in [bright_cyan]~/.vexor/plugins/[/]\n"
                "Each plugin must have a [bright_cyan]Scanner[/] class inheriting from [bright_cyan]BaseScanner[/].[/]"
            )

        yield Static("[bold bright_magenta]◈ INSTALLED PLUGINS[/]")
        table = DataTable(id="plugins-table")
        table.add_columns("Name", "Version", "Description", "Status")
        yield table

        with Horizontal(classes="plugins-btn-row"):
            yield Button("🔄 Refresh", id="btn-refresh-plugins")
            yield Button("📂 Open Plugins Dir", id="btn-open-plugins-dir")

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(id="plugins-log")

    def on_mount(self) -> None:
        self._load_plugins()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh-plugins":
            self._load_plugins()
        elif event.button.id == "btn-open-plugins-dir":
            self._show_plugins_dir()

    def _load_plugins(self) -> None:
        try:
            from vexor.config import PLUGINS_DIR
            from vexor.plugins.manager import PluginManager
            table = self.query_one("#plugins-table", DataTable)
            log   = self.query_one("#plugins-log", Log)
            table.clear()

            manager = PluginManager()
            plugins = manager.list_plugins()

            if not plugins:
                table.add_row("—", "—", "No plugins installed", "—")
                log.write_line(f"[*] Plugins dir: {PLUGINS_DIR}")
                log.write_line("[*] No plugins found")
                log.write_line(f"[*] Add plugins to: {PLUGINS_DIR}")
            else:
                for p in plugins:
                    table.add_row(
                        p.get("name", "unknown"),
                        p.get("version", "1.0"),
                        p.get("description", "")[:40],
                        "[bright_green]Active[/]",
                    )
                    log.write_line(f"[+] Loaded: {p.get('name')}")

            log.write_line(f"[*] {len(plugins)} plugin(s) loaded")
        except Exception as e:
            try:
                self.query_one("#plugins-log", Log).write_line(f"[!] Error: {e}")
            except Exception:
                pass

    def _show_plugins_dir(self) -> None:
        try:
            from vexor.config import PLUGINS_DIR
            log = self.query_one("#plugins-log", Log)
            log.write_line(f"[*] Plugins directory: {PLUGINS_DIR}")
            log.write_line(f"[*] Place .py plugin files here")
            self.notify(f"Plugins dir: {PLUGINS_DIR}", severity="information")
        except Exception:
            pass
