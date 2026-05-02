"""
Vexor Notes Screen — Pentest notes with SQLite persistence
Notes survive app restarts. Per-target or global notes.
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, TextArea, Log
from textual.containers import Horizontal, Vertical, Container
from textual import work
from datetime import datetime


class NotesScreen(Widget):

    DEFAULT_CSS = """
    NotesScreen {
        background: #0a0a0f;
        height: 100%;
        overflow-y: auto;
        padding: 0 1;
    }
    .notes-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
        margin-bottom: 1;
    }
    .notes-layout {
        height: 100%;
    }
    .notes-list-panel {
        width: 35%;
        border-right: solid #1a1a2e;
        padding: 0 1 0 0;
        height: 100%;
    }
    .notes-edit-panel {
        width: 65%;
        padding: 0 0 0 1;
        height: 100%;
    }
    .panel-label {
        height: 2;
        color: #ff00ff;
        text-style: bold;
    }
    #notes-table {
        height: 20;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    .list-btn-row {
        height: 3;
        margin-bottom: 1;
    }
    .list-btn-row Button {
        height: 3;
        margin-right: 1;
    }
    #note-title-input {
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #333355;
        margin-bottom: 1;
    }
    #note-title-input:focus {
        border: solid #00ffff;
    }
    #note-target-input {
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #333355;
        margin-bottom: 1;
    }
    #note-target-input:focus {
        border: solid #00ffff;
    }
    #note-content {
        height: 22;
        background: #0d0d1a;
        color: #cccccc;
        border: solid #1a1a2e;
        margin-bottom: 1;
    }
    #note-content:focus {
        border: solid #00ffff;
    }
    .edit-btn-row {
        height: 3;
    }
    .edit-btn-row Button {
        height: 3;
        margin-right: 1;
    }
    .notes-status {
        height: 1;
        color: #00ff88;
        margin-top: 1;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._notes: list[dict] = []
        self._selected_id: int | None = None

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ NOTES[/]  "
            "[bright_magenta]Pentest Notes — Persisted across sessions[/]",
            classes="notes-title",
        )

        with Horizontal(classes="notes-layout"):
            # ── Left: notes list ─────────────────────────────────────────────
            with Vertical(classes="notes-list-panel"):
                yield Static("[bold bright_magenta]◈ SAVED NOTES[/]", classes="panel-label")
                table = DataTable(id="notes-table")
                table.add_columns("Title", "Target", "Updated")
                table.cursor_type = "row"
                yield table

                with Horizontal(classes="list-btn-row"):
                    yield Button("➕ New",    id="btn-new-note",    classes="success")
                    yield Button("🗑 Delete", id="btn-delete-note", classes="danger")
                    yield Button("🔄 Refresh", id="btn-refresh-notes")

            # ── Right: note editor ───────────────────────────────────────────
            with Vertical(classes="notes-edit-panel"):
                yield Static("[bold bright_magenta]◈ EDITOR[/]", classes="panel-label")
                yield Static("[dim]Title[/]")
                yield Input(
                    placeholder="Note title...",
                    id="note-title-input",
                )
                yield Static("[dim]Target (optional)[/]")
                yield Input(
                    placeholder="example.com (optional)",
                    id="note-target-input",
                )
                yield Static("[dim]Content[/]")
                yield TextArea(
                    "",
                    id="note-content",
                    language="markdown",
                )
                with Horizontal(classes="edit-btn-row"):
                    yield Button("💾 Save Note", id="btn-save-note", classes="success")
                    yield Button("⊘ Clear",      id="btn-clear-note", classes="danger")

        yield Static("", id="notes-status", classes="notes-status")

    def on_mount(self) -> None:
        self._load_notes()

    def on_show(self) -> None:
        self._load_notes()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-new-note":
            self._new_note()
        elif bid == "btn-save-note":
            self._save_note()
        elif bid == "btn-delete-note":
            self._delete_note()
        elif bid == "btn-refresh-notes":
            self._load_notes()
        elif bid == "btn-clear-note":
            self._clear_editor()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Load selected note into editor"""
        try:
            idx = event.cursor_row
            if 0 <= idx < len(self._notes):
                note = self._notes[idx]
                self._selected_id = note["id"]
                self.query_one("#note-title-input",  Input).value = note.get("title", "")
                self.query_one("#note-target-input", Input).value = note.get("target", "")
                self.query_one("#note-content", TextArea).load_text(note.get("content", ""))
                self._set_status(f"[dim]Loaded: {note.get('title', '')}[/]")
        except Exception:
            pass

    # ─── Actions ─────────────────────────────────────────────────────────────

    def _new_note(self) -> None:
        self._selected_id = None
        self._clear_editor()
        try:
            self.query_one("#note-title-input", Input).focus()
        except Exception:
            pass
        self._set_status("[dim]New note — fill in title and content, then Save[/]")

    @work(exclusive=False)
    async def _save_note(self) -> None:
        title   = self.query_one("#note-title-input",  Input).value.strip()
        target  = self.query_one("#note-target-input", Input).value.strip()
        content = self.query_one("#note-content", TextArea).text

        if not title:
            self._set_status("[bright_red]Title is required[/]")
            return

        try:
            from vexor.core.db import save_note, update_note
            if self._selected_id:
                await update_note(self._selected_id, title, content)
                self._set_status(f"[bright_green]✓ Updated: {title}[/]")
            else:
                note_id = await save_note(title, content, target)
                self._selected_id = note_id
                self._set_status(f"[bright_green]✓ Saved: {title}[/]")
            self._load_notes()
            self.notify(f"Note saved: {title}", severity="information")
        except Exception as e:
            self._set_status(f"[bright_red]Save failed: {e}[/]")

    @work(exclusive=False)
    async def _delete_note(self) -> None:
        if not self._selected_id:
            self._set_status("[bright_yellow]Select a note to delete[/]")
            return
        try:
            from vexor.core.db import delete_note
            await delete_note(self._selected_id)
            self._selected_id = None
            self._clear_editor()
            self._load_notes()
            self._set_status("[bright_yellow]Note deleted[/]")
            self.notify("Note deleted", severity="warning")
        except Exception as e:
            self._set_status(f"[bright_red]Delete failed: {e}[/]")

    @work(exclusive=False)
    async def _load_notes(self) -> None:
        try:
            from vexor.core.db import get_notes, init_db
            await init_db()
            self._notes = await get_notes()
            table = self.query_one("#notes-table", DataTable)
            table.clear()
            if self._notes:
                for note in self._notes:
                    updated = note.get("updated_at", "")[:16].replace("T", " ")
                    table.add_row(
                        note.get("title", "")[:25],
                        note.get("target", "-")[:15] or "-",
                        updated,
                    )
            else:
                table.add_row("No notes yet", "-", "-")
            self._set_status(f"[dim]{len(self._notes)} note(s) loaded[/]")
        except Exception as e:
            self._set_status(f"[bright_red]Load error: {e}[/]")

    def _clear_editor(self) -> None:
        try:
            self.query_one("#note-title-input",  Input).value = ""
            self.query_one("#note-target-input", Input).value = ""
            self.query_one("#note-content", TextArea).load_text("")
        except Exception:
            pass

    def _set_status(self, msg: str) -> None:
        try:
            self.query_one("#notes-status", Static).update(msg)
        except Exception:
            pass
