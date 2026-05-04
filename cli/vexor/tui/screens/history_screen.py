"""
Vexor History Screen — Ctrl+G
View all past scan sessions from SQLite DB.
Select a session → view its findings → generate report → sync to cloud.
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, DataTable, Log
from textual.containers import Horizontal, Container
from textual import work


class HistoryScreen(Widget):

    DEFAULT_CSS = """
    HistoryScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .hist-title    { height: 2; color: #00ffff; text-style: bold; }
    .hist-btn-row  { height: 3; margin-bottom: 1; }
    .hist-btn-row Button { height: 3; margin-right: 1; }
    .hist-sessions { height: 12; border: solid #1a1a2e; margin-bottom: 1; }
    .hist-findings { height: 14; border: solid #00ffff; margin-bottom: 1; }
    .hist-log      { height: 8;  border: solid #1a1a2e; }
    .hist-label    { color: #ff00ff; text-style: bold; height: 2; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ SCAN HISTORY[/]  [dim]All past sessions from local database[/]",
            classes="hist-title",
        )

        with Horizontal(classes="hist-btn-row"):
            yield Button("🔄 Refresh",        id="btn-hist-refresh", classes="success")
            yield Button("📄 Generate Report", id="btn-hist-report")
            yield Button("☁ Sync to Cloud",   id="btn-hist-sync")
            yield Button("🗑 Delete Session",  id="btn-hist-delete",  classes="danger")
            yield Button("⊘ Clear All",       id="btn-hist-clear-all", classes="danger")

        yield Static("[bold bright_magenta]◈ SESSIONS[/]  [dim]Click to load findings[/]", classes="hist-label")
        sessions_table = DataTable(classes="hist-sessions", id="hist-sessions")
        sessions_table.add_columns("ID", "Target", "Type", "Started", "Total", "Crit", "High", "Med")
        sessions_table.cursor_type = "row"
        yield sessions_table

        yield Static("[bold bright_magenta]◈ FINDINGS[/]  [dim]for selected session[/]", classes="hist-label")
        findings_table = DataTable(classes="hist-findings", id="hist-findings")
        findings_table.add_columns("Severity", "Module", "Vulnerability", "Endpoint", "Param")
        findings_table.cursor_type = "row"
        yield findings_table

        yield Static("[bold bright_magenta]◈ LOG[/]", classes="hist-label")
        yield Log(classes="hist-log", id="hist-log")

    def on_mount(self) -> None:
        self._load_sessions()
        self._selected_session_id = None
        self._selected_target = ""

    def on_show(self) -> None:
        self._load_sessions()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-hist-refresh":
            self._load_sessions()
        elif bid == "btn-hist-report":
            self._generate_report()
        elif bid == "btn-hist-sync":
            self._sync_to_cloud()
        elif bid == "btn-hist-delete":
            self._delete_session()
        elif bid == "btn-hist-clear-all":
            self.notify("Delete not implemented yet — use: vexor history", severity="warning")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "hist-sessions":
            self._load_findings_for_row(event.cursor_row)

    @work(exclusive=False)
    async def _load_sessions(self) -> None:
        log = self.query_one("#hist-log", Log)
        try:
            from vexor.core.db import get_recent_sessions, init_db
            await init_db()
            sessions = await get_recent_sessions(limit=50)
            table = self.query_one("#hist-sessions", DataTable)
            table.clear()
            self._sessions = sessions

            if not sessions:
                log.write_line("[!] No sessions found. Run: F3 Scanner → scan a target")
                return

            sev_colors = {"CRITICAL": "bold bright_red", "HIGH": "bold bright_magenta"}
            for s in sessions:
                table.add_row(
                    str(s.get("id", "")),
                    s.get("target", "")[:35],
                    s.get("scan_type", ""),
                    s.get("started_at", "")[:16],
                    str(s.get("total", 0)),
                    f"[bold bright_red]{s.get('critical', 0)}[/]",
                    f"[bold bright_magenta]{s.get('high', 0)}[/]",
                    str(s.get("medium", 0)),
                )
            log.write_line(f"[+] Loaded {len(sessions)} sessions from database")
        except Exception as e:
            log.write_line(f"[!] DB error: {e}")

    @work(exclusive=False)
    async def _load_findings_for_row(self, row_idx: int) -> None:
        log = self.query_one("#hist-log", Log)
        try:
            sessions = getattr(self, "_sessions", [])
            if row_idx >= len(sessions):
                return
            session = sessions[row_idx]
            session_id = session["id"]
            self._selected_session_id = session_id
            self._selected_target = session.get("target", "")

            from vexor.core.db import get_session_findings
            findings = await get_session_findings(session_id)

            table = self.query_one("#hist-findings", DataTable)
            table.clear()

            if not findings:
                log.write_line(f"[!] Session {session_id}: no findings stored")
                return

            sev_colors = {
                "CRITICAL": "bold bright_red", "HIGH": "bold bright_magenta",
                "MEDIUM": "bright_yellow", "LOW": "bright_blue", "INFO": "dim white",
            }
            for f in findings:
                color = sev_colors.get(f.get("severity", "INFO"), "white")
                table.add_row(
                    f"[{color}]{f.get('severity', 'INFO')}[/]",
                    f.get("module", "")[:14],
                    f.get("vuln", "")[:35],
                    f.get("endpoint", "")[:40],
                    f.get("param", "") or "-",
                )
            log.write_line(f"[+] Session #{session_id} — {len(findings)} findings for: {self._selected_target}")
        except Exception as e:
            log.write_line(f"[!] Error loading findings: {e}")

    @work(exclusive=False)
    async def _generate_report(self) -> None:
        log = self.query_one("#hist-log", Log)
        sid = getattr(self, "_selected_session_id", None)
        if not sid:
            self.notify("Select a session first", severity="warning")
            return
        log.write_line(f"[*] Generating report for session #{sid}...")
        try:
            from vexor.core.db import get_session_findings
            from vexor.config import REPORTS_DIR
            import datetime, json
            findings = await get_session_findings(sid)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = REPORTS_DIR / f"vexor_session{sid}_{ts}.json"
            out.write_text(json.dumps(findings, indent=2, default=str))
            log.write_line(f"[+] Report saved: {out}")
            self.notify(f"Report: {out.name}", severity="information")

            # Try HTML if available
            try:
                from vexor.reports.html import HTMLReport
                html_out = REPORTS_DIR / f"vexor_session{sid}_{ts}.html"
                report = HTMLReport(title=f"Vexor — Session #{sid}")
                await report.generate(str(html_out), findings=findings, target=self._selected_target)
                log.write_line(f"[+] HTML report: {html_out}")
            except Exception:
                pass
        except Exception as e:
            log.write_line(f"[!] Report error: {e}")

    @work(exclusive=False)
    async def _sync_to_cloud(self) -> None:
        log = self.query_one("#hist-log", Log)
        sid = getattr(self, "_selected_session_id", None)
        if not sid:
            self.notify("Select a session first", severity="warning")
            return
        log.write_line(f"[*] Syncing session #{sid} to cloud...")
        try:
            from vexor.core.db import get_session_findings
            from vexor.config import API_BASE, TOKEN_FILE
            import json, httpx

            if not TOKEN_FILE.exists():
                log.write_line("[!] Not logged in — open Config screen (backtick key)")
                self.notify("Login required — press ` to open Config", severity="error")
                return

            token = json.loads(TOKEN_FILE.read_text()).get("access_token", "")
            findings = await get_session_findings(sid)

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{API_BASE}/sync/push",
                    json={"target": self._selected_target, "findings": findings},
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    log.write_line(f"[+] Synced! Cloud ID: {data.get('scan_id')} — {len(findings)} findings")
                    self.notify(f"Synced {len(findings)} findings to cloud", severity="information")
                else:
                    log.write_line(f"[!] Sync failed: {resp.status_code}")
        except Exception as e:
            log.write_line(f"[!] Sync error: {e}")

    @work(exclusive=False)
    async def _delete_session(self) -> None:
        log = self.query_one("#hist-log", Log)
        sid = getattr(self, "_selected_session_id", None)
        if not sid:
            self.notify("Select a session first", severity="warning")
            return
        try:
            from vexor.core.db import DB_PATH
            import aiosqlite
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute("DELETE FROM findings WHERE session_id=?", (sid,))
                await db.execute("DELETE FROM scan_sessions WHERE id=?", (sid,))
                await db.commit()
            log.write_line(f"[+] Session #{sid} deleted")
            self.notify(f"Session #{sid} deleted", severity="warning")
            self._selected_session_id = None
            self._load_sessions()
            self.query_one("#hist-findings", DataTable).clear()
        except Exception as e:
            log.write_line(f"[!] Delete error: {e}")
