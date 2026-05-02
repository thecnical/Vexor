"""
Vexor Config Screen — API keys, backend URL, scan settings
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, Label
from textual.containers import Horizontal, Vertical
from textual import work
import json


class ConfigScreen(Widget):

    DEFAULT_CSS = """
    ConfigScreen {
        background: #0a0a0f;
        height: auto;
        overflow-y: auto;
        padding: 1 2;
    }
    .config-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
        margin-bottom: 1;
    }
    .config-section {
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .config-section-title {
        height: 2;
        color: #ff00ff;
        text-style: bold;
    }
    .config-label {
        height: 1;
        color: #888888;
        margin-top: 1;
    }
    .config-input {
        height: 3;
        background: #1a1a2e;
        color: #ffffff;
        border: solid #333355;
        margin-bottom: 1;
    }
    .config-input:focus {
        border: solid #00ffff;
    }
    .config-btn-row {
        height: 3;
        margin-top: 1;
    }
    .config-status {
        height: 2;
        color: #00ff88;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ CONFIG[/]  "
            "[bright_magenta]Vexor Settings & API Keys[/]",
            classes="config-title",
        )

        # ── Backend ───────────────────────────────────────────────────────────
        with Vertical(classes="config-section"):
            yield Static("[bold bright_magenta]Backend Connection[/]", classes="config-section-title")
            yield Static("[dim]Backend URL (default: Render deployment)[/]", classes="config-label")
            yield Input(
                placeholder="https://vexor-backend-fnow.onrender.com",
                id="cfg-backend-url",
                classes="config-input",
            )
            with Horizontal(classes="config-btn-row"):
                yield Button("🔗 Test Connection", id="btn-test-conn")
                yield Button("💾 Save", id="btn-save-backend", classes="success")

        # ── Auth ──────────────────────────────────────────────────────────────
        with Vertical(classes="config-section"):
            yield Static("[bold bright_magenta]Authentication[/]", classes="config-section-title")
            yield Static("[dim]Email[/]", classes="config-label")
            yield Input(placeholder="your@email.com", id="cfg-email", classes="config-input")
            yield Static("[dim]Password[/]", classes="config-label")
            yield Input(placeholder="••••••••", id="cfg-password",
                        classes="config-input", password=True)
            with Horizontal(classes="config-btn-row"):
                yield Button("🔑 Login", id="btn-login", classes="success")
                yield Button("🚪 Logout", id="btn-logout", classes="danger")

        # ── Scan defaults ─────────────────────────────────────────────────────
        with Vertical(classes="config-section"):
            yield Static("[bold bright_magenta]Scan Defaults[/]", classes="config-section-title")
            yield Static("[dim]Timeout (seconds)[/]", classes="config-label")
            yield Input(placeholder="30", id="cfg-timeout", classes="config-input")
            yield Static("[dim]Threads[/]", classes="config-label")
            yield Input(placeholder="10", id="cfg-threads", classes="config-input")
            with Horizontal(classes="config-btn-row"):
                yield Button("💾 Save Defaults", id="btn-save-scan", classes="success")

        yield Static("", id="cfg-status", classes="config-status")

    def on_mount(self) -> None:
        self._load_config()

    def _load_config(self) -> None:
        try:
            from vexor.config import CONFIG_FILE, BACKEND_URL
            self.query_one("#cfg-backend-url", Input).value = BACKEND_URL
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text())
                if data.get("timeout"):
                    self.query_one("#cfg-timeout", Input).value = str(data["timeout"])
                if data.get("threads"):
                    self.query_one("#cfg-threads", Input).value = str(data["threads"])
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-test-conn":
            self._test_connection()
        elif bid == "btn-save-backend":
            self._save_backend()
        elif bid == "btn-login":
            self._do_login()
        elif bid == "btn-logout":
            self._do_logout()
        elif bid == "btn-save-scan":
            self._save_scan_defaults()

    def _set_status(self, msg: str) -> None:
        try:
            self.query_one("#cfg-status", Static).update(msg)
        except Exception:
            pass

    @work(exclusive=False)
    async def _test_connection(self) -> None:
        self._set_status("[dim]Testing connection...[/]")
        try:
            from vexor.ai.client import AIClient
            client = AIClient()
            ok = await client.health_check()
            if ok:
                self._set_status("[bright_green]✓ Backend connected[/]")
                self.notify("Backend connected!", severity="information")
            else:
                self._set_status("[bright_red]✗ Backend unreachable[/]")
                self.notify("Backend unreachable", severity="warning")
        except Exception as e:
            self._set_status(f"[bright_red]Error: {e}[/]")

    def _save_backend(self) -> None:
        try:
            url = self.query_one("#cfg-backend-url", Input).value.strip()
            if url:
                from vexor.config import CONFIG_FILE
                data = {}
                if CONFIG_FILE.exists():
                    data = json.loads(CONFIG_FILE.read_text())
                data["backend_url"] = url
                CONFIG_FILE.write_text(json.dumps(data, indent=2))
                self._set_status("[bright_green]✓ Backend URL saved (restart to apply)[/]")
        except Exception as e:
            self._set_status(f"[bright_red]Save failed: {e}[/]")

    @work(exclusive=False)
    async def _do_login(self) -> None:
        email    = self.query_one("#cfg-email",    Input).value.strip()
        password = self.query_one("#cfg-password", Input).value.strip()
        if not email or not password:
            self._set_status("[bright_red]Enter email and password[/]")
            return
        self._set_status("[dim]Logging in...[/]")
        try:
            import httpx, json as _json
            from vexor.config import API_BASE, TOKEN_FILE
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{API_BASE}/auth/login",
                    json={"email": email, "password": password},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    TOKEN_FILE.write_text(_json.dumps({"access_token": data["access_token"]}))
                    self._set_status("[bright_green]✓ Logged in successfully![/]")
                    self.notify("Logged in!", severity="information")
                else:
                    self._set_status(f"[bright_red]Login failed: {resp.json().get('detail', 'error')}[/]")
        except Exception as e:
            self._set_status(f"[bright_red]Error: {e}[/]")

    def _do_logout(self) -> None:
        try:
            from vexor.config import TOKEN_FILE
            if TOKEN_FILE.exists():
                TOKEN_FILE.unlink()
            self._set_status("[bright_yellow]Logged out[/]")
            self.notify("Logged out", severity="warning")
        except Exception as e:
            self._set_status(f"[bright_red]Error: {e}[/]")

    def _save_scan_defaults(self) -> None:
        try:
            from vexor.config import CONFIG_FILE
            data = {}
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text())
            t = self.query_one("#cfg-timeout", Input).value.strip()
            th = self.query_one("#cfg-threads", Input).value.strip()
            if t.isdigit():
                data["timeout"] = int(t)
            if th.isdigit():
                data["threads"] = int(th)
            CONFIG_FILE.write_text(json.dumps(data, indent=2))
            self._set_status("[bright_green]✓ Scan defaults saved[/]")
        except Exception as e:
            self._set_status(f"[bright_red]Save failed: {e}[/]")
