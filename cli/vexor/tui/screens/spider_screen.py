"""
Vexor Spider Screen — F11
Web crawler + JS endpoint discovery, right inside the TUI.
No need for CLI — fully interactive.
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, DataTable, Log, Checkbox
from textual.containers import Horizontal, Vertical, Container
from textual import work


class SpiderScreen(Widget):

    DEFAULT_CSS = """
    SpiderScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
    }
    .spider-title  { height: 2; color: #00ffff; text-style: bold; }
    .spider-ctrl   { border: solid #1a1a2e; padding: 1; margin-bottom: 1; height: auto; }
    .spider-opts   { height: 3; margin-bottom: 1; }
    .spider-opts Input  { margin-right: 1; }
    .spider-btn-row     { height: 3; margin-bottom: 1; }
    .spider-btn-row Button { height: 3; margin-right: 1; }
    .spider-table  { height: 14; border: solid #1a1a2e; margin-bottom: 1; }
    .spider-log    { height: 10; border: solid #1a1a2e; }
    .spider-stats  { height: 2; color: #00ff88; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ SPIDER[/]  [dim]JS-Aware Web Crawler · Discover Endpoints, Forms & APIs[/]",
            classes="spider-title",
        )

        with Container(classes="spider-ctrl"):
            yield Static("[bold bright_magenta]Target[/]")
            yield Input(placeholder="https://target.com", id="spider-target")

            with Horizontal(classes="spider-opts"):
                yield Input(value="5",   id="spider-depth",    placeholder="Depth")
                yield Input(value="500", id="spider-max",      placeholder="Max URLs")
                yield Input(value="10",  id="spider-threads",  placeholder="Threads")

            with Horizontal(classes="spider-btn-row"):
                yield Button("▶ Start Crawl",    id="btn-spider-start",  classes="success")
                yield Button("■ Stop",           id="btn-spider-stop",   classes="danger")
                yield Button("⊘ Clear",          id="btn-spider-clear")
                yield Button("→ Scanner",        id="btn-spider-to-scan")
                yield Checkbox("Respect robots.txt", id="chk-robots", value=True)
                yield Checkbox("Extract JS APIs",    id="chk-js",     value=True)

            yield Static("", id="spider-stats", classes="spider-stats")

        yield Static("[bold bright_magenta]◈ DISCOVERED URLS[/]")
        table = DataTable(classes="spider-table", id="spider-table")
        table.add_columns("Status", "Method", "Depth", "URL", "Type")
        table.cursor_type = "row"
        yield table

        yield Static("[bold bright_magenta]◈ LOG[/]")
        yield Log(classes="spider-log", id="spider-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-spider-start":
            self._start_crawl()
        elif bid == "btn-spider-stop":
            self._stop_flag = True
            self.notify("Crawl stopped", severity="warning")
        elif bid == "btn-spider-clear":
            self._clear()
        elif bid == "btn-spider-to-scan":
            self._send_to_scanner()

    def _start_crawl(self) -> None:
        target = self.query_one("#spider-target", Input).value.strip()
        if not target:
            self.notify("Enter a target URL first", severity="error")
            return
        if not target.startswith("http"):
            target = f"https://{target}"
            self.query_one("#spider-target", Input).value = target
        self._stop_flag = False
        self._crawled_urls = []
        self._run_crawl(target)

    @work(exclusive=True)
    async def _run_crawl(self, target: str) -> None:
        log   = self.query_one("#spider-log",   Log)
        table = self.query_one("#spider-table", DataTable)

        try:
            depth   = int(self.query_one("#spider-depth",   Input).value or "5")
            max_u   = int(self.query_one("#spider-max",     Input).value or "500")
            threads = int(self.query_one("#spider-threads", Input).value or "10")
            robots  = self.query_one("#chk-robots",  Checkbox).value
            js      = self.query_one("#chk-js",      Checkbox).value
        except Exception:
            depth, max_u, threads, robots, js = 5, 500, 10, True, True

        log.write_line(f"[*] Starting crawl: {target}")
        log.write_line(f"[*] Depth:{depth}  Max:{max_u}  Threads:{threads}")

        from vexor.core.spider import Spider, SpiderConfig
        cfg = SpiderConfig(
            target=target,
            max_depth=depth,
            max_urls=max_u,
            threads=threads,
            respect_robots=robots,
            extract_js_endpoints=js,
        )

        def on_url(crawled):
            if self._stop_flag:
                return
            try:
                color = "bright_green" if crawled.status_code == 200 else \
                        "bright_yellow" if crawled.status_code < 400 else "bright_red"
                url_type = "📋 Form" if crawled.params else \
                           "🔌 API" if "/api/" in crawled.url else \
                           "📄 Page"
                table.add_row(
                    f"[{color}]{crawled.status_code}[/]",
                    crawled.method,
                    str(crawled.depth),
                    crawled.url[:70],
                    url_type,
                )
                self._crawled_urls.append(crawled)
                if len(self._crawled_urls) % 25 == 0:
                    interesting = sum(1 for u in self._crawled_urls if u.interesting)
                    self.query_one("#spider-stats", Static).update(
                        f"[bright_cyan]Crawled: {len(self._crawled_urls)}[/]  "
                        f"[bright_yellow]Injectable: {interesting}[/]  "
                        f"[dim]Forms: {len(sp.forms)}[/]"
                    )
            except Exception:
                pass

        sp = Spider(config=cfg, on_url=on_url)
        # Patch stop flag into spider
        import asyncio

        async def _patched_crawl():
            from vexor.core.spider import Spider as _S
            results = await sp.crawl()
            return results

        try:
            results = await _patched_crawl()
            interesting = sp.get_interesting_urls()
            forms = sp.forms
            log.write_line(f"[+] Done — {len(results)} URLs  |  Injectable: {len(interesting)}  |  Forms: {len(forms)}")
            self.query_one("#spider-stats", Static).update(
                f"[bright_cyan]Total: {len(results)}[/]  "
                f"[bright_yellow]Injectable: {len(interesting)}[/]  "
                f"[bright_magenta]Forms: {len(forms)}[/]"
            )
            self.notify(f"Crawl done: {len(results)} URLs, {len(interesting)} injectable", severity="information")
            # Store for sending to scanner
            self._interesting = interesting
        except Exception as e:
            log.write_line(f"[!] Crawl error: {e}")
            self.notify(f"Error: {e}", severity="error")

    def _send_to_scanner(self) -> None:
        """Pre-fill the Scanner screen with an interesting URL from spider results."""
        try:
            interesting = getattr(self, "_interesting", [])
            if not interesting:
                self.notify("No injectable URLs found — run a crawl first", severity="warning")
                return
            # Send first interesting URL to scanner
            url = interesting[0].url
            try:
                from vexor.core.state import state
                state.scan_target = url
            except Exception:
                pass
            self.app.action_show_screen("scanner")
            self.notify(f"Sent to Scanner: {url[:50]}", severity="information")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def _clear(self) -> None:
        try:
            self.query_one("#spider-table", DataTable).clear()
            self.query_one("#spider-log", Log).clear()
            self.query_one("#spider-stats", Static).update("")
            self._crawled_urls = []
        except Exception:
            pass
