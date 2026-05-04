"""
Vexor — AI-Powered CLI Security Toolkit
Entry Point
Created by Chandan Pandey (Technical)
"""
import typer
import asyncio
import httpx
from typing import Optional
from pathlib import Path
from rich.console import Console

from vexor.config import (
    TOOL_VERSION, TOOL_AUTHOR,
    TOOL_TAGLINE, TOOL_DESCRIPTION, ensure_dirs
)

app = typer.Typer(
    name="vexor",
    help=f"Vexor v{TOOL_VERSION} — {TOOL_DESCRIPTION}",
    rich_markup_mode="rich",
    no_args_is_help=False,
)
console = Console()

BANNER = f"""[bold bright_cyan]
██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝[/]
[bold bright_magenta]  AI-Powered CLI Security Toolkit  v{TOOL_VERSION}[/]
[dim]  {TOOL_TAGLINE}[/]
[dim]  Created by {TOOL_AUTHOR}[/]
[dim]  Intelligence Engine · 26 Modules · 6-Phase OSINT · AI-Powered[/]
"""


def show_banner():
    console.print(BANNER)


# ─── Main callback ──────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
    offline: bool = typer.Option(False, "--offline", help="Run in offline mode"),
):
    """
    [bold bright_cyan]Vexor[/] — AI-Powered CLI Security Toolkit

    [dim]Run without arguments to launch the TUI dashboard.[/]
    """
    ensure_dirs()

    if version:
        console.print(f"[bright_cyan]Vexor[/] v{TOOL_VERSION} by {TOOL_AUTHOR}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        show_banner()
        launch_tui(offline=offline)


def launch_tui(offline: bool = False):
    """Launch the Textual TUI"""
    try:
        from vexor.tui.app import VexorApp
        app_instance = VexorApp()
        app_instance.is_offline = offline
        app_instance.run()
    except ImportError as e:
        console.print(f"[bright_red]Error:[/] Missing dependency: {e}")
        console.print("[dim]Run: pip install -e cli/[/]")
        raise typer.Exit(1)


# ─── scan ───────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Specific module"),
    full: bool = typer.Option(False, "--full", help="Run all modules"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    format: str = typer.Option("html", "--format", "-f", help="html/pdf/json"),
    offline: bool = typer.Option(False, "--offline", help="Offline mode"),
    threads: int = typer.Option(10, "--threads", "-t", help="Threads"),
):
    """[bold]Scan a target for vulnerabilities[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ SCANNER[/]  Target: [bright_yellow]{target}[/]")
    asyncio.run(_run_scan(
        target=target, module=module, full=full,
        output=output, fmt=format, offline=offline, threads=threads,
    ))


async def _run_scan(
    target: str, module: Optional[str], full: bool,
    output: Optional[str], fmt: str, offline: bool, threads: int,
):
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

    if module:
        modules_to_run = [module]
    elif full:
        modules_to_run = [
            # Core web vulns
            "sqli", "xss", "csrf", "idor", "ssrf", "xxe", "lfi",
            # Auth & tokens
            "jwt_analyzer", "auth_bypass",
            # Network & SSL
            "ssl_analyzer", "port_scanner",
            # Headers & config
            "headers", "cors",
            # Advanced
            "websocket", "api_tester", "graphql",
            "ssti", "http_smuggling",
            # Recon
            "fingerprinter", "subdomain", "dirbuster",
            "cve_lookup", "wayback", "github_dork",
            # Runtime
            "rate_limit", "open_redirect", "session_analyzer",
            "sensitive_data", "file_upload",
            # OOB
            "osint", "blind_scanner",
        ]
    else:
        modules_to_run = ["sqli", "xss", "headers", "cors", "ssl_analyzer"]

    # FIX 2: Auto-start callback server for blind XSS/SSRF/OOB detection
    from vexor.core.callback_server import get_callback_server as _get_cb
    _cb_srv = _get_cb()
    if not _cb_srv.is_running():
        try:
            await _cb_srv.start()
        except Exception:
            pass  # Port may be in use, continue without OOB

    all_findings = []
    import time as _time
    _scan_start = _time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bright_cyan]{task.description}[/]"),
        BarColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/]"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(modules_to_run))
        for mod_name in modules_to_run:
            progress.update(task, description=f"Running [bright_magenta]{mod_name}[/]...")
            try:
                import importlib
                mod = importlib.import_module(f"vexor.modules.{mod_name}")
                scanner = mod.Scanner(target=target, threads=threads, offline=offline)
                findings = await scanner.scan()
                all_findings.extend(findings)
            except ImportError as ie:
                console.print(f"[dim]  {mod_name}: import error — {ie}[/]")
            except Exception as e:
                console.print(f"[dim]  {mod_name}: {str(e)[:120]}[/]")
            progress.advance(task)

    _scan_duration = f"{_time.time() - _scan_start:.1f}s"
    _display_findings(all_findings)

    # BUG-008 FIX: Persist findings to local DB
    if all_findings:
        try:
            from vexor.core.db import create_session, finish_session, save_finding
            from collections import Counter
            session_id = await create_session(target, scan_type=module or ("full" if full else "quick"))
            for f in all_findings:
                await save_finding(session_id, f)
            counts = Counter(f.severity for f in all_findings)
            counts["total"] = len(all_findings)
            await finish_session(session_id, dict(counts))
            console.print(f"[dim]  Saved {len(all_findings)} findings to local DB (session #{session_id})[/]")
        except Exception as db_err:
            console.print(f"[dim]  DB save skipped: {db_err}[/]")

    if output or all_findings:
        await _generate_report(all_findings, output, fmt, target, duration=_scan_duration)


def _display_findings(findings: list):
    from rich.table import Table
    from collections import Counter

    if not findings:
        console.print("\n[bright_green]✓ No vulnerabilities found![/]")
        return

    table = Table(
        title=f"[bold bright_cyan]VEXOR FINDINGS — {len(findings)} Issues[/]",
        show_header=True,
        header_style="bold bright_magenta",
        border_style="bright_cyan",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", width=12)
    table.add_column("Vulnerability", width=30)
    table.add_column("Endpoint", width=40)
    table.add_column("Parameter", width=15)

    severity_colors = {
        "CRITICAL": "bold bright_red",
        "HIGH": "bold bright_magenta",
        "MEDIUM": "bright_yellow",
        "LOW": "bright_blue",
        "INFO": "dim white",
    }

    for f in findings:
        color = severity_colors.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/]",
            f.module, f.vuln, f.endpoint[:40], f.param or "-",
        )

    console.print(table)
    counts = Counter(f.severity for f in findings)
    console.print(
        f"\n[dim]Summary:[/] "
        f"[bold bright_red]Critical: {counts.get('CRITICAL', 0)}[/]  "
        f"[bold bright_magenta]High: {counts.get('HIGH', 0)}[/]  "
        f"[bright_yellow]Medium: {counts.get('MEDIUM', 0)}[/]  "
        f"[bright_blue]Low: {counts.get('LOW', 0)}[/]  "
        f"[dim]Info: {counts.get('INFO', 0)}[/]"
    )


async def _generate_report(findings: list, output: Optional[str], fmt: str, target: str, duration: str = "N/A"):
    from vexor.config import REPORTS_DIR
    import datetime

    if not output:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output = str(REPORTS_DIR / f"vexor_report_{ts}.{fmt}")

    console.print(f"\n[bright_cyan]◈ Generating {fmt.upper()} report...[/]")
    try:
        if fmt == "html":
            from vexor.reports.html import HTMLReport
            report = HTMLReport(title=f"Vexor Report — {target}")
            await report.generate(output, findings=[f.to_dict() for f in findings], target=target, duration=duration)
        elif fmt == "pdf":
            from vexor.reports.pdf import PDFReport
            report = PDFReport(title=f"Vexor Report — {target}")
            await report.generate(output, findings=[f.to_dict() for f in findings], target=target, duration=duration)
        elif fmt == "json":
            import json
            with open(output, 'w') as fp:
                json.dump([f.to_dict() for f in findings], fp, indent=2)
        console.print(f"[bright_green]✓ Report saved:[/] {output}")
    except Exception as e:
        console.print(f"[bright_red]Report error:[/] {str(e)}")


# ─── proxy ──────────────────────────────────────────────────

@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", help="Proxy host"),
    port: int = typer.Option(8080, "--port", "-p", help="Proxy port"),
    mitm: bool = typer.Option(False, "--mitm", help="Enable HTTPS interception (MITM)"),
    intercept: bool = typer.Option(False, "--intercept", "-i", help="Hold requests for manual review"),
    passive: bool = typer.Option(False, "--passive", help="Run passive scanner on all traffic"),
):
    """[bold]Start HTTP/HTTPS proxy interceptor[/]"""
    show_banner()
    mode = "MITM" if mitm else "Transparent"
    console.print(f"[bright_cyan]◈ PROXY[/]  [{mode}] Starting on [bright_yellow]{host}:{port}[/]")
    if mitm:
        console.print(f"[bright_yellow]  HTTPS interception active. Install CA cert:[/]")
        try:
            from vexor.core.mitm_proxy import install_ca_instructions, CA_CERT
            console.print(f"[dim]  Cert: {CA_CERT}[/]")
            console.print(f"[dim]  {install_ca_instructions()}[/]")
        except Exception:
            pass
    if intercept:
        console.print("[bright_magenta]  Intercept ON — use TUI to forward/drop requests[/]")
    console.print(f"[dim]Configure browser proxy: {host}:{port} | Ctrl+C to stop[/]\n")
    asyncio.run(_run_proxy(host, port, mitm=mitm, intercept=intercept, passive=passive))


async def _run_proxy(host: str, port: int, mitm: bool = False, intercept: bool = False, passive: bool = False):
    passive_scanner = None
    if passive:
        from vexor.core.spider import PassiveScanner
        passive_scanner = PassiveScanner(
            on_finding=lambda f: console.print(
                f"[bright_yellow][PASSIVE][/] [{f.get('severity','INFO')}] {f.get('vuln','')} — {f.get('endpoint','')[:50]}"
            )
        )

    def on_request(data: dict):
        console.print(
            f"[dim]{data.get('id', ''):<5}[/]  "
            f"[bright_cyan]{data.get('method', 'GET'):<6}[/]  "
            f"[white]{data.get('host', ''):<30}[/]  "
            f"[dim]{data.get('path', '/')[:50]}[/]  "
            f"[bright_green]{data.get('status', '')}[/]"
        )

    def on_response(req_data):
        if passive_scanner:
            passive_scanner.analyze(req_data)

    if mitm:
        from vexor.core.mitm_proxy import VexorMITMProxy
        proxy_instance = VexorMITMProxy(host=host, port=port, on_request=on_request, on_response=on_response)
    else:
        from vexor.core.proxy import VexorProxy
        proxy_instance = VexorProxy(host=host, port=port, on_request=on_request)

    if intercept:
        proxy_instance.intercept_enabled = True

    try:
        await proxy_instance.start()
        await asyncio.sleep(3600 * 24)   # run until Ctrl+C
    except KeyboardInterrupt:
        console.print("\n[bright_yellow]Proxy stopped.[/]")
    finally:
        if hasattr(proxy_instance, 'stop'):
            await proxy_instance.stop()


# ─── auth ───────────────────────────────────────────────────

@app.command()
def auth(
    action: str = typer.Argument(..., help="login / logout / status"),
    email: Optional[str] = typer.Option(None, "--email", "-e"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
):
    """[bold]Authentication — login / logout / status[/]"""
    show_banner()
    asyncio.run(_handle_auth(action, email, password))


async def _handle_auth(action: str, email: Optional[str], password: Optional[str]):
    import json

    if action == "login":
        if not email:
            email = typer.prompt("Email")
        if not password:
            password = typer.prompt("Password", hide_input=True)
        try:
            from vexor.config import API_BASE, TOKEN_FILE
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{API_BASE}/auth/login",
                    json={"email": email, "password": password}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    TOKEN_FILE.write_text(json.dumps({"access_token": data["access_token"]}))
                    console.print("[bright_green]✓ Logged in successfully![/]")
                else:
                    console.print(f"[bright_red]Login failed:[/] {resp.json().get('detail', 'Unknown error')}")
        except Exception as e:
            console.print(f"[bright_red]Connection error:[/] {str(e)}")

    elif action == "logout":
        from vexor.config import TOKEN_FILE
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()
        console.print("[bright_yellow]Logged out.[/]")

    elif action == "status":
        from vexor.config import TOKEN_FILE
        if TOKEN_FILE.exists():
            console.print("[bright_green]✓ Logged in[/]")
        else:
            console.print("[bright_red]Not logged in[/]  Run: vexor auth login")


# ─── update ─────────────────────────────────────────────────

@app.command()
def update():
    """[bold]Update Vexor to latest version from GitHub[/]"""
    show_banner()
    console.print("[bright_cyan]◈ UPDATER[/]  Checking for updates...")

    import subprocess
    import sys

    try:
        import vexor as _vexor_pkg
        vexor_file = Path(_vexor_pkg.__file__)

        # Walk up to find .git directory
        repo_path = None
        for parent in [vexor_file.parent, *vexor_file.parents]:
            if (parent / ".git").exists():
                repo_path = parent
                break

        if repo_path:
            console.print(f"[dim]  Repo: {repo_path}[/]")
            console.print("[bright_cyan]  Pulling latest changes...[/]")

            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=str(repo_path), capture_output=True, text=True
            )
            if result.returncode == 0:
                console.print(f"[bright_green]  ✓ {result.stdout.strip() or 'Already up to date'}[/]")
            else:
                console.print(f"[bright_yellow]  ! {result.stderr.strip()}[/]")

            # Reinstall with --break-system-packages if needed
            cli_path = repo_path / "cli"
            if not cli_path.exists():
                cli_path = repo_path

            pip_flags = []
            help_check = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--help"],
                capture_output=True, text=True
            )
            if "break-system-packages" in help_check.stdout:
                pip_flags = ["--break-system-packages"]

            console.print("[bright_cyan]  Reinstalling...[/]")
            result2 = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", ".", "--quiet"] + pip_flags,
                cwd=str(cli_path), capture_output=True, text=True
            )
            if result2.returncode == 0:
                console.print("[bright_green]  ✓ Vexor updated! Restart to apply.[/]")
            else:
                console.print(f"[bright_red]  ✗ Reinstall failed: {result2.stderr[:150]}[/]")
        else:
            # No git repo found — clone fresh
            console.print("[bright_yellow]  ! Git repo not found. Cloning fresh...[/]")
            clone_path = Path.home() / "Vexor"
            if clone_path.exists():
                subprocess.run(["git", "pull"], cwd=str(clone_path))
            else:
                subprocess.run([
                    "git", "clone",
                    "https://github.com/thecnical/Vexor",
                    str(clone_path)
                ])
            console.print(f"[bright_green]  ✓ Cloned to {clone_path}[/]")
            console.print(f"[dim]  Run: cd {clone_path} && ./install.sh[/]")

    except Exception as e:
        console.print(f"[bright_red]  Update error: {str(e)}[/]")
        console.print("[dim]  Manual: cd ~/Vexor && git pull && ./install.sh[/]")


# ─── osint ──────────────────────────────────────────────────

@app.command()
def osint(
    target: str = typer.Argument(..., help="Domain or IP to investigate"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    fmt: str = typer.Option("html", "--format", "-f", help="html/json"),
):
    """[bold]Run 6-phase OSINT investigation on a target[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ OSINT[/]  Target: [bright_yellow]{target}[/]")
    asyncio.run(_run_osint(target, output, fmt))


async def _run_osint(target: str, output: Optional[str], fmt: str):
    try:
        from vexor.modules.osint import Scanner
        scanner = Scanner(target=target)
        findings = await scanner.scan()
        _display_findings(findings)
        if findings:
            await _generate_report(findings, output, fmt, target)
    except Exception as e:
        console.print(f"[bright_red]OSINT error:[/] {e}")


# ─── spider ─────────────────────────────────────────────────

@app.command()
def spider(
    target: str = typer.Argument(..., help="Target URL to crawl"),
    depth: int = typer.Option(5, "--depth", "-d", help="Max crawl depth"),
    max_urls: int = typer.Option(500, "--max", help="Max URLs to crawl"),
    threads: int = typer.Option(10, "--threads", "-t"),
):
    """[bold]Crawl target — discover all endpoints, forms, JS APIs[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ SPIDER[/]  Target: [bright_yellow]{target}[/]")
    asyncio.run(_run_spider(target, depth, max_urls, threads))


async def _run_spider(target: str, depth: int, max_urls: int, threads: int):
    from vexor.core.spider import Spider, SpiderConfig
    cfg = SpiderConfig(target=target, max_depth=depth, max_urls=max_urls, threads=threads)

    def on_url(crawled):
        color = "bright_green" if crawled.status_code == 200 else "bright_yellow"
        console.print(f"[{color}]{crawled.status_code}[/]  {crawled.method:<6}  {crawled.url[:80]}")

    sp = Spider(config=cfg, on_url=on_url)
    results = await sp.crawl()
    interesting = sp.get_interesting_urls()
    console.print(f"\n[bright_cyan]Crawled:[/] {len(results)} URLs  |  [bright_yellow]Injectable:[/] {len(interesting)}  |  [dim]Forms:[/] {len(sp.forms)}")


# ─── intruder ────────────────────────────────────────────────

@app.command()
def intruder(
    host: str = typer.Argument(..., help="Target host (e.g. example.com)"),
    port: int = typer.Option(80, "--port", "-p"),
    https: bool = typer.Option(False, "--https"),
    attack: str = typer.Option("sniper", "--attack", "-a", help="sniper/battering_ram/pitchfork/cluster_bomb"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Path to wordlist file"),
    threads: int = typer.Option(10, "--threads", "-t"),
):
    """[bold]Fuzz a request with Sniper/BatteringRam/Pitchfork/ClusterBomb[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ INTRUDER[/]  {host}:{port}  Attack: [bright_yellow]{attack}[/]")
    console.print("[dim]Paste raw HTTP request (with §markers§), then press Ctrl+D:[/]")
    import sys
    raw = sys.stdin.read()
    if not raw.strip():
        console.print("[bright_red]No request provided.[/]")
        raise typer.Exit(1)
    asyncio.run(_run_intruder(host, port, https, attack, raw, wordlist, threads))


async def _run_intruder(host, port, https, attack, raw, wordlist_path, threads):
    from vexor.core.intruder import Intruder, IntruderConfig
    words = ["FUZZ"]
    if wordlist_path:
        try:
            words = Path(wordlist_path).read_text().splitlines()
        except Exception:
            pass

    def on_result(r):
        flag = "[bright_red]★[/]" if r.is_interesting else " "
        console.print(f"{flag} [{r.status_code}]  {r.response_length:>8}B  {r.elapsed_ms:>7.0f}ms  {str(r.payload)[:40]}")

    cfg = IntruderConfig(host=host, port=port, use_https=https, raw_request=raw,
                         attack_type=attack, wordlists=[words], threads=threads)
    intr = Intruder(on_result=on_result)
    results = await intr.run(cfg)
    interesting = [r for r in results if r.is_interesting]
    console.print(f"\n[bright_cyan]Total:[/] {len(results)}  |  [bright_yellow]Interesting:[/] {len(interesting)}")


# ─── report ─────────────────────────────────────────────────

@app.command()
def report(
    format: str = typer.Option("html", "--format", "-f", help="html/pdf/json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path"),
    session: Optional[int] = typer.Option(None, "--session", "-s", help="Session ID from DB"),
    last: bool = typer.Option(False, "--last", help="Use findings from last scan"),
):
    """[bold]Generate security report from last scan or a DB session[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ REPORT[/]  Format: [bright_yellow]{format}[/]")
    asyncio.run(_report_from_db(format, output, session, last))


async def _report_from_db(fmt: str, output: Optional[str], session_id: Optional[int], last: bool):
    from vexor.core.db import get_session_findings, get_recent_sessions

    if session_id:
        findings_dicts = await get_session_findings(session_id)
        target = f"session-{session_id}"
    elif last:
        sessions = await get_recent_sessions(limit=1)
        if not sessions:
            console.print("[bright_red]No sessions found in DB. Run a scan first.[/]")
            return
        session_id = sessions[0]["id"]
        target = sessions[0]["target"]
        findings_dicts = await get_session_findings(session_id)
    else:
        console.print("[dim]No findings to report. Use --last or --session <id>[/]")
        return

    if not findings_dicts:
        console.print("[bright_yellow]No findings in this session.[/]")
        return

    # Convert dicts to Finding-like objects
    class _F:
        def __init__(self, d):
            for k, v in d.items(): setattr(self, k, v)
            if not hasattr(self, 'param'): self.param = ''
        def to_dict(self): return self.__dict__

    findings = [_F(d) for d in findings_dicts]
    console.print(f"[bright_cyan]Loaded [/][bright_yellow]{len(findings)}[/][bright_cyan] findings for:[/] {target}")
    await _generate_report(findings, output, fmt, target)


# ─── sync ────────────────────────────────────────────────────

@app.command()
def sync(
    session: Optional[int] = typer.Option(None, "--session", "-s", help="Session ID to sync"),
    last: bool = typer.Option(False, "--last", help="Sync last scan session"),
):
    """[bold]Push local scan findings to cloud dashboard[/]"""
    show_banner()
    asyncio.run(_run_sync(session, last))


async def _run_sync(session_id: Optional[int], last: bool):
    import json as _json
    from vexor.core.db import get_session_findings, get_recent_sessions
    from vexor.config import API_BASE, TOKEN_FILE

    if not TOKEN_FILE.exists():
        console.print("[bright_red]Not logged in.[/] Run: vexor auth login")
        return

    token = _json.loads(TOKEN_FILE.read_text()).get("access_token", "")

    if last and not session_id:
        sessions = await get_recent_sessions(limit=1)
        if not sessions:
            console.print("[bright_red]No sessions found. Run a scan first.[/]")
            return
        session_id = sessions[0]["id"]

    if not session_id:
        console.print("[dim]Use --last or --session <id>[/]")
        return

    findings = await get_session_findings(session_id)
    if not findings:
        console.print("[bright_yellow]No findings in this session.[/]")
        return

    console.print(f"[bright_cyan]Syncing {len(findings)} findings...[/]")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{API_BASE}/sync/push",
                json={"target": f"session-{session_id}", "findings": findings},
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                console.print(f"[bright_green]✓ Synced! Cloud ID: {data.get('scan_id')}[/]")
            else:
                console.print(f"[bright_red]Sync failed:[/] {resp.status_code} {resp.text[:100]}")
    except Exception as e:
        console.print(f"[bright_red]Connection error:[/] {e}")


# ─── history ─────────────────────────────────────────────────

@app.command()
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of sessions to show"),
):
    """[bold]Show past scan sessions from local DB[/]"""
    show_banner()
    asyncio.run(_show_history(limit))


async def _show_history(limit: int):
    from vexor.core.db import get_recent_sessions
    from rich.table import Table
    sessions = await get_recent_sessions(limit=limit)
    if not sessions:
        console.print("[dim]No scan sessions found. Run: vexor scan <target>[/]")
        return
    table = Table(title="[bold bright_cyan]Vexor Scan History[/]",
                  header_style="bold bright_magenta", border_style="bright_cyan")
    table.add_column("ID", width=5)
    table.add_column("Target", width=35)
    table.add_column("Type", width=8)
    table.add_column("Started", width=20)
    table.add_column("Total", width=6)
    table.add_column("Crit", width=5, style="bold bright_red")
    table.add_column("High", width=5, style="bold bright_magenta")
    for s in sessions:
        table.add_row(
            str(s.get("id", "")), s.get("target", "")[:35], s.get("scan_type", ""),
            s.get("started_at", "")[:19], str(s.get("total", 0)),
            str(s.get("critical", 0)), str(s.get("high", 0)),
        )
    console.print(table)


# ─── Entry point ────────────────────────────────────────────

def run():
    """Entry point for pip install"""
    app()


if __name__ == "__main__":
    run()

