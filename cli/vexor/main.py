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
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

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
"""


def show_banner():
    console.print(BANNER)


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
        # Launch TUI
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
        console.print("[dim]Run: pip install vexor[all][/]")
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Specific module to run"),
    full: bool = typer.Option(False, "--full", help="Run all modules"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html/pdf/json"),
    offline: bool = typer.Option(False, "--offline", help="Offline mode"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of threads"),
):
    """
    [bold]Scan a target for vulnerabilities[/]

    Examples:
      vexor scan https://target.com
      vexor scan https://target.com --full
      vexor scan https://target.com --module sqli
      vexor scan https://target.com --output report.html
    """
    show_banner()
    console.print(f"[bright_cyan]◈ SCANNER[/]  Target: [bright_yellow]{target}[/]")

    asyncio.run(_run_scan(
        target=target,
        module=module,
        full=full,
        output=output,
        fmt=format,
        offline=offline,
        threads=threads,
    ))


async def _run_scan(
    target: str,
    module: Optional[str],
    full: bool,
    output: Optional[str],
    fmt: str,
    offline: bool,
    threads: int,
):
    """Async scan runner"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table

    modules_to_run = []

    if module:
        modules_to_run = [module]
    elif full:
        modules_to_run = [
            "sqli", "xss", "csrf", "idor", "ssrf", "xxe", "lfi",
            "jwt_analyzer", "ssl_analyzer", "headers", "cors",
            "websocket", "api_tester", "fingerprinter",
            "subdomain", "dirbuster", "port_scanner",
            "rate_limit", "open_redirect", "session_analyzer",
            "sensitive_data", "auth_bypass", "cve_lookup",
            "wayback", "github_dork",
        ]
    else:
        # Quick scan — top 5
        modules_to_run = ["sqli", "xss", "headers", "cors", "ssl_analyzer"]

    all_findings = []

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
            except ImportError:
                pass
            except Exception as e:
                console.print(f"[dim]  {mod_name}: {str(e)[:50]}[/]")
            progress.advance(task)

    # Display results
    _display_findings(all_findings)

    # Generate report
    if output or all_findings:
        await _generate_report(all_findings, output, fmt, target)


def _display_findings(findings: list):
    """Display findings in a beautiful table"""
    from rich.table import Table

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
            f.module,
            f.vuln,
            f.endpoint[:40],
            f.param or "-",
        )

    console.print(table)

    # Summary
    from collections import Counter
    counts = Counter(f.severity for f in findings)
    console.print(
        f"\n[dim]Summary:[/] "
        f"[bold bright_red]Critical: {counts.get('CRITICAL', 0)}[/]  "
        f"[bold bright_magenta]High: {counts.get('HIGH', 0)}[/]  "
        f"[bright_yellow]Medium: {counts.get('MEDIUM', 0)}[/]  "
        f"[bright_blue]Low: {counts.get('LOW', 0)}[/]  "
        f"[dim]Info: {counts.get('INFO', 0)}[/]"
    )


async def _generate_report(findings: list, output: Optional[str], fmt: str, target: str):
    """Generate report file"""
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
            await report.generate(output, findings=[f.to_dict() for f in findings])
        elif fmt == "pdf":
            from vexor.reports.pdf import PDFReport
            report = PDFReport(title=f"Vexor Report — {target}")
            await report.generate(output, findings=[f.to_dict() for f in findings])
        elif fmt == "json":
            import json
            with open(output, 'w') as f:
                json.dump([f.to_dict() for f in findings], f, indent=2)

        console.print(f"[bright_green]✓ Report saved:[/] {output}")
    except Exception as e:
        console.print(f"[bright_red]Report error:[/] {str(e)}")


@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", help="Proxy host"),
    port: int = typer.Option(8080, "--port", "-p", help="Proxy port"),
):
    """
    [bold]Start HTTP/HTTPS proxy interceptor[/]

    Configure browser to use 127.0.0.1:8080
    """
    show_banner()
    console.print(f"[bright_cyan]◈ PROXY[/]  Starting on [bright_yellow]{host}:{port}[/]")
    console.print(f"[dim]Configure browser proxy: {host}:{port}[/]")
    console.print(f"[dim]Press Ctrl+C to stop[/]\n")

    asyncio.run(_run_proxy(host, port))


async def _run_proxy(host: str, port: int):
    from vexor.core.proxy import VexorProxy
    from rich.table import Table

    table = Table(
        title="[bold bright_cyan]HTTP HISTORY[/]",
        show_header=True,
        header_style="bold bright_magenta",
    )
    table.add_column("#", width=4)
    table.add_column("Method", width=8)
    table.add_column("Host", width=30)
    table.add_column("Path", width=40)
    table.add_column("Status", width=8)

    def on_request(data: dict):
        console.print(
            f"[dim]{data.get('id', '')}[/]  "
            f"[bright_cyan]{data.get('method', 'GET'):<6}[/]  "
            f"[white]{data.get('host', ''):<30}[/]  "
            f"[dim]{data.get('path', '/')[:40]}[/]  "
            f"[bright_green]{data.get('status', '')}[/]"
        )

    proxy = VexorProxy(host=host, port=port, on_request=on_request)
    try:
        await proxy.start()
    except KeyboardInterrupt:
        console.print("\n[bright_yellow]Proxy stopped.[/]")


@app.command()
def auth(
    action: str = typer.Argument(..., help="login / logout / status"),
    email: Optional[str] = typer.Option(None, "--email", "-e"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
):
    """
    [bold]Authentication — login/logout/status[/]

    Examples:
      vexor auth login
      vexor auth status
      vexor auth logout
    """
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
                    TOKEN_FILE_data = {"access_token": data["access_token"]}
                    TOKEN_FILE.write_text(json.dumps(TOKEN_FILE_data))
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


@app.command()
def update():
    """
    [bold]Update Vexor to latest version[/]

    Pulls latest code from GitHub and reinstalls.
    """
    show_banner()
    console.print("[bright_cyan]◈ UPDATER[/]  Checking for updates...")

    import subprocess
    import sys

    # Find Vexor install location
    try:
        import vexor
        vexor_path = Path(vexor.__file__).parent.parent.parent
        repo_path = None

        # Check if it's a git repo
        git_dir = vexor_path / ".git"
        if not git_dir.exists():
            # Try parent directories
            for parent in vexor_path.parents:
                if (parent / ".git").exists():
                    repo_path = parent
                    break
        else:
            repo_path = vexor_path

        if repo_path:
            console.print(f"[dim]  Repo found at: {repo_path}[/]")
            console.print("[bright_cyan]  Pulling latest changes...[/]")

            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=str(repo_path),
                capture_output=True, text=True
            )

            if result.returncode == 0:
                console.print(f"[bright_green]  ✓ {result.stdout.strip()}[/]")
            else:
                console.print(f"[bright_yellow]  ! {result.stderr.strip()}[/]")

            # Reinstall
            console.print("[bright_cyan]  Reinstalling Vexor...[/]")
            cli_path = repo_path / "cli"
            if cli_path.exists():
                # Detect if --break-system-packages needed
                pip_flags = []
                test = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--help"],
                    capture_output=True, text=True
                )
                if "break-system-packages" in test.stdout:
                    pip_flags = ["--break-system-packages"]

                result2 = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-e", ".", "--quiet"] + pip_flags,
                    cwd=str(cli_path),
                    capture_output=True, text=True
                )
                if result2.returncode == 0:
                    console.print("[bright_green]  ✓ Vexor updated successfully![/]")
                    console.print(f"[dim]  Restart vexor to use new version[/]")
                else:
                    console.print(f"[bright_red]  ✗ Reinstall failed: {result2.stderr[:100]}[/]")
            else:
                console.print("[bright_yellow]  ! cli/ directory not found[/]")
        else:
            # No git repo — clone fresh
            console.print("[bright_yellow]  ! Not a git repo. Cloning fresh...[/]")
            home = Path.home()
            clone_path = home / "Vexor"

            if clone_path.exists():
                subprocess.run(["git", "pull"], cwd=str(clone_path))
            else:
                subprocess.run([
                    "git", "clone",
                    "https://github.com/thecnical/Vexor",
                    str(clone_path)
                ])

            console.print(f"[bright_green]  ✓ Updated at {clone_path}[/]")
            console.print(f"[dim]  Run: cd {clone_path} && ./install.sh[/]")

    except Exception as e:
        console.print(f"[bright_red]  Update error: {str(e)}[/]")
        console.print("[dim]  Manual update: cd ~/Vexor && git pull && ./install.sh[/]")
    format: str = typer.Option("html", "--format", "-f", help="html/pdf/json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path"),
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session name"),
):
    """[bold]Generate security report[/]"""
    show_banner()
    console.print(f"[bright_cyan]◈ REPORT[/]  Format: [bright_yellow]{format}[/]")
    asyncio.run(_generate_report([], output, format, ""))


def run():
    """Entry point for pip install"""
    app()


if __name__ == "__main__":
    run()
