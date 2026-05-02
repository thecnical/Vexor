"""
Vexor Screenshot Module
Takes screenshots of live hosts using Playwright.
Falls back gracefully if Playwright not installed.
Install: pip install playwright && playwright install chromium
"""
import asyncio
import shutil
from pathlib import Path
from vexor.modules.base import BaseScanner, Finding
from vexor.config import REPORTS_DIR


class Scanner(BaseScanner):
    """
    Screenshot Module — Visual recon of live hosts.
    Takes screenshots of discovered subdomains/live hosts.
    Saves to ~/.vexor/reports/screenshots/
    """

    MODULE_NAME = "screenshot"
    MODULE_DESC = "Visual Recon — Screenshot Live Hosts"

    async def scan(self) -> list[Finding]:
        # Check if playwright is available
        try:
            from playwright.async_api import async_playwright
            playwright_available = True
        except ImportError:
            playwright_available = False

        if not playwright_available:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Screenshot Module: Playwright Not Installed",
                endpoint=self.target,
                evidence="pip install playwright && playwright install chromium",
                description=(
                    "Playwright is not installed. Install it for visual recon:\n"
                    "pip install playwright\n"
                    "playwright install chromium"
                ),
                remediation="pip install playwright && playwright install chromium",
            ))
            return self.findings

        # Create screenshots directory
        screenshots_dir = REPORTS_DIR / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        async with self:
            await self._take_screenshot(self.target, screenshots_dir)

        return self.findings

    async def _take_screenshot(self, url: str, output_dir: Path) -> None:
        """Take a screenshot of a URL"""
        try:
            from playwright.async_api import async_playwright
            import re

            # Clean filename from URL
            clean = re.sub(r"[^\w\-.]", "_", url.replace("https://", "").replace("http://", ""))
            filename = f"{clean[:50]}.png"
            filepath = output_dir / filename

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--ignore-certificate-errors",
                    ],
                )
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )

                try:
                    await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    await asyncio.sleep(1)  # Let JS render
                    title = await page.title()
                    await page.screenshot(path=str(filepath), full_page=False)

                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln=f"Screenshot: {title[:50] or url}",
                        endpoint=url,
                        evidence=f"Screenshot saved: {filepath}\nPage title: {title}",
                        description=f"Visual screenshot of {url} captured for recon.",
                        remediation="Review screenshot for exposed admin panels, login pages, or sensitive content.",
                    ))

                except Exception as e:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln=f"Screenshot Failed: {url}",
                        endpoint=url,
                        evidence=str(e)[:200],
                        description=f"Could not screenshot {url}: {str(e)[:100]}",
                        remediation="",
                    ))
                finally:
                    await browser.close()

        except Exception as e:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Screenshot Error",
                endpoint=self.target,
                evidence=str(e)[:200],
                description=f"Screenshot module error: {str(e)[:100]}",
                remediation="Ensure Playwright is installed: pip install playwright && playwright install chromium",
            ))


async def screenshot_hosts(hosts: list[str], output_dir: Path = None) -> list[dict]:
    """
    Utility function to screenshot multiple hosts in parallel.
    Used by OSINT module after live host check.
    Returns list of {url, filepath, title} dicts.
    """
    if output_dir is None:
        output_dir = REPORTS_DIR / "screenshots"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return []

    results = []
    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent browsers

    async def _shot(url: str) -> dict | None:
        async with semaphore:
            try:
                import re
                clean = re.sub(r"[^\w\-.]", "_", url.replace("https://", "").replace("http://", ""))
                filepath = output_dir / f"{clean[:50]}.png"

                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
                    )
                    page = await browser.new_page(
                        viewport={"width": 1280, "height": 720},
                        ignore_https_errors=True,
                    )
                    try:
                        await page.goto(url, timeout=12000, wait_until="domcontentloaded")
                        await asyncio.sleep(0.5)
                        title = await page.title()
                        await page.screenshot(path=str(filepath))
                        return {"url": url, "filepath": str(filepath), "title": title}
                    except Exception:
                        return None
                    finally:
                        await browser.close()
            except Exception:
                return None

    tasks = [_shot(url) for url in hosts[:20]]  # Max 20 screenshots
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in raw if r and not isinstance(r, Exception)]
