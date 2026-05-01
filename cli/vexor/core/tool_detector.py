"""
Vexor Tool Detector
Auto-detects installed external tools (Go binaries, system tools)
No crash if tool missing — graceful skip
"""
import shutil
import asyncio
import subprocess
from typing import Optional


class ToolDetector:
    """Detects available external OSINT tools at runtime"""

    _cache: Optional[dict] = None

    @classmethod
    def detect(cls) -> dict:
        """Returns dict of available tools — cached after first call"""
        if cls._cache is not None:
            return cls._cache

        tools = {
            # Go binaries
            "assetfinder": shutil.which("assetfinder"),
            "hakrawler":   shutil.which("hakrawler"),
            "httpx_pd":    shutil.which("httpx"),       # ProjectDiscovery httpx
            "gf":          shutil.which("gf"),
            "findomain":   shutil.which("findomain"),
            # System tools
            "nmap":        shutil.which("nmap"),
            "masscan":     shutil.which("masscan"),
            "amass":       shutil.which("amass"),
            "subfinder":   shutil.which("subfinder"),
        }

        # Filter None values — only keep what's installed
        cls._cache = {k: v for k, v in tools.items() if v}
        return cls._cache

    @classmethod
    def available(cls, tool: str) -> bool:
        return tool in cls.detect()

    @classmethod
    def summary(cls) -> str:
        found = cls.detect()
        if not found:
            return "No external tools detected"
        return f"External tools: {', '.join(found.keys())}"

    @classmethod
    def reset_cache(cls):
        cls._cache = None


async def run_tool(
    cmd: list[str],
    timeout: int = 30,
    input_data: Optional[str] = None,
) -> tuple[str, str]:
    """
    Run an external tool asynchronously.
    Returns (stdout, stderr). Never raises — returns empty strings on failure.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        stdin_bytes = input_data.encode() if input_data else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes),
            timeout=timeout,
        )
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return "", "timeout"
    except Exception as e:
        return "", str(e)
