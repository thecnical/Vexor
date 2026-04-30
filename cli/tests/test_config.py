"""
Vexor Config Tests
"""
import pytest
from pathlib import Path
from vexor.config import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR,
    TOOL_DESCRIPTION, TOOL_TAGLINE,
    HOME_DIR, SESSIONS_DIR, REPORTS_DIR,
    PAYLOADS_DIR, API_BASE, BACKEND_URL,
)


def test_tool_constants():
    assert TOOL_NAME == "Vexor"
    assert TOOL_VERSION == "1.0.0"
    assert "Chandan Pandey" in TOOL_AUTHOR
    assert "Technical" in TOOL_AUTHOR
    assert len(TOOL_DESCRIPTION) > 0
    assert len(TOOL_TAGLINE) > 0


def test_backend_url():
    assert BACKEND_URL.startswith("https://")
    assert "onrender.com" in BACKEND_URL or "localhost" in BACKEND_URL


def test_api_base():
    assert "/api/v1" in API_BASE


def test_payloads_dir_exists():
    assert PAYLOADS_DIR.exists()
    assert (PAYLOADS_DIR / "sqli.txt").exists()
    assert (PAYLOADS_DIR / "xss.txt").exists()
    assert (PAYLOADS_DIR / "lfi.txt").exists()
    assert (PAYLOADS_DIR / "ssrf.txt").exists()


def test_ensure_dirs():
    from vexor.config import ensure_dirs
    ensure_dirs()
    assert HOME_DIR.exists()
    assert SESSIONS_DIR.exists()
    assert REPORTS_DIR.exists()
