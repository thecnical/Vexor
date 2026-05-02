"""
Vexor Module Tests
"""
import pytest
import asyncio
from vexor.modules.base import BaseScanner, Finding
from vexor.modules.headers import Scanner as HeadersScanner
from vexor.modules.cors import Scanner as CorsScanner
from vexor.modules.fingerprinter import Scanner as FingerprintScanner
from vexor.core.decoder import Decoder
from vexor.config import TOOL_VERSION, TOOL_AUTHOR


def test_tool_info():
    assert TOOL_VERSION is not None
    assert len(TOOL_VERSION) > 0
    assert "." in TOOL_VERSION   # semver format
    assert "Chandan Pandey" in TOOL_AUTHOR


def test_finding_dataclass():
    f = Finding(
        severity="HIGH",
        module="test",
        vuln="Test Vuln",
        endpoint="https://example.com",
    )
    assert f.severity == "HIGH"
    assert f.module == "test"
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["vuln"] == "Test Vuln"


def test_decoder_base64():
    d = Decoder()
    encoded = d.encode("hello", "base64")
    decoded = d.decode(encoded, "base64")
    assert decoded == "hello"


def test_decoder_hex():
    d = Decoder()
    encoded = d.encode("vexor", "hex")
    decoded = d.decode(encoded, "hex")
    assert decoded == "vexor"


def test_decoder_url():
    d = Decoder()
    encoded = d.encode("hello world", "url")
    assert "%20" in encoded or "+" in encoded


def test_decoder_rot13():
    d = Decoder()
    encoded = d.encode("hello", "rot13")
    decoded = d.decode(encoded, "rot13")
    assert decoded == "hello"


def test_decoder_auto_detect_base64():
    d = Decoder()
    import base64
    b64 = base64.b64encode(b"admin=true").decode()
    results = d.auto_detect(b64)
    formats = [r["format"] for r in results]
    assert "base64" in formats


def test_scanner_base_class():
    """Test that Scanner base class works correctly"""
    # Can't instantiate abstract class directly
    with pytest.raises(TypeError):
        BaseScanner("https://example.com")


@pytest.mark.asyncio
async def test_headers_scanner_offline():
    """Test headers scanner doesn't crash"""
    scanner = HeadersScanner(
        target="https://example.com",
        timeout=5,
        offline=True
    )
    assert scanner.target == "https://example.com"
    assert scanner.offline is True
    assert scanner.findings == []


@pytest.mark.asyncio
async def test_cors_scanner_init():
    scanner = CorsScanner(target="https://example.com", timeout=5)
    assert scanner.MODULE_NAME == "cors"
    assert scanner.MODULE_DESC == "CORS Misconfiguration Detection"


@pytest.mark.asyncio
async def test_fingerprinter_init():
    scanner = FingerprintScanner(target="https://example.com", timeout=5)
    assert scanner.MODULE_NAME == "fingerprint"


def test_finding_severity_levels():
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in severities:
        f = Finding(severity=sev, module="test", vuln="test", endpoint="https://x.com")
        assert f.severity == sev


def test_payload_loading():
    """Test built-in payloads load correctly"""
    from vexor.modules.sqli import Scanner
    scanner = Scanner(target="https://example.com")
    payloads = scanner.load_payloads("sqli")
    assert len(payloads) > 0
    assert "'" in payloads[0] or "OR" in payloads[0].upper()
