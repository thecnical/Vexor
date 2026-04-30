"""
Vexor Base Scanner Module
All scan modules inherit from this
"""
import httpx
import asyncio
from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A security finding"""
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    module: str            # Module name
    vuln: str              # Vulnerability name
    endpoint: str          # Affected endpoint
    param: str = ""        # Affected parameter
    payload: str = ""      # Payload used
    evidence: str = ""     # Evidence/proof
    description: str = ""  # Description
    remediation: str = ""  # How to fix
    ai_note: str = ""      # AI analysis note
    cve: str = ""          # Related CVE if any

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "module": self.module,
            "vuln": self.vuln,
            "endpoint": self.endpoint,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "ai_note": self.ai_note,
            "cve": self.cve,
        }


class BaseScanner(ABC):
    """Base class for all Vexor scan modules"""

    MODULE_NAME = "base"
    MODULE_DESC = "Base scanner"

    def __init__(
        self,
        target: str,
        timeout: int = 30,
        threads: int = 10,
        offline: bool = False,
        session: Optional[object] = None
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.offline = offline
        self.session = session
        self.findings: list[Finding] = []
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Vexor/1.0 Security Scanner",
            }
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @abstractmethod
    async def scan(self) -> list[Finding]:
        """Run the scan — must be implemented by each module"""
        pass

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Safe GET request"""
        try:
            if self._client:
                return await self._client.get(url, **kwargs)
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                return await client.get(url, **kwargs)
        except Exception:
            return None

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Safe POST request"""
        try:
            if self._client:
                return await self._client.post(url, **kwargs)
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                return await client.post(url, **kwargs)
        except Exception:
            return None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding"""
        self.findings.append(finding)
        if self.session:
            self.session.add_finding(finding.to_dict())

    def load_payloads(self, payload_type: str) -> list[str]:
        """Load payloads from built-in payload files"""
        from vexor.config import PAYLOADS_DIR
        payload_file = PAYLOADS_DIR / f"{payload_type}.txt"
        if payload_file.exists():
            return [
                line.strip()
                for line in payload_file.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
        return []
