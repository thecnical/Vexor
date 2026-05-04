"""Vexor Base Scanner - scope enforcement wired in"""
import httpx
import asyncio
from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: str
    module: str
    vuln: str
    endpoint: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    ai_note: str = ""
    cve: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "module": self.module,
            "vuln": self.vuln, "endpoint": self.endpoint,
            "param": self.param, "payload": self.payload,
            "evidence": self.evidence, "description": self.description,
            "remediation": self.remediation, "ai_note": self.ai_note,
            "cve": self.cve,
        }


class BaseScanner(ABC):
    MODULE_NAME = "base"
    MODULE_DESC = "Base scanner"

    def __init__(self, target: str, timeout: int = 30, threads: int = 10,
                 offline: bool = False, session=None, skip_scope_check: bool = False):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.offline = offline
        self.session = session
        self.findings: list[Finding] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._skip_scope_check = skip_scope_check

    async def __aenter__(self):
        if not self._skip_scope_check:
            try:
                from vexor.core.scope import is_in_scope
                if not is_in_scope(self.target):
                    raise PermissionError(
                        f"Target {self.target} is OUT OF SCOPE. "
                        "Add it to ~/.vexor/scope.txt or pass skip_scope_check=True."
                    )
            except ImportError:
                pass
        self._client = httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Vexor/4.0 Security Scanner"},
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @abstractmethod
    async def scan(self) -> list[Finding]:
        pass

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            if self._client:
                return await self._client.get(url, **kwargs)
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                return await c.get(url, **kwargs)
        except Exception:
            return None

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            if self._client:
                return await self._client.post(url, **kwargs)
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                return await c.post(url, **kwargs)
        except Exception:
            return None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.session:
            self.session.add_finding(finding.to_dict())

    def load_payloads(self, payload_type: str) -> list[str]:
        from vexor.config import PAYLOADS_DIR
        payload_file = PAYLOADS_DIR / f"{payload_type}.txt"
        if payload_file.exists():
            return [l.strip() for l in payload_file.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
        return []
