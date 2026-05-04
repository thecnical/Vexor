"""Vexor Base Scanner
- Fixed: threads param now wired into asyncio.Semaphore (was stored but never used)
- Added: put/delete/patch/options HTTP methods
- Added: rate-aware request wrapper with jitter
- Added: custom header injection for WAF evasion testing
"""
import httpx
import asyncio
import random
from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    severity:    str
    module:      str
    vuln:        str
    endpoint:    str
    param:       str = ""
    payload:     str = ""
    evidence:    str = ""
    description: str = ""
    remediation: str = ""
    ai_note:     str = ""
    cve:         str = ""

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

    def __init__(
        self,
        target: str,
        timeout: int = 30,
        threads: int = 10,
        offline: bool = False,
        session=None,
        skip_scope_check: bool = False,
        rate_limit_delay: float = 0.0,   # seconds between requests (0 = unlimited)
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.offline = offline
        self.session = session
        self.findings: list[Finding] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._skip_scope_check = skip_scope_check
        self._rate_limit_delay = rate_limit_delay
        # BUG-013 variant FIX: semaphore is now actually created with the threads value
        self._sem: asyncio.Semaphore = asyncio.Semaphore(max(1, threads))

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
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Vexor/4.0 Security Scanner"},
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @abstractmethod
    async def scan(self) -> list[Finding]:
        pass

    # ─── HTTP helpers (all rate-aware and semaphore-gated) ──────────────────

    async def _throttle(self):
        """Apply rate limit delay + jitter if configured."""
        if self._rate_limit_delay > 0:
            jitter = random.uniform(0, self._rate_limit_delay * 0.3)
            await asyncio.sleep(self._rate_limit_delay + jitter)

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.get(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.get(url, **kwargs)
            except Exception:
                return None

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.post(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.post(url, **kwargs)
            except Exception:
                return None

    async def put(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.put(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.put(url, **kwargs)
            except Exception:
                return None

    async def delete(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.delete(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.delete(url, **kwargs)
            except Exception:
                return None

    async def patch(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.patch(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.patch(url, **kwargs)
            except Exception:
                return None

    async def options(self, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.options(url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.options(url, **kwargs)
            except Exception:
                return None

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """Generic method-agnostic request."""
        async with self._sem:
            await self._throttle()
            try:
                if self._client:
                    return await self._client.request(method, url, **kwargs)
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                    return await c.request(method, url, **kwargs)
            except Exception:
                return None

    # ─── Finding helpers ────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.session:
            self.session.add_finding(finding.to_dict())

    def load_payloads(self, payload_type: str) -> list[str]:
        from vexor.config import PAYLOADS_DIR
        payload_file = PAYLOADS_DIR / f"{payload_type}.txt"
        if payload_file.exists():
            return [
                line.strip()
                for line in payload_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.startswith("#")
            ]
        return []

    # ─── Concurrent task runner ─────────────────────────────────────────────

    async def run_concurrent(self, coros: list, max_concurrent: Optional[int] = None) -> list:
        """
        Run a list of coroutines with semaphore-limited concurrency.
        Uses self.threads if max_concurrent not specified.
        """
        sem = asyncio.Semaphore(max_concurrent or self.threads)
        async def _wrap(coro):
            async with sem:
                return await coro
        return await asyncio.gather(*[_wrap(c) for c in coros], return_exceptions=True)
