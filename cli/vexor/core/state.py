"""
Vexor Global State Manager
Persists data across screen switches
"""
from dataclasses import dataclass, field
from typing import Optional
import datetime


@dataclass
class ScanResult:
    severity: str
    module: str
    vuln: str
    endpoint: str
    param: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S"))


@dataclass
class ProxyEntry:
    id: int
    method: str
    host: str
    path: str
    status: int = 0
    length: int = 0
    mime: str = ""
    timestamp: str = ""
    request_raw: str = ""
    response_raw: str = ""


class VexorState:
    """Singleton global state — survives screen switches"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.scan_results: list[ScanResult] = []
        self.proxy_history: list[ProxyEntry] = []
        self.osint_results: list[ScanResult] = []
        self.scan_target: str = ""
        self.proxy_running: bool = False
        self.is_offline: bool = False
        self.is_connected: bool = False
        self.scans_run: int = 0
        self.ai_analyses: int = 0
        self.reports_generated: int = 0
        self._listeners: list = []

    def add_scan_result(self, result: ScanResult):
        self.scan_results.append(result)
        self._notify("scan_result", result)

    def add_proxy_entry(self, entry: ProxyEntry):
        self.proxy_history.append(entry)
        self._notify("proxy_entry", entry)

    def add_osint_result(self, result: ScanResult):
        self.osint_results.append(result)
        self._notify("osint_result", result)

    def clear_scan_results(self):
        self.scan_results.clear()

    def get_stats(self) -> dict:
        from collections import Counter
        counts = Counter(r.severity for r in self.scan_results)
        return {
            "total": len(self.scan_results),
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "scans_run": self.scans_run,
            "ai_analyses": self.ai_analyses,
            "reports": self.reports_generated,
            "proxy_requests": len(self.proxy_history),
        }

    def register_listener(self, callback):
        self._listeners.append(callback)

    def _notify(self, event: str, data):
        for listener in self._listeners:
            try:
                listener(event, data)
            except Exception:
                pass


# Global singleton
state = VexorState()
