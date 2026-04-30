"""
Vexor Session Manager — Project Save/Load
"""
import json
import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict

from vexor.config import SESSIONS_DIR, ensure_dirs


@dataclass
class VexorSession:
    """A Vexor project session"""
    name: str
    target: str = ""
    created_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    findings: list = field(default_factory=list)
    requests: list = field(default_factory=list)
    notes: str = ""
    scan_config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "VexorSession":
        return cls(**data)


class SessionManager:
    """Manages Vexor project sessions"""

    def __init__(self):
        ensure_dirs()
        self.current_session: Optional[VexorSession] = None

    def new_session(self, name: str, target: str = "") -> VexorSession:
        """Create a new session"""
        session = VexorSession(name=name, target=target)
        self.current_session = session
        self.save()
        return session

    def save(self) -> None:
        """Save current session to disk"""
        if not self.current_session:
            return

        self.current_session.updated_at = datetime.datetime.now().isoformat()
        filename = self._session_filename(self.current_session.name)

        with open(filename, 'w') as f:
            json.dump(self.current_session.to_dict(), f, indent=2)

    def load(self, name: str) -> Optional[VexorSession]:
        """Load a session from disk"""
        filename = self._session_filename(name)
        if not filename.exists():
            return None

        with open(filename) as f:
            data = json.load(f)

        self.current_session = VexorSession.from_dict(data)
        return self.current_session

    def list_sessions(self) -> list[dict]:
        """List all saved sessions"""
        sessions = []
        for f in SESSIONS_DIR.glob("*.json"):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                sessions.append({
                    "name": data.get("name", f.stem),
                    "target": data.get("target", ""),
                    "created_at": data.get("created_at", ""),
                    "findings_count": len(data.get("findings", [])),
                })
            except Exception:
                continue
        return sessions

    def add_finding(self, finding: dict) -> None:
        """Add a finding to current session"""
        if self.current_session:
            self.current_session.findings.append(finding)
            self.save()

    def add_request(self, request: dict) -> None:
        """Add a request to current session"""
        if self.current_session:
            self.current_session.requests.append(request)
            self.save()

    def delete_session(self, name: str) -> bool:
        """Delete a session"""
        filename = self._session_filename(name)
        if filename.exists():
            filename.unlink()
            return True
        return False

    def _session_filename(self, name: str) -> Path:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        return SESSIONS_DIR / f"{safe_name}.json"
