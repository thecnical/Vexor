"""
Vexor Workspace / Project System
Each target gets its own workspace with findings, notes, and history.
Workspaces stored in ~/.vexor/workspaces/<name>/
"""
import json
import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from vexor.config import HOME_DIR

WORKSPACES_DIR = HOME_DIR / "workspaces"


@dataclass
class Workspace:
    name: str
    target: str
    created_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    description: str = ""
    tags: list[str] = field(default_factory=list)
    scan_count: int = 0
    finding_count: int = 0

    @property
    def path(self) -> Path:
        return WORKSPACES_DIR / self.name

    @property
    def findings_file(self) -> Path:
        return self.path / "findings.json"

    @property
    def notes_file(self) -> Path:
        return self.path / "notes.md"

    @property
    def meta_file(self) -> Path:
        return self.path / "workspace.json"

    def save(self) -> None:
        """Save workspace metadata"""
        self.path.mkdir(parents=True, exist_ok=True)
        self.updated_at = datetime.datetime.now().isoformat()
        self.meta_file.write_text(json.dumps(asdict(self), indent=2))

    def add_findings(self, findings: list[dict]) -> None:
        """Append findings to workspace"""
        existing = self.get_findings()
        existing.extend(findings)
        self.findings_file.write_text(json.dumps(existing, indent=2, default=str))
        self.finding_count = len(existing)
        self.scan_count += 1
        self.save()

    def get_findings(self) -> list[dict]:
        """Load all findings"""
        if self.findings_file.exists():
            try:
                return json.loads(self.findings_file.read_text())
            except Exception:
                return []
        return []

    def get_notes(self) -> str:
        """Load notes"""
        if self.notes_file.exists():
            return self.notes_file.read_text()
        return f"# {self.name}\n\nTarget: {self.target}\n\n## Notes\n\n"

    def save_notes(self, content: str) -> None:
        """Save notes"""
        self.path.mkdir(parents=True, exist_ok=True)
        self.notes_file.write_text(content)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self.findings_file.write_text("[]")
        self.finding_count = 0
        self.save()

    def delete(self) -> None:
        """Delete workspace"""
        import shutil
        if self.path.exists():
            shutil.rmtree(self.path)


class WorkspaceManager:
    """Manages all workspaces"""

    def __init__(self):
        WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
        self._active: Optional[Workspace] = None

    @property
    def active(self) -> Optional[Workspace]:
        return self._active

    def set_active(self, workspace: Workspace) -> None:
        self._active = workspace

    def create(self, name: str, target: str, description: str = "") -> Workspace:
        """Create a new workspace"""
        # Sanitize name
        import re
        safe_name = re.sub(r"[^\w\-.]", "_", name)[:50]
        ws = Workspace(name=safe_name, target=target, description=description)
        ws.save()
        return ws

    def get(self, name: str) -> Optional[Workspace]:
        """Get workspace by name"""
        meta_file = WORKSPACES_DIR / name / "workspace.json"
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text())
                return Workspace(**data)
            except Exception:
                return None
        return None

    def list_all(self) -> list[Workspace]:
        """List all workspaces"""
        workspaces = []
        if not WORKSPACES_DIR.exists():
            return workspaces
        for ws_dir in sorted(WORKSPACES_DIR.iterdir(), reverse=True):
            if ws_dir.is_dir():
                ws = self.get(ws_dir.name)
                if ws:
                    workspaces.append(ws)
        return workspaces

    def delete(self, name: str) -> bool:
        """Delete a workspace"""
        ws = self.get(name)
        if ws:
            ws.delete()
            if self._active and self._active.name == name:
                self._active = None
            return True
        return False

    def get_or_create(self, target: str) -> Workspace:
        """Get existing workspace for target or create new one"""
        import re
        name = re.sub(r"[^\w\-.]", "_", target.replace("https://", "").replace("http://", ""))[:40]
        ws = self.get(name)
        if not ws:
            ws = self.create(name=name, target=target)
        return ws


# Global singleton
_manager = WorkspaceManager()


def get_workspace_manager() -> WorkspaceManager:
    return _manager
