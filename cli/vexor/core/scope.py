"""
Vexor Scope Manager
Defines in-scope and out-of-scope targets for authorized testing.
All scan modules check scope before testing.
Scope file: ~/.vexor/scope.txt
"""
import re
from pathlib import Path
from vexor.config import HOME_DIR

SCOPE_FILE = HOME_DIR / "scope.txt"

SCOPE_TEMPLATE = """# Vexor Scope File
# One entry per line. Supports:
#   - Exact domains:     example.com
#   - Wildcards:         *.example.com
#   - IP addresses:      192.168.1.1
#   - CIDR ranges:       192.168.1.0/24
#   - Exclusions (prefix with !): !admin.example.com
#
# Lines starting with # are comments.
# Empty lines are ignored.
#
# Example:
# example.com
# *.example.com
# !staging.example.com
# 10.0.0.0/24
"""


class ScopeManager:
    """
    Manages in-scope and out-of-scope targets.
    If scope file is empty or doesn't exist, everything is in scope.
    """

    def __init__(self):
        self._in_scope:  list[str] = []
        self._out_scope: list[str] = []
        self._loaded = False

    def load(self) -> None:
        """Load scope from file"""
        self._in_scope  = []
        self._out_scope = []

        if not SCOPE_FILE.exists():
            self._loaded = True
            return

        for line in SCOPE_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                self._out_scope.append(line[1:].strip())
            else:
                self._in_scope.append(line)

        self._loaded = True

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is in scope.
        Returns True if:
        - No scope defined (empty scope = everything allowed)
        - Target matches an in-scope entry AND doesn't match an exclusion
        """
        if not self._loaded:
            self.load()

        # No scope defined = everything in scope
        if not self._in_scope:
            return True

        # Clean target
        clean = self._clean_target(target)

        # Check exclusions first
        for excl in self._out_scope:
            if self._matches(clean, excl):
                return False

        # Check in-scope
        for entry in self._in_scope:
            if self._matches(clean, entry):
                return True

        return False

    def get_scope_summary(self) -> str:
        """Human-readable scope summary"""
        if not self._loaded:
            self.load()
        if not self._in_scope:
            return "No scope defined — all targets allowed"
        lines = [f"In scope ({len(self._in_scope)}): {', '.join(self._in_scope[:5])}"]
        if self._out_scope:
            lines.append(f"Excluded ({len(self._out_scope)}): {', '.join(self._out_scope[:5])}")
        return " | ".join(lines)

    def add_to_scope(self, target: str, exclude: bool = False) -> None:
        """Add a target to scope file"""
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not SCOPE_FILE.exists():
            SCOPE_FILE.write_text(SCOPE_TEMPLATE)
        prefix = "!" if exclude else ""
        with open(SCOPE_FILE, "a") as f:
            f.write(f"\n{prefix}{target}")
        self._loaded = False  # Force reload

    def create_default(self) -> None:
        """Create default scope file with template"""
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not SCOPE_FILE.exists():
            SCOPE_FILE.write_text(SCOPE_TEMPLATE)

    def _clean_target(self, target: str) -> str:
        """Extract hostname/IP from URL"""
        from urllib.parse import urlparse
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split("/")[0].split(":")[0]

    def _matches(self, target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern"""
        # Wildcard: *.example.com
        if pattern.startswith("*."):
            domain = pattern[2:]
            return target == domain or target.endswith(f".{domain}")

        # CIDR: 192.168.1.0/24
        if "/" in pattern and not pattern.startswith("http"):
            try:
                import ipaddress
                return ipaddress.ip_address(target) in ipaddress.ip_network(pattern, strict=False)
            except Exception:
                pass

        # Exact match
        return target == pattern or target.endswith(f".{pattern}")


# Global singleton
_scope = ScopeManager()


def get_scope() -> ScopeManager:
    return _scope


def is_in_scope(target: str) -> bool:
    return _scope.is_in_scope(target)
