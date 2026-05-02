"""
Vexor Nuclei Integration
Wraps ProjectDiscovery Nuclei for template-based vulnerability scanning.
Auto-detects nuclei binary. Falls back gracefully if not installed.
Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""
import asyncio
import json
import shutil
from vexor.modules.base import BaseScanner, Finding
from vexor.core.tool_detector import run_tool


# Nuclei severity → Vexor severity mapping
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}

# Default template tags to run (fast, high-value)
DEFAULT_TAGS = [
    "cve",
    "misconfig",
    "exposure",
    "takeover",
    "default-login",
    "sqli",
    "xss",
    "ssrf",
    "lfi",
    "rce",
]


class Scanner(BaseScanner):
    """
    Nuclei Integration — Template-based vulnerability scanner
    Requires nuclei to be installed: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    """

    MODULE_NAME = "nuclei"
    MODULE_DESC = "Nuclei Template-Based Vulnerability Scanner"

    async def scan(self) -> list[Finding]:
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Nuclei Not Installed",
                endpoint=self.target,
                evidence="nuclei binary not found in PATH",
                description=(
                    "Nuclei is not installed. Install it for template-based scanning:\n"
                    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                    "Then run: nuclei -update-templates"
                ),
                remediation="Install nuclei and run: nuclei -update-templates",
            ))
            return self.findings

        # Update templates silently (non-blocking, best effort)
        asyncio.create_task(self._update_templates(nuclei_path))

        # Build nuclei command
        cmd = [
            nuclei_path,
            "-u", self.target,
            "-tags", ",".join(DEFAULT_TAGS),
            "-json",                    # JSON output for parsing
            "-silent",                  # No banner
            "-no-color",                # No ANSI in output
            "-timeout", str(self.timeout),
            "-rate-limit", "50",        # Requests per second
            "-bulk-size", "25",         # Templates in parallel
            "-concurrency", "10",       # Hosts in parallel
            "-retries", "1",
        ]

        stdout, stderr = await run_tool(cmd, timeout=300)  # 5 min max

        if not stdout:
            if "nuclei" in (stderr or "").lower() and "update" in (stderr or "").lower():
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="Nuclei Templates Need Update",
                    endpoint=self.target,
                    evidence="Run: nuclei -update-templates",
                    description="Nuclei templates are outdated. Update them for best results.",
                    remediation="Run: nuclei -update-templates",
                ))
            return self.findings

        # Parse JSONL output (one JSON object per line)
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                result = json.loads(line)
                finding = self._parse_nuclei_result(result)
                if finding:
                    self.add_finding(finding)
            except json.JSONDecodeError:
                continue

        return self.findings

    def _parse_nuclei_result(self, result: dict) -> Finding | None:
        """Parse a single nuclei JSON result into a Finding"""
        try:
            template_id   = result.get("template-id", "")
            template_name = result.get("info", {}).get("name", template_id)
            severity_raw  = result.get("info", {}).get("severity", "info").lower()
            severity      = SEVERITY_MAP.get(severity_raw, "INFO")

            matched_at    = result.get("matched-at", self.target)
            matcher_name  = result.get("matcher-name", "")
            extracted     = result.get("extracted-results", [])
            curl_cmd      = result.get("curl-command", "")
            description   = result.get("info", {}).get("description", "")
            remediation   = result.get("info", {}).get("remediation", "")
            tags          = result.get("info", {}).get("tags", [])
            cve_list      = [t for t in tags if t.upper().startswith("CVE-")]
            cve           = cve_list[0].upper() if cve_list else ""

            # Build evidence
            evidence_parts = []
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
            if curl_cmd:
                evidence_parts.append(f"PoC:\n{curl_cmd[:500]}")
            evidence = "\n".join(evidence_parts) if evidence_parts else f"Template: {template_id}"

            vuln_name = f"[Nuclei] {template_name}"
            if matcher_name:
                vuln_name += f" — {matcher_name}"

            return Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=vuln_name,
                endpoint=matched_at,
                evidence=evidence,
                description=description or f"Nuclei template {template_id} matched on {matched_at}",
                remediation=remediation or "Review the finding and apply appropriate fix.",
                cve=cve,
            )
        except Exception:
            return None

    async def _update_templates(self, nuclei_path: str) -> None:
        """Update nuclei templates in background (silent)"""
        try:
            await run_tool([nuclei_path, "-update-templates", "-silent"], timeout=60)
        except Exception:
            pass
