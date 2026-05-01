"""
Vexor AI Client
Communicates with Vexor backend for AI analysis
Falls back to offline mode gracefully
"""
import httpx
import asyncio
from typing import Optional
from vexor.config import API_BASE, TOKEN_FILE
import json


class AIClient:
    """
    Vexor AI Client
    Sends requests to backend which handles all AI providers
    """

    def __init__(self):
        self._token = self._load_token()
        self._offline = False

    def _load_token(self) -> Optional[str]:
        """Load auth token from disk"""
        try:
            if TOKEN_FILE.exists():
                data = json.loads(TOKEN_FILE.read_text())
                return data.get("access_token")
        except Exception:
            pass
        return None

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def health_check(self) -> bool:
        """Check if backend is reachable"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{API_BASE}/health")
                return resp.status_code == 200
        except Exception:
            return False

    async def analyze(
        self,
        request: str = "",
        response: str = "",
        vulnerability: str = ""
    ) -> str:
        """Analyze vulnerability or request/response"""
        if self._offline:
            return self._offline_analyze(request, response, vulnerability)

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/analyze",
                    json={
                        "request": request,
                        "response": response,
                        "vulnerability": vulnerability,
                    },
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "No analysis available")
                return self._offline_analyze(request, response, vulnerability)
        except Exception:
            self._offline = True
            return self._offline_analyze(request, response, vulnerability)

    async def explain(self, content: str) -> str:
        """Explain HTTP content from security perspective"""
        if self._offline:
            return "AI offline — manual analysis required"

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/explain",
                    json={"content": content},
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return "Could not get AI explanation"
        except Exception:
            return "AI offline — manual analysis required"

    async def suggest_attack(self, context: str) -> str:
        """Suggest next attack steps"""
        if self._offline:
            return "AI offline — refer to OWASP testing guide"

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/suggest",
                    json={"context": context},
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return "Could not get suggestions"
        except Exception:
            return "AI offline"

    async def generate_payloads(
        self,
        target: str = "",
        payload_type: str = "general",
        count: int = 20
    ) -> list[str]:
        """Generate AI-powered payloads"""
        if self._offline:
            return self._offline_payloads(payload_type)

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/payload",
                    json={
                        "target": target,
                        "payload_type": payload_type,
                        "count": count,
                    },
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("payloads", [])
                return self._offline_payloads(payload_type)
        except Exception:
            return self._offline_payloads(payload_type)

    async def filter_false_positives(self, findings: str) -> str:
        """Filter false positives from findings"""
        if self._offline:
            return "AI offline — manual review required"

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/filter",
                    json={"findings": findings},
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return findings
        except Exception:
            return "AI offline"

    async def write_report_section(self, findings: str) -> str:
        """Write professional report section"""
        if self._offline:
            return "AI offline — manual report writing required"

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/report",
                    json={"findings": findings},
                    headers=self._headers()
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return "Could not generate report section"
        except Exception:
            return "AI offline"

    async def osint_scan(self, target: str, modules: list[str] = []) -> list[dict]:
        """
        Run backend-proxied OSINT modules (Shodan, VT, OTX, URLScan, Chaos).
        Returns list of finding dicts. Empty list if offline or no token.
        """
        if self._offline or not self._token:
            return []

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/osint/scan",
                    json={"target": target, "modules": modules},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("findings", [])
                return []
        except Exception:
            return []

    async def osint_status(self) -> dict:
        """
        Check which backend OSINT modules are available (keys configured on Render).
        Returns dict like: {"shodan": True, "virustotal": False, ...}
        """
        if self._offline or not self._token:
            return {}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{API_BASE}/osint/status",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json()
                return {}
        except Exception:
            return {}

    async def osint_ai_correlate(self, domain: str, findings_summary: str) -> str:
        """
        Master OSINT AI — attack chains, threat profile, prioritized actions.
        Returns markdown-formatted intelligence report.
        """
        if self._offline or not self._token:
            return ""
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{API_BASE}/osint/ai/correlate",
                    json={"domain": domain, "findings_summary": findings_summary},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return ""
        except Exception:
            return ""

    async def osint_ai_subdomain_intel(self, domain: str, subdomains: list) -> str:
        """AI analysis of subdomain list for attack vectors"""
        if self._offline or not self._token:
            return ""
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    f"{API_BASE}/osint/ai/subdomain-intel",
                    json={"domain": domain, "subdomains": subdomains},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return ""
        except Exception:
            return ""

    async def osint_ai_secret_analysis(self, domain: str, secrets: list) -> str:
        """AI deep analysis of leaked secrets"""
        if self._offline or not self._token:
            return ""
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    f"{API_BASE}/osint/ai/secret-analysis",
                    json={"domain": domain, "secrets": secrets},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return ""
        except Exception:
            return ""

    async def osint_ai_live_hosts(self, domain: str, live_hosts: list) -> str:
        """AI attack surface analysis of live hosts"""
        if self._offline or not self._token:
            return ""
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    f"{API_BASE}/osint/ai/live-hosts",
                    json={"domain": domain, "live_hosts": live_hosts},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return ""
        except Exception:
            return ""

    def _offline_analyze(self, request: str, response: str, vuln: str) -> str:
        """Basic offline analysis"""
        notes = []
        if "sql" in vuln.lower() or "sqli" in vuln.lower():
            notes.append("SQL Injection: Use parameterized queries")
        if "xss" in vuln.lower():
            notes.append("XSS: Encode output, implement CSP")
        if "csrf" in vuln.lower():
            notes.append("CSRF: Implement CSRF tokens")
        if not notes:
            notes.append("Review OWASP Top 10 for remediation guidance")
        return "\n".join(notes) + "\n\n[Offline mode — connect to Vexor backend for full AI analysis]"

    def _offline_payloads(self, payload_type: str) -> list[str]:
        """Return built-in payloads when offline"""
        from vexor.config import PAYLOADS_DIR
        payload_file = PAYLOADS_DIR / f"{payload_type}.txt"
        if payload_file.exists():
            return [
                line.strip()
                for line in payload_file.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ][:20]
        return ["' OR 1=1--", "<script>alert(1)</script>", "../../../etc/passwd"]
