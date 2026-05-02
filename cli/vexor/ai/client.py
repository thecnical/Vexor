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
    Maintains conversation history for context-aware responses
    """

    def __init__(self):
        self._token = self._load_token()
        self._offline = False
        self._conversation_history: list[dict] = []   # Chat history
        self._max_history = 20   # Keep last 20 exchanges

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

    def add_to_history(self, role: str, content: str) -> None:
        """Add a message to conversation history"""
        self._conversation_history.append({"role": role, "content": content})
        # Keep only last N exchanges
        if len(self._conversation_history) > self._max_history * 2:
            self._conversation_history = self._conversation_history[-self._max_history * 2:]

    def get_history(self) -> list[dict]:
        """Get conversation history"""
        return list(self._conversation_history)

    def clear_history(self) -> None:
        """Clear conversation history"""
        self._conversation_history = []

    async def chat(self, message: str) -> str:
        """
        Send a chat message with full conversation history context.
        This is the main method for the AI Panel chat interface.
        """
        if self._offline:
            return "AI offline — connect to backend for chat"

        await self.ensure_token()

        # Add user message to history
        self.add_to_history("user", message)

        # Build context from history
        history_context = ""
        if len(self._conversation_history) > 1:
            history_lines = []
            for msg in self._conversation_history[:-1]:  # Exclude current message
                role = "User" if msg["role"] == "user" else "Vexor AI"
                history_lines.append(f"{role}: {msg['content'][:200]}")
            history_context = "\n".join(history_lines[-10:])  # Last 10 messages

        # Build prompt with history
        if history_context:
            prompt = (
                f"Previous conversation:\n{history_context}\n\n"
                f"User: {message}"
            )
        else:
            prompt = message

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/analyze",
                    json={
                        "request": prompt,
                        "response": "",
                        "vulnerability": "",
                    },
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    result = resp.json().get("result", "")
                    # Add AI response to history
                    self.add_to_history("assistant", result)
                    return result
                return "AI request failed — try again"
        except Exception as e:
            return f"AI error: {str(e)[:100]}"

    async def generate_poc(self, finding: dict) -> str:
        """
        Feature 15: AI-Generated PoC exploit script.
        Takes a finding dict and generates a working Python PoC.
        """
        if self._offline:
            return "AI offline — cannot generate PoC"

        await self.ensure_token()

        vuln     = finding.get("vuln", "")
        endpoint = finding.get("endpoint", "")
        param    = finding.get("param", "")
        payload  = finding.get("payload", "")
        evidence = finding.get("evidence", "")
        severity = finding.get("severity", "")

        prompt = f"""You are an expert penetration tester. Generate a working Python proof-of-concept exploit script for this vulnerability.

VULNERABILITY: {vuln}
SEVERITY: {severity}
ENDPOINT: {endpoint}
PARAMETER: {param}
PAYLOAD USED: {payload}
EVIDENCE: {evidence[:300]}

Requirements:
1. Write a complete, runnable Python script
2. Use only standard library + requests/httpx (no exotic deps)
3. Include clear comments explaining each step
4. Add a disclaimer at the top: "# For authorized testing only"
5. The script should:
   - Set up the target URL
   - Send the exploit payload
   - Verify the vulnerability is present
   - Print clear output showing success/failure
6. Keep it under 80 lines
7. Make it actually work — no placeholder code

Output ONLY the Python script, no explanation."""

        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    f"{API_BASE}/ai/analyze",
                    json={"request": prompt, "response": "", "vulnerability": vuln},
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return resp.json().get("result", "")
                return "PoC generation failed"
        except Exception as e:
            return f"Error: {str(e)[:100]}"

    async def health_check(self) -> bool:
        """Check if backend is reachable"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{API_BASE}/health")
                return resp.status_code == 200
        except Exception:
            return False

    async def ensure_token(self) -> bool:
        """
        Ensure we have a valid token.
        If not logged in, auto-register a guest account so AI works without manual login.
        Returns True if token is available.
        """
        if self._token:
            return True

        # Try auto guest login
        try:
            import hashlib, platform
            machine_id = hashlib.md5(platform.node().encode()).hexdigest()[:12]
            guest_email = f"guest_{machine_id}@vexor.local"
            guest_pass  = f"vexor_{machine_id}_guest"

            async with httpx.AsyncClient(timeout=15) as client:
                # Try login first
                resp = await client.post(
                    f"{API_BASE}/auth/login",
                    json={"email": guest_email, "password": guest_pass},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._token = data.get("access_token")
                    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
                    TOKEN_FILE.write_text(json.dumps({"access_token": self._token}))
                    return True

                # Register if login failed
                resp2 = await client.post(
                    f"{API_BASE}/auth/register",
                    json={
                        "email": guest_email,
                        "password": guest_pass,
                        "username": f"vexor_user_{machine_id[:6]}",
                    },
                )
                if resp2.status_code == 200:
                    # Now login
                    resp3 = await client.post(
                        f"{API_BASE}/auth/login",
                        json={"email": guest_email, "password": guest_pass},
                    )
                    if resp3.status_code == 200:
                        data = resp3.json()
                        self._token = data.get("access_token")
                        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
                        TOKEN_FILE.write_text(json.dumps({"access_token": self._token}))
                        return True
        except Exception:
            pass
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

        # Auto-get token if not logged in
        await self.ensure_token()

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
        if self._offline:
            return []

        await self.ensure_token()
        if not self._token:
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
        if self._offline:
            return {}

        await self.ensure_token()
        if not self._token:
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
