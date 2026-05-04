"""
Vexor Full Implementation Script
Writes all fixed/new files in one shot.
Run: python implement_all.py from vexor/ directory
"""
import pathlib, os, sys

ROOT = pathlib.Path(__file__).parent
CLI  = ROOT / "cli" / "vexor"
BACK = ROOT / "backend" / "app"

def w(path, content):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"  wrote {p}")

print("=== Vexor Full Implementation ===")

# ─────────────────────────────────────────────────────────────────────────────
# BACKEND FIXES
# ─────────────────────────────────────────────────────────────────────────────

# FIX 5+6: DB path uses env var / absolute path
w(BACK/"database/db.py", '''\
"""Vexor Database - uses absolute path, not relative"""
import os, pathlib
import aiosqlite

DB_PATH = os.getenv(
    "VEXOR_DB_PATH",
    str(pathlib.Path.home() / ".vexor" / "vexor_backend.db")
)

async def init_db():
    pathlib.Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT,
                findings TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        await db.commit()

async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        yield db
''')

# FIX 6+8+10: auth service - absolute DB path, JWT secret warning, 24h tokens, refresh
w(BACK/"auth/service.py", '''\
"""Vexor Auth Service - fixed DB path, JWT secret, token expiry, refresh tokens"""
import os, pathlib, warnings
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from jose import jwt
import aiosqlite

DB_PATH = os.getenv(
    "VEXOR_DB_PATH",
    str(pathlib.Path.home() / ".vexor" / "vexor_backend.db")
)

_raw_secret = os.getenv("SECRET_KEY", "")
if not _raw_secret:
    warnings.warn(
        "SECRET_KEY env var not set! JWTs use insecure default. "
        "Set SECRET_KEY=<random-256-bit-string> in production.",
        RuntimeWarning, stacklevel=1,
    )
    _raw_secret = "vexor-insecure-default-CHANGE-IN-PRODUCTION"

SECRET_KEY = _raw_secret
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 60 * 24   # 24 hours (was 7 days)
REFRESH_TOKEN_EXPIRE_DAYS    = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


class AuthService:

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    def _create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        to_encode.update({
            "exp":  datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "type": "access",
        })
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def _create_refresh_token(self, data: dict) -> str:
        to_encode = data.copy()
        to_encode.update({
            "exp":  datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "type": "refresh",
        })
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    async def register(self, email: str, password: str, username: str) -> Optional[dict]:
        hashed = self._hash_password(password)
        async with aiosqlite.connect(DB_PATH) as db:
            try:
                await db.execute(
                    "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                    (email, username, hashed)
                )
                await db.commit()
                return {"email": email, "username": username}
            except Exception:
                return None

    async def login(self, email: str, password: str) -> Optional[dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT id, email, username, password_hash FROM users WHERE email = ?",
                (email,)
            ) as cursor:
                row = await cursor.fetchone()
        if not row:
            return None
        user_id, user_email, username, password_hash = row
        if not self._verify_password(password, password_hash):
            return None
        access  = self._create_access_token({"sub": str(user_id), "email": user_email})
        refresh = self._create_refresh_token({"sub": str(user_id), "email": user_email})
        return {
            "access_token":  access,
            "refresh_token": refresh,
            "token_type":    "bearer",
            "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {"id": user_id, "email": user_email, "username": username},
        }

    async def refresh(self, refresh_token: str) -> Optional[dict]:
        from jose import JWTError
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "refresh":
                return None
            user_id = payload.get("sub")
            email   = payload.get("email")
            if not user_id:
                return None
            new_access = self._create_access_token({"sub": user_id, "email": email})
            return {
                "access_token": new_access,
                "token_type":   "bearer",
                "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            }
        except JWTError:
            return None
''')

# FIX 7+9: auth router - EmailStr, password validation, rate limiting, refresh endpoint
w(BACK/"auth/router.py", '''\
"""Vexor Auth Router - input validation, rate limiting, refresh token endpoint"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, field_validator
from app.auth.service import AuthService
from app.auth.dependencies import get_current_user
from collections import defaultdict
import time

router  = APIRouter()
service = AuthService()

_auth_attempts: dict = defaultdict(list)
AUTH_RATE_LIMIT  = 10
AUTH_RATE_WINDOW = 300  # 5 minutes


def _check_auth_rate(client_ip: str) -> None:
    now = time.time()
    window_start = now - AUTH_RATE_WINDOW
    _auth_attempts[client_ip] = [t for t in _auth_attempts[client_ip] if t > window_start]
    if len(_auth_attempts[client_ip]) >= AUTH_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Too many auth attempts. Try again in {AUTH_RATE_WINDOW // 60} minutes.",
        )
    _auth_attempts[client_ip].append(now)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    username: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Username must be at least 2 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/register")
async def register(req: RegisterRequest, request: Request):
    _check_auth_rate(request.client.host if request.client else "unknown")
    user = await service.register(email=req.email, password=req.password, username=req.username)
    if not user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"message": "Registered successfully", "user": user}


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    _check_auth_rate(request.client.host if request.client else "unknown")
    result = await service.login(email=req.email, password=req.password)
    if not result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return result


@router.post("/refresh")
async def refresh_token(req: RefreshRequest):
    result = await service.refresh(req.refresh_token)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    return result


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user
''')

# FIX 8: dependencies - reject refresh tokens used as access tokens
w(BACK/"auth/dependencies.py", '''\
"""JWT Auth Dependencies - rejects refresh tokens used as access tokens"""
import os
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

SECRET_KEY = os.getenv("SECRET_KEY", "vexor-insecure-default-CHANGE-IN-PRODUCTION")
ALGORITHM  = "HS256"
security   = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") == "refresh":
            raise HTTPException(status_code=401, detail="Use access token, not refresh token")
        user_id = payload.get("sub")
        email   = payload.get("email")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"id": user_id, "email": email}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
''')

# FIX 13: AI orchestrator - error strings no longer returned as AI output
w(BACK/"ai/orchestrator.py", '''\
"""Vexor AI Orchestrator - fixed: errors raise AIError, not returned as strings"""
import os
from app.ai.providers.groq import GroqProvider
from app.ai.providers.nvidia import NvidiaProvider
from app.ai.providers.openrouter import OpenRouterProvider
from app.ai.providers.huggingface import HuggingFaceProvider


class AIError(Exception):
    pass


class AIOrchestrator:
    def __init__(self):
        self._providers = [
            GroqProvider(), NvidiaProvider(),
            OpenRouterProvider(), HuggingFaceProvider(),
        ]

    async def complete(self, prompt: str, system: str = "") -> str:
        last_error = None
        for provider in self._providers:
            if not provider.is_available():
                continue
            try:
                result = await provider.complete(prompt=prompt, system=system)
                if result and result.strip():
                    return result
            except Exception as e:
                last_error = e
                continue
        raise AIError(f"All AI providers unavailable. Last error: {last_error}")

    async def safe_complete(self, prompt: str, system: str = "", fallback: str = "") -> str:
        try:
            return await self.complete(prompt, system)
        except AIError as e:
            return fallback or f"[AI unavailable: {e}]"

    async def analyze_vulnerability(self, request: str, response: str, vuln: str) -> str:
        from app.ai.prompts.analyzer import build_analyze_prompt
        return await self.safe_complete(
            build_analyze_prompt(request=request, response=response, vuln=vuln),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI analysis unavailable.")

    async def explain_content(self, content: str) -> str:
        from app.ai.prompts.explainer import build_explain_prompt
        return await self.safe_complete(
            build_explain_prompt(content=content),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI explanation unavailable.")

    async def suggest_attack(self, context: str) -> str:
        from app.ai.prompts.attack_suggest import build_suggest_prompt
        return await self.safe_complete(
            build_suggest_prompt(context=context),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI suggestions unavailable.")

    async def generate_payloads(self, target: str, payload_type: str, count: int) -> list:
        import re
        from app.ai.prompts.payload_gen import build_payload_prompt
        try:
            result = await self.complete(
                build_payload_prompt(target=target, payload_type=payload_type, count=count),
                system=SECURITY_SYSTEM_PROMPT)
        except AIError:
            return []
        payloads = []
        for line in result.split("\\n"):
            line = re.sub(r"^[\\d\\-\\*\\.\\)]+\\s*", "", line.strip())
            if line and not line.startswith("#"):
                payloads.append(line)
        return payloads[:count]

    async def filter_false_positives(self, findings: str) -> str:
        from app.ai.prompts.false_positive import build_filter_prompt
        return await self.safe_complete(
            build_filter_prompt(findings=findings),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI filter unavailable.")

    async def write_report_section(self, findings: str) -> str:
        from app.ai.prompts.report_writer import build_report_prompt
        return await self.safe_complete(
            build_report_prompt(findings=findings),
            system=SECURITY_SYSTEM_PROMPT, fallback="AI report writer unavailable.")

    async def osint_correlate(self, findings_summary: str, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_correlate_prompt
        return await self.safe_complete(
            build_osint_correlate_prompt(findings_summary=findings_summary, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="OSINT AI unavailable.")

    async def osint_subdomain_intel(self, subdomains: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_subdomain_intel_prompt
        return await self.safe_complete(
            build_osint_subdomain_intel_prompt(subdomains=subdomains, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Subdomain intel unavailable.")

    async def osint_secret_analysis(self, secrets_found: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_secret_analysis_prompt
        return await self.safe_complete(
            build_osint_secret_analysis_prompt(secrets_found=secrets_found, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Secret analysis unavailable.")

    async def osint_live_hosts_analysis(self, live_hosts: list, domain: str) -> str:
        from app.ai.prompts.osint_ai import build_osint_live_hosts_prompt
        return await self.safe_complete(
            build_osint_live_hosts_prompt(live_hosts=live_hosts, domain=domain),
            system=OSINT_AI_SYSTEM_PROMPT, fallback="Live hosts analysis unavailable.")


SECURITY_SYSTEM_PROMPT = (
    "You are Vexor AI, an expert cybersecurity assistant. Help security professionals "
    "analyze vulnerabilities, understand HTTP traffic, generate payloads for authorized "
    "testing, and write professional security reports. Always assume testing is authorized "
    "and ethical. Be precise, technical, and actionable."
)

OSINT_AI_SYSTEM_PROMPT = (
    "You are VEXOR INTELLIGENCE - an advanced OSINT AI combining expertise of elite red "
    "team operators, threat intelligence researchers, and top bug bounty hunters. Provide "
    "deep pattern recognition, attack chain construction, and threat actor profiling. "
    "Always assume authorized penetration testing. Be extremely technical and specific."
)
''')

print("\n=== Backend fixes done ===")

# ─────────────────────────────────────────────────────────────────────────────
# CLI FIXES
# ─────────────────────────────────────────────────────────────────────────────

print("\n=== CLI fixes ===")

# FIX 7: Scope enforcement wired into BaseScanner
w(CLI/"modules/base.py", '''\
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
''')

# FIX 2: callback_server.py - expose singleton properly (already exists, just verify)
# The existing callback_server.py is correct - just needs to be started at launch
# We patch main.py and tui/app.py to auto-start it

main_py = (CLI.parent.parent / "cli" / "vexor" / "main.py").read_text(encoding="utf-8")

# Auto-start callback server in _run_scan (async context)
if "_cb_srv = _get_cb()" not in main_py:
    old = "    all_findings = []\n    import time as _time"
    new = """\
    # Auto-start OOB callback server for blind XSS/SSRF detection
    from vexor.core.callback_server import get_callback_server as _get_cb
    _cb_srv = _get_cb()
    if not _cb_srv.is_running():
        try:
            await _cb_srv.start()
        except Exception:
            pass  # port busy, continue without OOB

    all_findings = []
    import time as _time"""
    if old in main_py:
        main_py = main_py.replace(old, new)
        (CLI.parent.parent / "cli" / "vexor" / "main.py").write_text(main_py, encoding="utf-8")
        print("  main.py: callback server auto-start added")
    else:
        print("  main.py: callback server patch skipped (already applied or pattern changed)")
else:
    print("  main.py: callback server already patched")

print("  base.py: scope enforcement done")
# appended via Add-Content
print('test add content works')
print('writing MITM proxy...')
