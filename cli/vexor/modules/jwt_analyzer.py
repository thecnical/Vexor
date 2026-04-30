"""
Vexor JWT Analyzer
JWT Token Analysis and Attack Detection
"""
import asyncio
import base64
import json
import re
import hmac
import hashlib
from vexor.modules.base import BaseScanner, Finding


WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "jwt_secret", "your-secret", "change-me", "test",
    "supersecret", "mysecret", "jwtkey", "secret123",
    "", "null", "undefined", "jwt", "token",
]


class Scanner(BaseScanner):
    """JWT Token Analyzer"""

    MODULE_NAME = "jwt_analyzer"
    MODULE_DESC = "JWT Token Security Analysis"

    async def scan(self) -> list[Finding]:
        async with self:
            # Get JWT tokens from response
            response = await self.get(self.target)
            if not response:
                return self.findings

            tokens = self._extract_jwts(response)

            for token in tokens:
                await self._analyze_jwt(token)

        return self.findings

    def _extract_jwts(self, response) -> list[str]:
        """Extract JWT tokens from response headers and body"""
        tokens = []
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        )

        # Check headers
        for header_name, header_val in response.headers.items():
            matches = jwt_pattern.findall(header_val)
            tokens.extend(matches)

        # Check body
        matches = jwt_pattern.findall(response.text)
        tokens.extend(matches)

        return list(set(tokens))

    async def _analyze_jwt(self, token: str) -> None:
        """Analyze a JWT token for vulnerabilities"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            # Decode header and payload
            header = self._decode_part(parts[0])
            payload = self._decode_part(parts[1])

            if not header or not payload:
                return

            # Check algorithm
            alg = header.get('alg', '').upper()

            # None algorithm attack
            if alg == 'NONE' or alg == '':
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="JWT Algorithm None Attack",
                    endpoint=self.target,
                    evidence=f"JWT uses 'none' algorithm: {token[:50]}...",
                    description="JWT accepts 'none' algorithm — signature bypass possible",
                    remediation="Reject JWTs with 'none' algorithm. Always verify signature.",
                ))

            # Weak algorithm
            if alg in ['HS256', 'HS384', 'HS512']:
                await self._test_weak_secret(token, parts, alg)

            # RS256 to HS256 confusion
            if alg in ['RS256', 'RS384', 'RS512']:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="JWT RSA Algorithm — Test for Confusion Attack",
                    endpoint=self.target,
                    evidence=f"JWT uses {alg} — test RS256→HS256 confusion",
                    description="RSA-signed JWT may be vulnerable to algorithm confusion",
                    remediation="Explicitly specify allowed algorithms in JWT verification",
                ))

            # Check expiry
            exp = payload.get('exp')
            if not exp:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="JWT Missing Expiration",
                    endpoint=self.target,
                    evidence=f"JWT payload has no 'exp' claim",
                    description="JWT token never expires — session cannot be invalidated",
                    remediation="Always set expiration time in JWT tokens",
                ))

            # Check sensitive data in payload
            sensitive_keys = ['password', 'secret', 'key', 'token', 'credit', 'ssn', 'pin']
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="Sensitive Data in JWT Payload",
                        endpoint=self.target,
                        evidence=f"JWT payload contains sensitive key: '{key}'",
                        description="JWT payload contains potentially sensitive information",
                        remediation="Never store sensitive data in JWT payload — it is base64 encoded, not encrypted",
                    ))

        except Exception:
            pass

    async def _test_weak_secret(self, token: str, parts: list, alg: str) -> None:
        """Test for weak HMAC secret"""
        header_payload = f"{parts[0]}.{parts[1]}"
        original_sig = self._base64url_decode(parts[2])

        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            try:
                # Python hmac: hmac.new(key, msg, digestmod)
                h = hmac.new(
                    key=secret.encode(),
                    msg=header_payload.encode(),
                    digestmod=hash_func
                )
                computed = h.digest()

                if hmac.compare_digest(computed, original_sig):
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="JWT Weak Secret Key",
                        endpoint=self.target,
                        evidence=f"JWT signed with weak secret: '{secret}'",
                        description=f"JWT HMAC secret is weak: '{secret}'",
                        remediation=(
                            "Use a strong random secret (min 256 bits). "
                            "Rotate the secret immediately."
                        ),
                    ))
                    return
            except Exception:
                continue

    def _decode_part(self, part: str) -> dict:
        try:
            padded = part + '=' * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return {}

    def _base64url_decode(self, s: str) -> bytes:
        padded = s + '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(padded)
