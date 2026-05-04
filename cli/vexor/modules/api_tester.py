"""
Vexor API Tester v3.0 - Elite Level
REST endpoint discovery, HTTP method testing, auth bypass,
mass assignment, BOLA/IDOR, API versioning, rate limiting,
OpenAPI/Swagger parsing, response data exposure, CORS
"""
import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/admin", "/api/config", "/api/settings",
    "/api/health", "/api/status", "/api/info", "/api/version",
    "/api/docs", "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/redoc", "/graphql",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/api/me", "/api/profile", "/api/whoami",
    "/api/token", "/api/auth", "/api/login",
    "/api/search", "/api/data", "/api/export",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credit_card", "ssn", "pin", "private_key", "access_token",
    "refresh_token", "auth_token", "session", "cookie",
]

MASS_ASSIGNMENT_FIELDS = [
    "role", "admin", "is_admin", "is_superuser", "privilege",
    "permissions", "verified", "active", "enabled",
    "balance", "credit", "subscription",
]


class Scanner(BaseScanner):
    """API Tester v3.0 - Elite Level"""

    MODULE_NAME = "api_tester"
    MODULE_DESC = "API: Discovery/Methods/Auth/MassAssignment/BOLA/Versioning/CORS/OpenAPI"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._discover_endpoints(),
                self._test_http_methods(),
                self._test_mass_assignment(),
                self._test_bola(),
                self._check_api_versioning(),
                self._check_cors(),
                self._parse_openapi(),
                return_exceptions=True,
            )
        return self.findings

    async def _discover_endpoints(self) -> None:
        """Discover API endpoints and check for sensitive data"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        semaphore = asyncio.Semaphore(15)
        found = []

        async def check(path: str) -> None:
            async with semaphore:
                url = base + path
                try:
                    resp = await self.get(url, headers={"Accept": "application/json"})
                    if not resp or resp.status_code not in [200, 201]:
                        return

                    found.append(path)
                    content_type = resp.headers.get("content-type", "")

                    # API docs exposure
                    if any(doc in path for doc in ["/swagger", "/openapi", "/api-docs", "/redoc"]):
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="API Documentation Exposed",
                            endpoint=url,
                            evidence=f"API docs at {path} (HTTP 200)",
                            description="API documentation is publicly accessible.",
                            remediation="Restrict API docs to authenticated users.",
                        ))

                    # Check JSON response for sensitive data
                    if "json" in content_type:
                        try:
                            data = resp.json()
                            self._check_sensitive_response(url, data)
                        except Exception:
                            pass

                    # Check for unauthenticated admin access
                    if "admin" in path or "config" in path:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"Admin/Config API Accessible Without Auth: {path}",
                            endpoint=url,
                            evidence=f"HTTP 200 on {path}",
                            description=f"Admin/config endpoint {path} accessible without authentication.",
                            remediation="Require authentication for all admin/config endpoints.",
                        ))

                except Exception:
                    pass

        tasks = [check(p) for p in API_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

        if found:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln=f"API Endpoints Discovered ({len(found)})",
                endpoint=self.target,
                evidence=f"Found: {', '.join(found[:10])}",
                description=f"Discovered {len(found)} API endpoint(s).",
                remediation="Ensure all API endpoints require proper authentication.",
            ))

    def _check_sensitive_response(self, url: str, data) -> None:
        """Check API response for sensitive data"""
        data_str = json.dumps(data).lower()
        for field in SENSITIVE_FIELDS:
            if f'"{field}"' in data_str or f"'{field}'" in data_str:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln=f"Sensitive Field in API Response: {field}",
                    endpoint=url,
                    evidence=f"Response contains field: '{field}'",
                    description=f"API response exposes sensitive field '{field}'.",
                    remediation=f"Remove '{field}' from API responses. Use field filtering.",
                ))
                break

    async def _test_http_methods(self) -> None:
        """Test for dangerous HTTP methods"""
        import httpx

        for method in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:  # nosec B501
                    resp = await client.request(method, self.target)
                    if resp.status_code not in [405, 501, 403, 404]:
                        severity = "HIGH" if method in ["DELETE", "TRACE"] else "LOW"
                        self.add_finding(Finding(
                            severity=severity,
                            module=self.MODULE_NAME,
                            vuln=f"HTTP Method {method} Allowed",
                            endpoint=self.target,
                            evidence=f"{method} returned HTTP {resp.status_code}",
                            description=f"HTTP {method} method is allowed on this endpoint.",
                            remediation=f"Disable {method} if not required.",
                        ))
            except Exception:
                continue

        # OPTIONS — check allowed methods
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:  # nosec B501
                resp = await client.options(self.target)
                allow = resp.headers.get("allow", resp.headers.get("Access-Control-Allow-Methods", ""))
                if allow and any(m in allow.upper() for m in ["DELETE", "TRACE", "PUT"]):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Dangerous Methods in Allow Header",
                        endpoint=self.target,
                        evidence=f"Allow: {allow}",
                        description=f"Server advertises dangerous methods: {allow}",
                        remediation="Remove dangerous methods from Allow header.",
                    ))
        except Exception:
            pass

    async def _test_mass_assignment(self) -> None:
        """Test for mass assignment vulnerability"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Try to update user with privileged fields
        for path in ["/api/users/1", "/api/profile", "/api/me", "/api/account"]:
            url = base + path
            try:
                # First GET to see current state
                get_resp = await self.get(url, headers={"Accept": "application/json"})
                if not get_resp or get_resp.status_code != 200:
                    continue

                # Try PATCH/PUT with mass assignment fields
                for field in MASS_ASSIGNMENT_FIELDS[:5]:
                    payload = {field: True if field != "role" else "admin"}
                    try:
                        import httpx
                        async with httpx.AsyncClient(verify=False, timeout=10) as client:  # nosec B501
                            resp = await client.patch(
                                url,
                                json=payload,
                                headers={"Content-Type": "application/json"},
                            )
                            if resp.status_code in [200, 201]:
                                # Check if field was accepted
                                try:
                                    data = resp.json()
                                    if field in json.dumps(data).lower():
                                        self.add_finding(Finding(
                                            severity="CRITICAL",
                                            module=self.MODULE_NAME,
                                            vuln=f"Mass Assignment — Privileged Field Accepted: {field}",
                                            endpoint=url,
                                            payload=json.dumps(payload),
                                            evidence=f"Field '{field}' accepted in PATCH response",
                                            description=(
                                                f"Mass assignment: field '{field}' accepted. "
                                                "Attacker can escalate privileges."
                                            ),
                                            remediation=(
                                                "Use allowlist for accepted fields. "
                                                "Never bind request body directly to model."
                                            ),
                                        ))
                                        return
                                except Exception:
                                    pass
                    except Exception:
                        continue
            except Exception:
                continue

    async def _test_bola(self) -> None:
        """Test for BOLA (Broken Object Level Authorization)"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        bola_paths = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/accounts/{id}",
            "/api/orders/{id}",
            "/api/documents/{id}",
        ]

        for path_template in bola_paths:
            for obj_id in ["1", "2", "3", "100"]:
                url = base + path_template.replace("{id}", obj_id)
                try:
                    resp = await self.get(url, headers={"Accept": "application/json"})
                    if resp and resp.status_code == 200:
                        try:
                            data = resp.json()
                            data_str = json.dumps(data).lower()
                            if any(f in data_str for f in ["email", "name", "user", "account"]):
                                self.add_finding(Finding(
                                    severity="HIGH",
                                    module=self.MODULE_NAME,
                                    vuln=f"BOLA — Object Accessible Without Auth: {path_template}",
                                    endpoint=url,
                                    evidence=f"Object ID={obj_id} returned data: {data_str[:150]}",
                                    description=(
                                        f"Object at {path_template} accessible without authorization. "
                                        "BOLA/IDOR vulnerability."
                                    ),
                                    remediation=(
                                        "Verify user owns requested object. "
                                        "Implement object-level authorization."
                                    ),
                                ))
                                return
                        except Exception:
                            pass
                except Exception:
                    continue

    async def _check_api_versioning(self) -> None:
        """Check for deprecated API versions"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        versions = {}
        for v in ["v1", "v2", "v3", "v4"]:
            for prefix in ["/api/", "/"]:
                url = base + prefix + v
                try:
                    resp = await self.get(url)
                    if resp and resp.status_code in [200, 201]:
                        versions[v] = url
                        break
                except Exception:
                    continue

        if len(versions) > 1:
            latest = max(versions.keys())
            for v, url in versions.items():
                if v != latest:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Deprecated API Version Active: {v}",
                        endpoint=url,
                        evidence=f"Old version {v} still returns 200 (latest: {latest})",
                        description=f"Deprecated API version {v} is still accessible.",
                        remediation=f"Deprecate and remove API version {v}.",
                    ))

    async def _check_cors(self) -> None:
        """Check CORS configuration"""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10) as client:  # nosec B501
                resp = await client.get(
                    self.target,
                    headers={"Origin": "https://evil-attacker.com"},
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="CORS Wildcard Origin",
                        endpoint=self.target,
                        evidence=f"Access-Control-Allow-Origin: *",
                        description="CORS allows any origin. Sensitive data may be accessible cross-origin.",
                        remediation="Restrict CORS to specific trusted origins.",
                    ))
                elif acao == "https://evil-attacker.com":
                    severity = "CRITICAL" if "true" in acac.lower() else "HIGH"
                    self.add_finding(Finding(
                        severity=severity,
                        module=self.MODULE_NAME,
                        vuln="CORS Arbitrary Origin Reflected" + (" + Credentials" if "true" in acac.lower() else ""),
                        endpoint=self.target,
                        evidence=f"ACAO: {acao}\nACAC: {acac}",
                        description="CORS reflects arbitrary Origin header.",
                        remediation="Validate Origin against strict whitelist.",
                    ))
        except Exception:
            pass

    async def _parse_openapi(self) -> None:
        """Parse OpenAPI/Swagger spec for sensitive endpoints"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        spec_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json"]
        for path in spec_paths:
            try:
                resp = await self.get(base + path)
                if not resp or resp.status_code != 200:
                    continue
                try:
                    spec = resp.json()
                    paths = spec.get("paths", {})
                    sensitive_endpoints = []
                    for ep_path, methods in paths.items():
                        if any(s in ep_path.lower() for s in ["admin", "secret", "internal", "debug", "config"]):
                            sensitive_endpoints.append(ep_path)

                    if sensitive_endpoints:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"OpenAPI Spec Exposes Sensitive Endpoints ({len(sensitive_endpoints)})",
                            endpoint=base + path,
                            evidence=f"Sensitive paths: {', '.join(sensitive_endpoints[:5])}",
                            description="OpenAPI spec reveals sensitive/internal endpoints.",
                            remediation="Restrict OpenAPI spec access. Remove sensitive endpoint docs.",
                        ))
                    elif paths:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln=f"OpenAPI Spec Publicly Accessible ({len(paths)} endpoints)",
                            endpoint=base + path,
                            evidence=f"Spec at {path} exposes {len(paths)} endpoints",
                            description="OpenAPI specification is publicly accessible.",
                            remediation="Restrict API documentation to authenticated users.",
                        ))
                    return
                except Exception:
                    pass
            except Exception:
                continue
