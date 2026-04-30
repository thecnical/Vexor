"""
Vexor API Security Tester
REST and GraphQL API Testing
"""
import asyncio
import json
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


COMMON_API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/api/users', '/api/user', '/api/accounts',
    '/api/admin', '/api/config', '/api/settings',
    '/api/health', '/api/status', '/api/info',
    '/api/docs', '/swagger', '/swagger.json',
    '/swagger/v1/swagger.json', '/openapi.json',
    '/api-docs', '/redoc', '/graphql',
    '/v1', '/v2', '/v3',
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
"""


class Scanner(BaseScanner):
    """API Security Tester"""

    MODULE_NAME = "api_tester"
    MODULE_DESC = "REST/GraphQL API Security Testing"

    async def scan(self) -> list[Finding]:
        async with self:
            await asyncio.gather(
                self._discover_api_endpoints(),
                self._test_graphql(),
                self._check_api_versioning(),
                self._test_http_methods(),
                return_exceptions=True
            )
        return self.findings

    async def _discover_api_endpoints(self) -> None:
        """Discover API endpoints"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_apis = []
        tasks = []
        for path in COMMON_API_PATHS:
            tasks.append(self._check_api_path(base, path, found_apis))

        await asyncio.gather(*tasks, return_exceptions=True)

        if found_apis:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="API Endpoints Discovered",
                endpoint=self.target,
                evidence=f"Found: {', '.join(found_apis[:10])}",
                description=f"Discovered {len(found_apis)} API endpoint(s)",
                remediation="Ensure all API endpoints require proper authentication",
            ))

    async def _check_api_path(self, base: str, path: str, found: list) -> None:
        url = base + path
        resp = await self.get(url)
        if resp and resp.status_code in [200, 201]:
            found.append(path)

            # Check for sensitive data in API response
            try:
                data = resp.json()
                self._check_sensitive_api_data(url, data)
            except Exception:
                pass

            # Check for API docs exposure
            if any(doc in path for doc in ['/swagger', '/openapi', '/api-docs', '/redoc']):
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="API Documentation Exposed",
                    endpoint=url,
                    evidence=f"API docs accessible at {path}",
                    description="API documentation is publicly accessible",
                    remediation="Restrict API documentation to authenticated users",
                ))

    def _check_sensitive_api_data(self, url: str, data) -> None:
        """Check API response for sensitive data"""
        sensitive_keys = [
            'password', 'secret', 'token', 'key', 'api_key',
            'credit_card', 'ssn', 'pin', 'private_key',
        ]
        data_str = json.dumps(data).lower()
        for key in sensitive_keys:
            if key in data_str:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Sensitive Data in API Response",
                    endpoint=url,
                    evidence=f"API response contains sensitive key: '{key}'",
                    description=f"API exposes sensitive field: '{key}'",
                    remediation="Remove sensitive fields from API responses",
                ))
                break

    async def _test_graphql(self) -> None:
        """Test GraphQL endpoint"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        graphql_url = base + "/graphql"

        # Test introspection
        resp = await self.post(
            graphql_url,
            json={"query": GRAPHQL_INTROSPECTION},
            headers={"Content-Type": "application/json"}
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if '__schema' in str(data):
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="GraphQL Introspection Enabled",
                        endpoint=graphql_url,
                        evidence="GraphQL schema exposed via introspection",
                        description=(
                            "GraphQL introspection is enabled — "
                            "attackers can enumerate all types and fields"
                        ),
                        remediation="Disable introspection in production",
                    ))
            except Exception:
                pass

    async def _check_api_versioning(self) -> None:
        """Check for old API versions"""
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        old_versions = ['/api/v1', '/api/v2']
        current_version = None

        for version in ['/api/v3', '/api/v2', '/api/v1']:
            resp = await self.get(base + version)
            if resp and resp.status_code == 200:
                current_version = version
                break

        if current_version:
            # Check if older versions still work
            for version in old_versions:
                if version == current_version:
                    continue
                resp = await self.get(base + version)
                if resp and resp.status_code == 200:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="Old API Version Still Active",
                        endpoint=base + version,
                        evidence=f"Old version {version} still returns 200",
                        description=f"Old API version {version} is still accessible",
                        remediation="Deprecate and remove old API versions",
                    ))

    async def _test_http_methods(self) -> None:
        """Test for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']

        for method in dangerous_methods:
            try:
                import httpx
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.request(method, self.target)
                    if resp.status_code not in [405, 501, 403]:
                        self.add_finding(Finding(
                            severity="LOW",
                            module=self.MODULE_NAME,
                            vuln=f"HTTP Method {method} Allowed",
                            endpoint=self.target,
                            evidence=f"{method} returned {resp.status_code}",
                            description=f"HTTP {method} method is allowed",
                            remediation=f"Disable {method} method if not needed",
                        ))
            except Exception:
                pass
