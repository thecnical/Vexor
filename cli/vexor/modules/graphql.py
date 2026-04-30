"""
Vexor GraphQL Security Scanner
Detects: Introspection, injection, batching attacks, DoS
"""
import asyncio
import json
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


GRAPHQL_ENDPOINTS = [
    '/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql',
    '/graphiql', '/playground', '/api', '/query',
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

INJECTION_QUERIES = [
    # SQLi via GraphQL
    '{ user(id: "1 OR 1=1") { id name email } }',
    '{ user(id: "1\' OR \'1\'=\'1") { id } }',
    # NoSQLi
    '{ user(id: {$gt: ""}) { id name } }',
    # SSRF via GraphQL
    '{ importData(url: "http://169.254.169.254/latest/meta-data/") { data } }',
]

BATCH_ATTACK = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
] * 10  # 30 queries in one batch


class Scanner(BaseScanner):
    """GraphQL Security Scanner"""

    MODULE_NAME = "graphql"
    MODULE_DESC = "GraphQL Security Testing"

    async def scan(self) -> list[Finding]:
        async with self:
            # Find GraphQL endpoint
            gql_url = await self._find_graphql_endpoint()

            if gql_url:
                await asyncio.gather(
                    self._test_introspection(gql_url),
                    self._test_injection(gql_url),
                    self._test_batching(gql_url),
                    self._test_depth_limit(gql_url),
                    return_exceptions=True
                )
            else:
                # Check if main endpoint is GraphQL
                await self._test_introspection(self.target)

        return self.findings

    async def _find_graphql_endpoint(self) -> str:
        """Find GraphQL endpoint"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in GRAPHQL_ENDPOINTS:
            url = base + path
            resp = await self.post(
                url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"}
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        self.add_finding(Finding(
                            severity="INFO",
                            module=self.MODULE_NAME,
                            vuln=f"GraphQL Endpoint Found: {path}",
                            endpoint=url,
                            evidence=f"GraphQL responds at {path}",
                            description="GraphQL endpoint discovered",
                            remediation="Ensure GraphQL is properly secured",
                        ))
                        return url
                except Exception:
                    pass
        return ""

    async def _test_introspection(self, url: str) -> None:
        """Test if introspection is enabled"""
        resp = await self.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"}
        )

        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
            if "__schema" in str(data) and "types" in str(data):
                # Count types
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="GraphQL Introspection Enabled",
                    endpoint=url,
                    evidence=f"Schema exposed: {len(types)} types found",
                    description=(
                        "GraphQL introspection is enabled — attackers can enumerate "
                        "all types, queries, mutations, and fields"
                    ),
                    remediation="Disable introspection in production environments",
                ))
        except Exception:
            pass

    async def _test_injection(self, url: str) -> None:
        """Test for injection vulnerabilities"""
        for query in INJECTION_QUERIES[:3]:
            resp = await self.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"}
            )
            if not resp:
                continue

            resp_text = resp.text.lower()
            # Check for SQL errors
            sql_errors = ["sql", "syntax error", "mysql", "postgresql", "sqlite"]
            if any(err in resp_text for err in sql_errors):
                self.add_finding(Finding(
                    severity="CRITICAL",
                    module=self.MODULE_NAME,
                    vuln="GraphQL SQL Injection",
                    endpoint=url,
                    payload=query[:100],
                    evidence="SQL error in GraphQL response",
                    description="SQL injection via GraphQL argument",
                    remediation="Use parameterized queries in GraphQL resolvers",
                ))
                return

    async def _test_batching(self, url: str) -> None:
        """Test for batching attack (DoS/brute force bypass)"""
        resp = await self.post(
            url,
            json=BATCH_ATTACK,
            headers={"Content-Type": "application/json"}
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln="GraphQL Batching Enabled",
                        endpoint=url,
                        evidence=f"Server processed {len(data)} batched queries",
                        description=(
                            "GraphQL batching allows sending multiple queries at once. "
                            "Can be used to bypass rate limiting for brute force attacks."
                        ),
                        remediation="Limit batch query size or disable batching",
                    ))
            except Exception:
                pass

    async def _test_depth_limit(self, url: str) -> None:
        """Test for query depth limit"""
        # Deeply nested query
        deep_query = "{ a { b { c { d { e { f { g { h { i { j { __typename } } } } } } } } } } }"
        resp = await self.post(
            url,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"}
        )

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "errors" not in data:
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln="GraphQL No Query Depth Limit",
                        endpoint=url,
                        evidence="Deeply nested query (10 levels) executed successfully",
                        description="No query depth limit — DoS via deeply nested queries possible",
                        remediation="Implement query depth limiting (max 5-7 levels)",
                    ))
            except Exception:
                pass
