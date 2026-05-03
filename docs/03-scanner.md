# Vexor Scanner — Complete Guide

The Scanner has **28 vulnerability modules** covering all major web security issues.

---

## CLI Usage

```bash
# Quick scan (7 modules: sqli, xss, headers, cors, ssl, fingerprinter, sensitive_data)
vexor scan https://target.com

# Full scan (all 28 modules)
vexor scan https://target.com --full

# Single module
vexor scan https://target.com --module sqli
vexor scan https://target.com --module xss
vexor scan https://target.com --module nuclei

# With output
vexor scan https://target.com --full --output report.html
vexor scan https://target.com --full --format pdf
vexor scan https://target.com --full --format json

# With custom threads
vexor scan https://target.com --full --threads 20

# Offline mode (no AI)
vexor scan https://target.com --full --offline
```

---

## TUI Usage

1. Press `F3` to open Scanner
2. Enter target URL in the input field
3. Choose scan type:
   - **Full Scan** — all 28 modules
   - **Quick Scan** — 7 core modules
   - **Custom Scan** — select specific modules via checkboxes
4. Click **Start OSINT** or press Enter
5. Click a finding row to see full details
6. Click **🧠 AI Analyze** for AI analysis of findings

---

## All 28 Modules

### Injection Attacks

#### `sqli` — SQL Injection
```bash
vexor scan https://target.com?id=1 --module sqli
```
**What it tests:**
- Error-based SQLi (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Time-based blind SQLi (SLEEP, WAITFOR, pg_sleep)
- Boolean-based blind SQLi
- UNION-based data extraction (column count, data dump)
- WAF bypass (comment injection, encoding, case variation)
- Stacked queries
- Second-order SQLi
- HTTP header injection (User-Agent, Referer, X-Forwarded-For)

**Example finding:**
```
CRITICAL | sqli | SQL Injection — Error-Based (MySQL)
Endpoint: https://target.com/user?id=1
Payload: ' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--
Evidence: You have an error in your SQL syntax...
```

---

#### `xss` — Cross-Site Scripting
```bash
vexor scan https://target.com --module xss
```
**What it tests:**
- Reflected XSS (context-aware: HTML/attribute/JS/URL)
- Stored XSS (submits to forms, checks retrieval pages)
- DOM XSS (source-to-sink flow analysis)
- Filter bypass (20+ techniques)
- CSP analysis and bypass vectors
- Header XSS (User-Agent, Referer)
- Blind XSS (callback server)

---

#### `lfi` — Local File Inclusion
```bash
vexor scan https://target.com?page=home --module lfi
```
**What it tests:**
- Path traversal (8 patterns × 7 depths)
- Null byte bypass (`%00`, `\x00`)
- PHP wrapper exploitation (`php://filter`)
- Log poisoning → RCE
- Remote File Inclusion (RFI)
- Windows + Linux target files

---

#### `xxe` — XML External Entity
```bash
vexor scan https://target.com/api/xml --module xxe
```
**What it tests:**
- Classic XXE (file read, SSRF, RCE via expect://)
- Blind XXE (error-based)
- SVG file upload XXE
- SOAP endpoint XXE
- All XML content types

---

#### `ssrf` — Server-Side Request Forgery
```bash
vexor scan "https://target.com?url=https://example.com" --module ssrf
```
**What it tests:**
- Cloud metadata endpoints (AWS, GCP, Azure)
- Internal network access
- Timing-based blind SSRF
- Form input SSRF (actually tests payloads)

---

#### `ssti` — Server-Side Template Injection
```bash
vexor scan https://target.com?name=test --module ssti
```
**What it tests:**
- Engine detection: Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB
- RCE via engine-specific payloads
- Blind SSTI via timing
- HTTP header injection

---

### Authentication & Authorization

#### `jwt_analyzer` — JWT Security
```bash
vexor scan https://target.com --module jwt_analyzer
```
**What it tests:**
- Algorithm none attack
- 50+ weak secrets brute-force
- RS256→HS256 confusion
- kid injection (SQL + path traversal)
- jku/x5u SSRF
- Expiry analysis
- Claim tampering

---

#### `auth_bypass` — Authentication Bypass
```bash
vexor scan https://target.com --module auth_bypass
```
**What it tests:**
- 35 admin/sensitive paths
- 20 header bypass techniques
- 20 path manipulation bypasses
- 20 default credential pairs
- Password reset host header injection
- Account enumeration
- OAuth open redirect

---

#### `idor` — Insecure Direct Object Reference
```bash
vexor scan "https://target.com/api/user?id=1" --module idor
```
**What it tests:**
- Numeric parameter enumeration with data verification
- UUID parameter testing
- API endpoint IDOR
- Path-based IDOR

---

#### `session_analyzer` — Session Security
```bash
vexor scan https://target.com --module session_analyzer
```
**What it tests:**
- Cookie flags (HttpOnly, Secure, SameSite)
- Session ID entropy
- Session fixation
- Session in URL
- Logout invalidation
- Cookie scope

---

### Web Security

#### `csrf` — Cross-Site Request Forgery
```bash
vexor scan https://target.com --module csrf
```
**What it tests:**
- CSRF token presence and strength
- Static token detection
- CSRF PoC generation
- JSON CSRF
- CORS-CSRF chain

---

#### `cors` — CORS Misconfiguration
```bash
vexor scan https://target.com --module cors
```
**What it tests:**
- Wildcard origin
- Arbitrary origin reflection
- Null origin bypass
- Credentials flag

---

#### `headers` — Security Headers
```bash
vexor scan https://target.com --module headers
```
**What it tests:**
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Referrer-Policy, Permissions-Policy
- Server/X-Powered-By version disclosure

---

#### `open_redirect` — Open Redirect
```bash
vexor scan "https://target.com?redirect=https://example.com" --module open_redirect
```
**What it tests:**
- 30+ bypass payloads
- URL/path/header/POST param redirects
- XSS via redirect (javascript: / data:)
- Meta refresh redirects

---

#### `rate_limit` — Rate Limiting
```bash
vexor scan https://target.com --module rate_limit
```
**What it tests:**
- Login endpoint rate limiting
- API rate limiting
- IP spoofing bypass (10 headers)
- Account lockout
- CAPTCHA presence

---

### Network & Infrastructure

#### `ssl_analyzer` — SSL/TLS Analysis
```bash
vexor scan https://target.com --module ssl_analyzer
```
**What it tests:**
- Certificate expiry, hostname mismatch
- Weak key size, MD5/SHA1 signature
- TLS 1.0/1.1 support
- Weak cipher suites
- HSTS configuration
- Mixed content
- OCSP stapling
- Certificate Transparency

---

#### `port_scanner` — Port Scanner
```bash
vexor scan https://target.com --module port_scanner
```
**What it tests:**
- Top 100 TCP ports
- Service detection
- Dangerous port identification

---

#### `http_smuggling` — HTTP Request Smuggling
```bash
vexor scan https://target.com --module http_smuggling
```
**What it tests:**
- CL.TE timing attack
- TE.CL timing attack
- TE.TE obfuscation (7 variants)
- Differential response confirmation
- HTTP/2 downgrade

---

### Recon & OSINT

#### `subdomain` — Subdomain Enumeration
```bash
vexor scan https://target.com --module subdomain
```
**What it tests:**
- 100+ common subdomain wordlist
- DNS resolution
- Interesting subdomain detection

---

#### `dirbuster` — Directory Discovery
```bash
vexor scan https://target.com --module dirbuster
```
**What it tests:**
- 150+ paths (admin, API, config, git, backup, debug, actuator)
- Soft-404 detection
- Content analysis for secrets
- Technology-specific paths

---

#### `wayback` — Wayback Machine
```bash
vexor scan https://target.com --module wayback
```
**What it tests:**
- Historical URL discovery
- Interesting path patterns (admin, backup, .env, .git)

---

#### `github_dork` — GitHub Dorking
```bash
vexor scan https://target.com --module github_dork
```
**What it tests:**
- Domain mentions in public code
- Leaked credentials/API keys

---

#### `sensitive_data` — Sensitive Data Exposure
```bash
vexor scan https://target.com --module sensitive_data
```
**What it tests:**
- 50+ patterns (AWS keys, GitHub tokens, Stripe, private keys, PII)
- JavaScript file scanning
- 60+ sensitive file paths
- Error page analysis
- API response scanning

---

### Advanced

#### `nuclei` — Nuclei Templates
```bash
vexor scan https://target.com --module nuclei
```
**What it tests:**
- 50,000+ community templates
- CVE detection
- Misconfiguration detection
- Exposure detection

**Requires:** `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

---

#### `graphql` — GraphQL Security
```bash
vexor scan https://target.com --module graphql
```
**What it tests:**
- Introspection, injection, batching DoS
- Depth/complexity limits, IDOR, alias overloading

---

#### `websocket` — WebSocket Security
```bash
vexor scan https://target.com --module websocket
```
**What it tests:**
- Origin validation (CSWSH)
- XSS/SQLi/SSTI injection
- Auth bypass, message flooding

---

#### `api_tester` — API Security
```bash
vexor scan https://target.com --module api_tester
```
**What it tests:**
- Endpoint discovery, HTTP methods
- Mass assignment, BOLA, CORS
- OpenAPI/Swagger parsing

---

#### `file_upload` — File Upload
```bash
vexor scan https://target.com --module file_upload
```
**What it tests:**
- 25+ bypass techniques
- PHP/JSP/ASP webshell upload
- SVG XSS, ImageTragick, polyglot

---

#### `cve_lookup` — CVE + ExploitDB
```bash
vexor scan https://target.com --module cve_lookup
```
**What it tests:**
- Technology fingerprinting
- CVE lookup via NVD API
- ExploitDB public exploit search
- GitHub PoC search

---

## Custom Scan (TUI)

1. Press `F3` → Scanner
2. Click **▶ Custom Scan**
3. Check the modules you want
4. Click **▶ Custom Scan** again

---

## AI Analysis

After any scan:
1. Click **🧠 AI Analyze** button
2. AI validates findings (true/false positive)
3. Generates exploitation paths
4. Constructs attack chains
5. Suggests immediate fixes

---

## Reports

```bash
# HTML report
vexor scan https://target.com --full --format html --output report.html

# PDF report
vexor scan https://target.com --full --format pdf --output report.pdf

# JSON export
vexor scan https://target.com --full --format json --output findings.json
```

Reports saved to: `~/.vexor/reports/`
