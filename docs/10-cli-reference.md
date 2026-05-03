# Vexor CLI Reference

Complete reference for all command-line commands.

---

## `vexor` — Launch TUI

```bash
vexor
vexor --offline          # Offline mode (no AI)
vexor --version          # Show version
vexor -v                 # Short version flag
```

---

## `vexor scan` — Vulnerability Scanner

```bash
vexor scan <URL> [OPTIONS]
```

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--module` | `-m` | None | Run specific module |
| `--full` | | False | Run all 28 modules |
| `--output` | `-o` | Auto | Output file path |
| `--format` | `-f` | html | Output format (html/pdf/json) |
| `--offline` | | False | Offline mode |
| `--threads` | `-t` | 10 | Concurrent threads |

### Examples

```bash
# Quick scan (7 modules)
vexor scan https://target.com

# Full scan (28 modules)
vexor scan https://target.com --full

# Single module
vexor scan https://target.com --module sqli
vexor scan https://target.com --module xss
vexor scan https://target.com --module lfi
vexor scan https://target.com --module xxe
vexor scan https://target.com --module ssrf
vexor scan https://target.com --module ssti
vexor scan https://target.com --module csrf
vexor scan https://target.com --module idor
vexor scan https://target.com --module jwt_analyzer
vexor scan https://target.com --module ssl_analyzer
vexor scan https://target.com --module headers
vexor scan https://target.com --module cors
vexor scan https://target.com --module auth_bypass
vexor scan https://target.com --module session_analyzer
vexor scan https://target.com --module open_redirect
vexor scan https://target.com --module rate_limit
vexor scan https://target.com --module file_upload
vexor scan https://target.com --module websocket
vexor scan https://target.com --module graphql
vexor scan https://target.com --module api_tester
vexor scan https://target.com --module http_smuggling
vexor scan https://target.com --module port_scanner
vexor scan https://target.com --module subdomain
vexor scan https://target.com --module dirbuster
vexor scan https://target.com --module wayback
vexor scan https://target.com --module github_dork
vexor scan https://target.com --module sensitive_data
vexor scan https://target.com --module cve_lookup
vexor scan https://target.com --module nuclei
vexor scan https://target.com --module osint

# Save reports
vexor scan https://target.com --full --output ~/reports/target.html
vexor scan https://target.com --full --format pdf --output ~/reports/target.pdf
vexor scan https://target.com --full --format json --output ~/reports/target.json

# Custom threads
vexor scan https://target.com --full --threads 20

# Offline mode
vexor scan https://target.com --full --offline
```

---

## `vexor proxy` — HTTP/HTTPS Proxy

```bash
vexor proxy [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 127.0.0.1 | Proxy host |
| `--port` | 8080 | Proxy port |

### Examples

```bash
# Default proxy
vexor proxy

# Custom port
vexor proxy --port 9090

# Listen on all interfaces (for mobile testing)
vexor proxy --host 0.0.0.0 --port 8080
```

---

## `vexor auth` — Authentication

```bash
vexor auth <action> [OPTIONS]
```

### Actions

| Action | Description |
|--------|-------------|
| `login` | Login to Vexor backend |
| `logout` | Logout and remove token |
| `status` | Check login status |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--email` | `-e` | Email address |
| `--password` | `-p` | Password |

### Examples

```bash
# Interactive login
vexor auth login

# Non-interactive login
vexor auth login --email user@example.com --password mypassword

# Check status
vexor auth status

# Logout
vexor auth logout
```

---

## `vexor update` — Update Vexor

```bash
vexor update
```

Pulls latest code from GitHub and reinstalls.

---

## `vexor report` — Generate Report

```bash
vexor report [OPTIONS]
```

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | html | Report format (html/pdf/json) |
| `--output` | `-o` | Auto | Output file path |

### Examples

```bash
# Generate HTML report from last scan
vexor report

# PDF report
vexor report --format pdf

# Custom output path
vexor report --format html --output ~/Desktop/report.html
```

---

## All Modules Reference

| Module | Category | Key Feature |
|--------|----------|-------------|
| `sqli` | Injection | UNION extraction, WAF bypass |
| `xss` | Injection | Context-aware, stored, DOM |
| `lfi` | Injection | PHP wrappers, log poisoning |
| `xxe` | Injection | SVG upload, SOAP, blind |
| `ssrf` | Injection | Cloud metadata, timing |
| `ssti` | Injection | RCE via Jinja2/Freemarker/etc |
| `csrf` | Auth | Token analysis, PoC generation |
| `idor` | Auth | Data leakage verification |
| `jwt_analyzer` | Auth | 50+ secrets, kid injection |
| `auth_bypass` | Auth | Headers, paths, default creds |
| `session_analyzer` | Auth | Entropy, fixation, logout |
| `cors` | Web | Wildcard, arbitrary origin |
| `headers` | Web | HSTS, CSP, X-Frame-Options |
| `open_redirect` | Web | 30+ bypass payloads |
| `rate_limit` | Web | IP bypass, lockout, CAPTCHA |
| `file_upload` | Web | 25+ bypass, RCE confirmation |
| `ssl_analyzer` | Network | Chain, HSTS, mixed content |
| `port_scanner` | Network | Top 100 ports |
| `http_smuggling` | Network | CL.TE, TE.CL, differential |
| `websocket` | Advanced | Origin, injection, flooding |
| `graphql` | Advanced | Introspection, batching, IDOR |
| `api_tester` | Advanced | Mass assignment, BOLA, CORS |
| `subdomain` | Recon | 100+ wordlist |
| `dirbuster` | Recon | 150+ paths, soft-404 |
| `wayback` | Recon | Historical URLs |
| `github_dork` | Recon | Leaked secrets |
| `sensitive_data` | Recon | 50+ patterns, JS scanning |
| `cve_lookup` | Recon | CVE + ExploitDB mapping |
| `nuclei` | Advanced | 50k+ templates |
| `osint` | OSINT | 6-phase pipeline |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (missing dependency, connection failed) |
| 2 | No findings |
