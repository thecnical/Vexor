<div align="center">

```
██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# VEXOR — AI-Powered CLI Security Toolkit

### The Free, Open-Source Alternative to Burp Suite Pro

*Penetrate. Analyze. Dominate.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Kali%20Linux-Native-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-00D26A?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0.0-00FFFF?style=for-the-badge)](https://github.com/thecnical/Vexor/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/thecnical/Vexor/ci.yml?style=for-the-badge&label=CI)](https://github.com/thecnical/Vexor/actions)

> **Vexor** is a free, AI-powered CLI security toolkit built for penetration testers, bug bounty hunters, and red teamers.  
> Runs entirely in your terminal. No Java. No GUI. No $475/year license.

</div>

---

## Why Vexor?

| Feature | Burp Community | Burp Pro ($475/yr) | **Vexor v4 (Free)** |
|:--------|:---:|:---:|:---:|
| Automated Vulnerability Scanner | ❌ | ✅ | ✅ **28 modules** |
| AI Analysis & Payload Generation | ❌ | ❌ | ✅ **Unlimited** |
| OSINT Intelligence Engine | ❌ | ❌ | ✅ **6-Phase** |
| Nuclei Template Scanning | ❌ | ❌ | ✅ **50k+ templates** |
| CVE + ExploitDB Auto-Mapping | ❌ | ❌ | ✅ |
| AI-Generated PoC Exploits | ❌ | ❌ | ✅ |
| Blind XSS/SSRF Callback Server | ❌ | ✅ Collaborator | ✅ **Built-in** |
| Subdomain Takeover Detection | ❌ | ❌ | ✅ **27 services** |
| Cloud Sync + Team Collaboration | ❌ | ❌ | ✅ |
| Scan Session Persistence | ❌ | ✅ | ✅ **SQLite** |
| Intruder (unlimited speed) | ❌ Throttled | ✅ | ✅ **50 parallel** |
| SecLists Auto-Download | ❌ | ❌ | ✅ |
| Screenshot Visual Recon | ❌ | ❌ | ✅ Playwright |
| Scope Management | ❌ | ✅ | ✅ |
| Workspace / Project System | ❌ | ✅ | ✅ |
| Notes Panel | ❌ | ❌ | ✅ |
| CLI Native (no Java/GUI) | ❌ | ❌ | ✅ |
| **Price** | Free | **$475/year** | **🆓 Free Forever** |

---

## Mind Map

```
                        ┌─────────────────────────────────────────────────────┐
                        │                    V E X O R                        │
                        │          AI-Powered CLI Security Toolkit            │
                        └──────────────────────┬──────────────────────────────┘
                                               │
          ┌────────────────────────────────────┼────────────────────────────────────┐
          │                                    │                                    │
   ┌──────▼──────┐                    ┌────────▼────────┐                  ┌────────▼────────┐
   │  SCANNER    │                    │  INTELLIGENCE   │                  │   AI ENGINE     │
   │  28 Modules │                    │  OSINT v4       │                  │  Multi-Provider │
   └──────┬──────┘                    └────────┬────────┘                  └────────┬────────┘
          │                                    │                                    │
   ┌──────┴──────────────┐           ┌─────────┴──────────┐              ┌─────────┴──────────┐
   │ Injection           │           │ Phase 1: Discovery  │              │ Groq (fastest)     │
   │  · SQLi (5 DBs)     │           │  DNS · CT · WHOIS   │              │ NVIDIA NIM         │
   │  · XSS (3 types)    │           │  ASN · Passive Subs │              │ OpenRouter         │
   │  · XXE · LFI · SSTI │           ├─────────────────────┤              │ HuggingFace        │
   ├─────────────────────┤           │ Phase 2: Live Check │              ├────────────────────┤
   │ Auth & Session      │           │  httpx async check  │              │ Features:          │
   │  · JWT Analyzer     │           ├─────────────────────┤              │ · Analyze vulns    │
   │  · Auth Bypass      │           │ Phase 3: Deep Recon │              │ · Auto Exploit     │
   │  · Session Analyzer │           │  Ports · SSL · Tech │              │ · Generate PoC     │
   ├─────────────────────┤           │  Wayback · Crawl    │              │ · CVSS Scoring     │
   │ Network & Infra     │           ├─────────────────────┤              │ · Smart Payloads   │
   │  · Port Scanner     │           │ Phase 4: Secrets    │              │ · False Pos Filter │
   │  · SSL Analyzer     │           │  API keys · JWT     │              │ · Report Writer    │
   │  · HTTP Smuggling   │           │  SQLi params · SSRF │              │ · Translate (10x)  │
   │  · Cache Poisoning  │           ├─────────────────────┤              │ · Chat History     │
   ├─────────────────────┤           │ Phase 5: Threat Intel│             └────────────────────┘
   │ Web Vulnerabilities │           │  Shodan · VT · OTX  │
   │  · CSRF · CORS      │           │  URLScan · Chaos DB │
   │  · Open Redirect    │           ├─────────────────────┤
   │  · File Upload      │           │ Phase 6: AI Correlate│
   │  · SSRF · IDOR      │           │  Attack chains      │
   ├─────────────────────┤           │  Threat profiling   │
   │ Advanced            │           │  PoC generation     │
   │  · Nuclei (50k+)    │           └─────────────────────┘
   │  · Blind XSS/SSRF   │
   │  · CVE + ExploitDB  │
   │  · Screenshot       │
   └─────────────────────┘

          ┌────────────────────────────────────────────────────────────────────┐
          │                         TUI SCREENS (13)                           │
          ├──────────┬──────────┬──────────┬──────────┬──────────┬────────────┤
          │Dashboard │  Proxy   │ Scanner  │ Intruder │ Repeater │  AI Panel  │
          │   F1     │   F2     │   F3     │   F4     │   F5     │    F6      │
          ├──────────┼──────────┼──────────┼──────────┼──────────┼────────────┤
          │ Reports  │ Decoder  │ Comparer │  OSINT   │  Config  │  Plugins   │
          │   F7     │   F8     │   F9     │   F10    │    `     │    F12     │
          ├──────────┴──────────┴──────────┴──────────┴──────────┴────────────┤
          │                    Notes (Ctrl+N)                                  │
          └────────────────────────────────────────────────────────────────────┘

          ┌────────────────────────────────────────────────────────────────────┐
          │                      CORE SYSTEMS                                  │
          ├─────────────┬──────────────┬─────────────┬──────────┬─────────────┤
          │  SQLite DB  │  Workspace   │   Scope     │ Callback │   Cloud     │
          │  Persistence│  Projects   │  Management │  Server  │   Sync      │
          │  Sessions   │  Per-target │  scope.txt  │ OOB XSS  │  Team Collab│
          └─────────────┴──────────────┴─────────────┴──────────┴─────────────┘
```

---

## Installation

### One-Line Install (Kali Linux / Debian / Ubuntu)

```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### Step by Step

```bash
git clone https://github.com/thecnical/Vexor
cd Vexor
./install.sh
```

### WSL / Windows Users

```powershell
# PowerShell (Admin) — install Kali Linux
wsl --install -d kali-linux
```

Then inside Kali:
```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### Update

```bash
cd ~/Vexor && git pull && ./install.sh
```

### Optional: Go Tools (for full OSINT power)

The installer auto-installs these if Go is present:

```bash
# Install Go: https://go.dev/dl/
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## Usage

### Launch TUI

```bash
vexor
```

### TUI Navigation

| Key | Screen | Description |
|-----|--------|-------------|
| `F1` | Dashboard | Live stats, recent findings, quick start |
| `F2` | Proxy | HTTP/HTTPS interceptor with match & replace |
| `F3` | Scanner | 28 vulnerability modules, custom scan |
| `F4` | Intruder | 50 parallel requests, SecLists integration |
| `F5` | Repeater | Manual request editor → Send to Scanner |
| `F6` | AI Panel | 9 AI actions, chat history, PoC generator |
| `F7` | Reports | 5 templates: Full, Executive, Bug Bounty, Pentest, OSINT |
| `F8` | Decoder | Base64, URL, Hex, JWT, HTML, ROT13 |
| `F9` | Comparer | Diff two requests/responses |
| `F10` | OSINT | 6-phase intelligence engine |
| `` ` `` | Config | Login, backend URL, scan settings |
| `F12` | Plugins | Plugin manager |
| `Ctrl+N` | Notes | Persistent pentest notes |
| `Ctrl+H` | Help | Keyboard shortcuts |
| `Ctrl+O` | Offline | Toggle offline mode |
| `Ctrl+Q` | Quit | Exit Vexor |

### CLI Commands

```bash
# Launch TUI
vexor

# Scan
vexor scan https://target.com                    # Quick scan (7 modules)
vexor scan https://target.com --full             # Full scan (28 modules)
vexor scan https://target.com --module sqli      # Single module
vexor scan https://target.com --module nuclei    # Nuclei templates
vexor scan https://target.com --full --format pdf  # PDF report

# Proxy
vexor proxy                    # Start on 127.0.0.1:8080
vexor proxy --port 9090        # Custom port

# Auth
vexor auth login               # Login (enables AI features)
vexor auth status              # Check login status
vexor auth logout              # Logout

# Utilities
vexor update                   # Update to latest version
vexor --offline                # Offline mode (no AI)
vexor --version                # Show version
```

---

## Security Modules (28)

### Injection Attacks
| Module | What it Tests |
|--------|--------------|
| `sqli` | SQL Injection — Error-based, Time-based, Boolean, WAF bypass (MySQL/PG/MSSQL/Oracle/SQLite) |
| `xss` | Cross-Site Scripting — Reflected, Stored, DOM |
| `xxe` | XML External Entity — File read, SSRF via XXE, Blind XXE |
| `lfi` | Local File Inclusion — Path traversal, Base64 filter bypass |
| `ssti` | Server-Side Template Injection — Jinja2, Twig, Freemarker |
| `ssrf` | Server-Side Request Forgery — Cloud metadata, internal endpoints |

### Authentication & Authorization
| Module | What it Tests |
|--------|--------------|
| `jwt_analyzer` | JWT — Algorithm confusion, weak secrets, none attack |
| `auth_bypass` | Auth Bypass — Header injection, default creds, path traversal |
| `session_analyzer` | Sessions — Cookie flags, fixation, ID strength |
| `idor` | IDOR — Sequential IDs, UUID enumeration, API endpoints |

### Web Security
| Module | What it Tests |
|--------|--------------|
| `csrf` | CSRF — Token detection, SameSite, Origin validation |
| `cors` | CORS — Wildcard, arbitrary origin, null bypass |
| `headers` | Security Headers — HSTS, CSP, X-Frame-Options, 7+ headers |
| `open_redirect` | Open Redirect — 10+ bypass payloads |
| `file_upload` | File Upload — SVG XSS, PHP bypass, extension tricks |
| `rate_limit` | Rate Limiting — Login brute force detection |

### Network & Infrastructure
| Module | What it Tests |
|--------|--------------|
| `ssl_analyzer` | SSL/TLS — Cert validity, weak ciphers, HSTS |
| `port_scanner` | Ports — TCP scan, service detection, dangerous ports |
| `http_smuggling` | HTTP Smuggling — CL.TE, TE.CL timing attacks |
| `cache_poisoning` | Cache Poisoning — Unkeyed header injection |
| `host_header` | Host Header — Password reset poisoning |
| `websocket` | WebSocket — XSS, SQLi via WebSocket |

### Recon & OSINT
| Module | What it Tests |
|--------|--------------|
| `subdomain` | Subdomain Enum — 100+ wordlist, DNS resolution |
| `dirbuster` | Directory Discovery — 50+ paths, sensitive files |
| `wayback` | Wayback Machine — Historical endpoints, old admin paths |
| `github_dork` | GitHub Dorking — Leaked secrets, API keys |
| `sensitive_data` | Sensitive Data — 20+ patterns (AWS keys, tokens, PII) |
| `fingerprinter` | Tech Stack — Framework, server, version detection |

### Advanced
| Module | What it Tests |
|--------|--------------|
| `nuclei` | Nuclei Templates — 50,000+ CVE, misconfig, exposure templates |
| `cve_lookup` | CVE + ExploitDB — Auto-maps CVEs to public exploits + GitHub PoCs |
| `screenshot` | Screenshots — Visual recon via Playwright |
| `blind_scanner` | Blind XSS/SSRF — OOB callback server, Log4Shell |
| `api_tester` | API Testing — REST, GraphQL, versioning, method testing |
| `graphql` | GraphQL — Introspection, injection, batching attacks |

---

## OSINT Intelligence Engine

Just provide a target — Vexor does everything:

```
Target: example.com
         │
Phase 1 ─┤ Discovery
         │  DNS (A/AAAA/MX/NS/TXT/SOA) · Certificate Transparency (crt.sh)
         │  WHOIS · ASN/BGP (BGPView) · HackerTarget · RapidDNS
         │  Assetfinder · Findomain · SSL SANs · Subdomain Takeover (27 services)
         │
Phase 2 ─┤ Live Host Check
         │  Async httpx check on all discovered subdomains
         │  Status codes · Page titles · Server headers
         │
Phase 3 ─┤ Deep Recon (on live hosts)
         │  Port scan · SSL chain analysis · Tech fingerprinting
         │  Wayback Machine · Hakrawler crawl · Email harvesting
         │  SPF/DMARC/DKIM · IP Geolocation · Social media presence
         │
Phase 4 ─┤ Secret Extraction (Gf Patterns)
         │  API keys · AWS keys · GitHub tokens · JWT tokens
         │  SQLi parameters · XSS parameters · Open redirect params
         │  SSRF parameters · Sensitive file extensions
         │
Phase 5 ─┤ Threat Intelligence (Backend)
         │  Shodan — open ports, CVEs, banners
         │  VirusTotal — malware history, passive DNS
         │  AlienVault OTX — threat pulses, malware samples
         │  URLScan.io — scan history, malicious resources
         │  Chaos DB — 50M+ passive subdomains
         │
Phase 6 ─┤ AI Correlation
         │  Attack chain construction
         │  Threat actor profiling (MITRE ATT&CK)
         │  Subdomain attack vector analysis
         │  Leaked secrets deep analysis
         │  Live hosts attack surface mapping
         └─▶ Intelligence Report
```

---

## AI Features

No API key needed — AI works automatically via multi-provider fallback:

```
Groq (fastest) → NVIDIA NIM → OpenRouter → HuggingFace
```

| Action | Description |
|--------|-------------|
| 🔍 Analyze | Deep vulnerability analysis with exploitation paths |
| 💡 Explain | Explain any HTTP request/response |
| ⚡ Suggest | Next attack step recommendations |
| 🎯 Payload Gen | Context-aware smart payloads |
| 🧹 Filter | Remove false positives from findings |
| 📄 Report | Write professional pentest report sections |
| 🔥 Auto Exploit | Full attack chain generation |
| 📊 Risk Score | CVSS v3.1 scoring with vector string |
| 🌐 Translate | Reports in 10 languages |
| 💻 PoC Generator | Working Python exploit scripts |
| 💬 Chat History | Context-aware conversation (last 20 exchanges) |

---

## Project Structure

```
Vexor/
├── cli/
│   └── vexor/
│       ├── modules/           ← 28 scan modules
│       │   ├── sqli.py        ← SQL Injection (5 DBs, WAF bypass)
│       │   ├── xss.py         ← XSS (Reflected/Stored/DOM)
│       │   ├── nuclei.py      ← Nuclei template wrapper
│       │   ├── cve_lookup.py  ← CVE + ExploitDB mapping
│       │   ├── screenshot.py  ← Playwright visual recon
│       │   ├── osint.py       ← 6-phase OSINT pipeline
│       │   └── ...            ← 22 more modules
│       │
│       ├── tui/
│       │   ├── screens/       ← 13 TUI screens
│       │   │   ├── dashboard.py
│       │   │   ├── scanner_screen.py
│       │   │   ├── ai_screen.py
│       │   │   ├── osint_screen.py
│       │   │   ├── notes_screen.py
│       │   │   └── ...
│       │   └── widgets/       ← Header, Sidebar, StatusBar
│       │
│       ├── core/
│       │   ├── db.py          ← SQLite persistence
│       │   ├── workspace.py   ← Project/workspace system
│       │   ├── scope.py       ← Scope management
│       │   ├── callback_server.py  ← OOB callback (Blind XSS/SSRF)
│       │   ├── proxy.py       ← HTTP/HTTPS proxy
│       │   └── tool_detector.py    ← Auto-detect Go/system tools
│       │
│       ├── ai/
│       │   └── client.py      ← AI client (chat, PoC, sync, team)
│       │
│       ├── reports/
│       │   ├── html.py        ← Professional HTML reports
│       │   └── pdf.py         ← PDF via weasyprint
│       │
│       └── payloads/          ← Built-in payload lists
│           ├── sqli.txt
│           ├── xss.txt
│           ├── lfi.txt
│           └── ssrf.txt
│
├── install.sh                 ← One-click installer
├── uninstall.sh               ← Clean uninstaller
└── check_deps.py              ← Dependency checker
```

---

## Legal Disclaimer

> **For authorized security testing ONLY.**
>
> Using Vexor against systems you do not own or have explicit written permission
> to test is **illegal** and may result in criminal prosecution.
> The author assumes no liability for misuse.

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">

Made with ❤️ by **[Chandan Pandey (Technical)](https://github.com/thecnical)**

⭐ **Star this repo** if Vexor helped you — it helps others find it!

`penetration-testing` · `bug-bounty` · `osint` · `kali-linux` · `vulnerability-scanner`  
`burp-suite-alternative` · `cli-security-tool` · `ai-pentest` · `red-team` · `nuclei`

</div>
