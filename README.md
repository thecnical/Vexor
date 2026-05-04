<div align="center">

```
██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# VEXOR v4.1 — AI-Powered Terminal Security Toolkit

**The Free, Open-Source Burp Suite Pro Alternative. Built for the Terminal.**

*Penetrate. Analyze. Dominate.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Kali%20Linux-Native-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-00D26A?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.1.0-00FFFF?style=for-the-badge)](https://github.com/thecnical/Vexor/releases)

> **Vexor** is a full-featured, TUI-first security toolkit that lives entirely in your terminal.  
> No Java. No GUI. No $475/year license. Just type `vexor` and start hacking.

</div>

---

## TUI Architecture — How It Works

Vexor is **TUI-first**. Running `vexor` launches a full terminal UI built with [Textual](https://textual.textualize.io/). Every feature is accessible via keyboard. CLI commands are shortcuts that trigger the same underlying engines.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  VEXOR v4.1  ·  Penetrate. Analyze. Dominate.           [ONLINE] [TARGET:-] │
├──────────────────────┬──────────────────────────────────────────────────────┤
│  NAVIGATION          │                                                       │
│  ─────────────────   │          ACTIVE SCREEN PANEL                         │
│  ◈ Dashboard    F1   │         (switches on keypress)                        │
│  ◈ Proxy        F2   │                                                       │
│  ◈ Scanner      F3   │                                                       │
│  ◈ Intruder     F4   │                                                       │
│  ◈ Repeater     F5   │                                                       │
│  ◈ AI Panel     F6   │                                                       │
│  ─────────────────   │                                                       │
│  ◈ Reports      F7   │                                                       │
│  ◈ Decoder      F8   │                                                       │
│  ◈ Comparer     F9   │                                                       │
│  ◈ OSINT        F10  │                                                       │
│  ─────────────────   │                                                       │
│  ◈ Config        `   │                                                       │
│  ◈ Plugins      F12  │                                                       │
│  ◈ Notes     Ctrl+N  │                                                       │
├──────────────────────┴──────────────────────────────────────────────────────┤
│  [Ctrl+H] Help  [Ctrl+O] Offline  [Ctrl+Q] Quit  · Vexor v4.1              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Complete Mind Map

```
                              VEXOR v4.1
                    AI-Powered Terminal Security Toolkit
                         (TUI + CLI — Terminal Native)
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
  ┌─────▼──────┐            ┌───────▼───────┐          ┌───────▼───────┐
  │  TUI (F1-  │            │  SCAN ENGINE  │          │  AI ENGINE    │
  │  F12+Ctrl) │            │  35+ Modules  │          │  Multi-Model  │
  └─────┬──────┘            └───────┬───────┘          └───────┬───────┘
        │                           │                           │
  ┌─────▼─────────────────┐  ┌──────▼──────────────┐  ┌───────▼──────────┐
  │ F1  Dashboard          │  │ Injection            │  │ Groq (fastest)   │
  │  · Live stats          │  │  · SQLi (5 DBs)      │  │ NVIDIA NIM       │
  │  · Recent findings     │  │  · XSS (3 types)     │  │ OpenRouter       │
  │  · Quick start         │  │  · XXE / LFI / SSTI  │  │ HuggingFace      │
  ├────────────────────────┤  │  · SSRF / CSRF       │  ├──────────────────┤
  │ F2  Proxy Interceptor  │  ├──────────────────────┤  │ AI Actions:      │
  │  · Start/Stop proxy    │  │ Auth & Session        │  │  Analyze vulns   │
  │  · HTTP history table  │  │  · JWT Analyzer       │  │  Auto Exploit    │
  │  · Request editor      │  │  · Auth Bypass        │  │  Generate PoC    │
  │  · Send→Repeater       │  │  · Session Analyzer   │  │  CVSS Scoring    │
  │  · Send→Intruder       │  │  · IDOR               │  │  Smart Payloads  │
  │  · Send→Comparer       │  ├──────────────────────┤  │  False+ Filter   │
  │  · MITM mode (--mitm)  │  │ Network & Infra       │  │  Report Writer   │
  │  · Passive scanner     │  │  · Port Scanner       │  │  Translate (10x) │
  ├────────────────────────┤  │  · SSL Analyzer       │  │  Chat History    │
  │ F3  Scanner            │  │  · HTTP Smuggling     │  │  PoC Generator   │
  │  · Target URL input    │  │  · Cache Poisoning    │  └──────────────────┘
  │  · Full / Quick /      │  │  · WebSocket Tester   │
  │    Custom scan modes   │  ├──────────────────────┤
  │  · 28 module checkboxes│  │ Recon                 │
  │  · Live progress bar   │  │  · Subdomain Enum     │
  │  · Findings table      │  │  · Dir Bruteforce     │
  │  · Click row→details   │  │  · Wayback Machine    │
  │  · Auto AI analysis    │  │  · GitHub Dorking     │
  │  · DB persistence      │  │  · Fingerprinter      │
  ├────────────────────────┤  │  · Sensitive Data     │
  │ F4  Intruder           │  ├──────────────────────┤
  │  · 4 attack modes:     │  │ Advanced              │
  │    Sniper              │  │  · Nuclei (50k+ tmpl) │
  │    Battering Ram       │  │  · CVE + ExploitDB    │
  │    Pitchfork           │  │  · Screenshot (Playwright)│
  │    Cluster Bomb        │  │  · Blind XSS/SSRF OOB│
  │  · §position§ markers  │  │  · API Tester         │
  │  · Wordlist import     │  │  · GraphQL            │
  │  · Concurrent threads  │  │  · SSTI               │
  │  · Interesting flag    │  │  · HTTP Smuggling     │
  ├────────────────────────┤  └──────────────────────┘
  │ F5  Repeater           │
  │  · Manual request edit │         CORE SYSTEMS
  │  · Send HTTP/HTTPS     │  ┌───────────────────────────────────────────┐
  │  · Response history    │  │ SQLite DB  · Workspace · Scope Management │
  │  · Diff responses      │  │ OOB Callback Server (port 7331)           │
  ├────────────────────────┤  │ Cloud Sync · Team Collaboration WS        │
  │ F6  AI Panel           │  │ MITM Proxy · CA Generator · Cert Signing  │
  │  · Chat interface      │  └───────────────────────────────────────────┘
  │  · 11 AI actions       │
  │  · Context-aware       │         OSINT ENGINE (6 Phases)
  │  · PoC generation      │  ┌───────────────────────────────────────────┐
  ├────────────────────────┤  │ 1. Discovery  DNS·CT·WHOIS·ASN·Subs       │
  │ F7  Reports            │  │ 2. Live Check httpx async on all hosts    │
  │  · HTML / PDF / JSON   │  │ 3. Deep Recon Ports·SSL·Tech·Wayback      │
  │  · Load from DB        │  │ 4. Secrets   API keys·JWT·SQLi params     │
  │  · 5 report templates  │  │ 5. Threat Intel Shodan·VT·OTX·URLScan    │
  ├────────────────────────┤  │ 6. AI Correlate Attack chains·MITRE ATT&CK│
  │ F8  Decoder            │  └───────────────────────────────────────────┘
  │  · Base64 / URL / Hex  │
  │  · JWT decode/forge    │
  │  · HTML / ROT13        │
  ├────────────────────────┤
  │ F9  Comparer           │
  │  · Diff requests       │
  │  · Diff responses      │
  │  · Highlight changes   │
  ├────────────────────────┤
  │ F10 OSINT              │
  │  · 6-phase pipeline    │
  │  · Live progress feed  │
  │  · AI threat profile   │
  ├────────────────────────┤
  │ `   Config & Settings  │
  │  · Login / Logout      │
  │  · Backend URL         │
  │  · Scan defaults       │
  ├────────────────────────┤
  │ F12 Plugins            │
  │  · Plugin manager      │
  │  · Load custom modules │
  ├────────────────────────┤
  │ Ctrl+N  Notes          │
  │  · Pentest notes       │
  │  · Per-target tagging  │
  │  · Persistent SQLite   │
  └────────────────────────┘
```

---

## Why Vexor?

| Feature | Burp Community | Burp Pro ($475/yr) | **Vexor v4.1 (Free)** |
|:--------|:---:|:---:|:---:|
| TUI — works over SSH, no GUI needed | ❌ | ❌ | ✅ |
| Automated Vulnerability Scanner | ❌ | ✅ | ✅ **35 modules** |
| HTTPS MITM Proxy | ✅ | ✅ | ✅ **with CA gen** |
| Intruder (4 attack modes) | ❌ throttled | ✅ | ✅ **unlimited** |
| Repeater | ✅ | ✅ | ✅ |
| AI Analysis & PoC Generation | ❌ | ❌ | ✅ **Unlimited** |
| OSINT Intelligence Engine | ❌ | ❌ | ✅ **6-Phase** |
| Nuclei Template Scanning | ❌ | ❌ | ✅ **50k+ templates** |
| Blind XSS/SSRF OOB Callbacks | ❌ | ✅ Collaborator | ✅ **Built-in** |
| Spider / Web Crawler | ✅ | ✅ | ✅ **JS-aware** |
| Passive Scanner | ❌ | ✅ | ✅ **on all traffic** |
| Decoder / Comparer | ✅ | ✅ | ✅ |
| Cloud Sync + Team Collaboration | ❌ | ❌ | ✅ **WebSocket** |
| Scan Session Persistence | ❌ | ✅ | ✅ **SQLite** |
| JWT Revocation / Secure Auth | ❌ | N/A | ✅ |
| Scope Management | ❌ | ✅ | ✅ |
| Notes Panel | ❌ | ❌ | ✅ |
| **Price** | Free | **$475/year** | **🆓 Free Forever** |

---

## Installation

### One-Line (Kali / Debian / Ubuntu)

```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### WSL / Windows

```powershell
# PowerShell (Admin)
wsl --install -d kali-linux
```

Then inside Kali:

```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### Update

```bash
vexor update
# or manually:
cd ~/Vexor && git pull && ./install.sh
```

### Optional Go Tools (full OSINT power)

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
```

---

## Usage

### Launch TUI

```bash
vexor            # Full TUI — recommended
vexor --offline  # TUI without AI/cloud features
```

### TUI Keyboard Reference

| Key | Screen | What you can do |
|-----|--------|-----------------|
| `F1` | **Dashboard** | View live stats, recent findings, target overview |
| `F2` | **Proxy** | Start/stop HTTP proxy, view history, edit & resend, send→Repeater/Intruder |
| `F3` | **Scanner** | Type target → Full / Quick / Custom scan, pick modules, view findings, AI auto-analysis |
| `F4` | **Intruder** | Paste request with `§markers§`, pick attack mode, load wordlist, run attack |
| `F5` | **Repeater** | Edit raw HTTP request, send, view response, diff history |
| `F6` | **AI Panel** | Analyze findings, generate PoC, CVSS score, translate reports, chat |
| `F7` | **Reports** | Generate HTML/PDF/JSON from last scan or session ID |
| `F8` | **Decoder** | Base64 / URL / Hex / JWT / HTML / ROT13 encode-decode |
| `F9` | **Comparer** | Paste two requests or responses, see unified diff |
| `F10` | **OSINT** | Enter domain → 6-phase recon pipeline with AI threat profile |
| `` ` `` | **Config** | Login, backend URL, scan timeout, proxy defaults |
| `F12` | **Plugins** | Load / manage custom scan modules |
| `Ctrl+N` | **Notes** | Write and persist pentest notes, tag by target |
| `Ctrl+H` | **Help** | Full keyboard shortcut reference |
| `Ctrl+O` | Toggle | Switch Online ↔ Offline mode |
| `Ctrl+Q` | Quit | Exit Vexor |
| `Escape` | Quit | Exit Vexor |

---

## CLI Commands

CLI commands use the same scan engines as the TUI — no difference in power.

```bash
# ─── Launch ────────────────────────────────────────────────
vexor                                       # Launch TUI (default)
vexor --offline                             # TUI in offline mode

# ─── Scanner ───────────────────────────────────────────────
vexor scan https://target.com              # Quick scan (7 core modules)
vexor scan https://target.com --full       # Full scan (35 modules)
vexor scan https://target.com --module sqli          # Single module
vexor scan https://target.com --full --format pdf    # Save PDF report
vexor scan https://target.com --threads 20           # 20 concurrent threads

# ─── Proxy ─────────────────────────────────────────────────
vexor proxy                                # HTTP proxy on 127.0.0.1:8080
vexor proxy --port 9090                    # Custom port
vexor proxy --mitm                         # HTTPS interception (installs CA)
vexor proxy --mitm --intercept             # Hold requests for manual review
vexor proxy --mitm --passive               # Passive scan all proxied traffic

# ─── OSINT ─────────────────────────────────────────────────
vexor osint target.com                     # 6-phase OSINT investigation
vexor osint target.com --format json       # Save JSON report

# ─── Spider ────────────────────────────────────────────────
vexor spider https://target.com            # Crawl + discover endpoints
vexor spider https://target.com --depth 8  # Deep crawl
vexor spider https://target.com --max 1000 # Up to 1000 URLs

# ─── Intruder ──────────────────────────────────────────────
# Paste raw HTTP request with §position§ markers, then Ctrl+D
vexor intruder target.com --attack sniper -w /usr/share/wordlists/rockyou.txt
vexor intruder target.com --https --attack cluster_bomb -w payloads.txt
# Attack modes: sniper | battering_ram | pitchfork | cluster_bomb

# ─── Reports ───────────────────────────────────────────────
vexor report --last                        # Report from last scan
vexor report --session 5 --format pdf      # Report from session ID 5
vexor history                              # List all past sessions

# ─── Cloud Sync ────────────────────────────────────────────
vexor sync --last                          # Push last scan to cloud
vexor sync --session 3                     # Push session 3 to cloud

# ─── Auth ──────────────────────────────────────────────────
vexor auth login                           # Login (enables AI + sync)
vexor auth status                          # Check login status
vexor auth logout                          # Revoke token + logout

# ─── Other ─────────────────────────────────────────────────
vexor update                               # Self-update from git
vexor --version                            # Show version
```

---

## How the Proxy + MITM Works

```
Browser (proxy: 127.0.0.1:8080)
        │
        ▼
  VexorProxy / VexorMITMProxy (asyncio)
        │
        ├── HTTP → parse request → history → passive scan → forward
        │
        └── HTTPS CONNECT → TLS handshake with target
                          → sign per-host cert with Vexor CA
                          → decrypt traffic
                          → history → passive scan → forward
                          → re-encrypt to browser
        │
        ▼
  Intercept Queue (if --intercept)
  → TUI Proxy Screen shows request
  → User clicks Forward / Drop
        │
        ▼
  → Repeater / Intruder (send→ buttons in TUI F2 screen)
```

**First time with MITM:**

```bash
vexor proxy --mitm
# Install the CA cert shown in output into your browser:
# Chrome: Settings → Privacy → Manage Certificates → Authorities → Import
# Firefox: Settings → Privacy → Certificates → Import
# Path: ~/.vexor/ca/vexor_ca.crt
```

---

## Intruder Attack Modes

| Mode | Behaviour | Use Case |
|------|-----------|----------|
| **Sniper** | One `§position§` at a time, single wordlist | Parameter fuzzing |
| **Battering Ram** | Same payload into ALL positions at once | Same value everywhere |
| **Pitchfork** | Multiple wordlists zipped 1:1 per position | Username:Password pairs |
| **Cluster Bomb** | Cartesian product of all wordlists | Brute force all combos |

**In TUI (F4):** Paste raw request with `§value§` markers → pick mode → load wordlist → Run  
**In CLI:** `vexor intruder target.com --attack sniper -w wordlist.txt` then paste request

---

## Security Modules (35)

### Injection
`sqli` · `xss` · `xxe` · `lfi` · `ssti` · `ssrf`

### Auth & Session
`jwt_analyzer` · `auth_bypass` · `session_analyzer` · `idor`

### Web Security
`csrf` · `cors` · `headers` · `open_redirect` · `file_upload` · `rate_limit` · `host_header`

### Network & Infra
`ssl_analyzer` · `port_scanner` · `http_smuggling` · `cache_poisoning` · `websocket`

### Recon
`subdomain` · `dirbuster` · `wayback` · `github_dork` · `sensitive_data` · `fingerprinter`

### Advanced
`nuclei` · `cve_lookup` · `screenshot` · `blind_scanner` · `api_tester` · `graphql`

---

## Project Structure

```
Vexor/
├── cli/vexor/
│   ├── modules/          ← 35 scan modules
│   ├── tui/
│   │   ├── app.py        ← Main TUI (Textual, F1-F12 navigation)
│   │   ├── screens/      ← 13 TUI screens (dashboard, proxy, scanner…)
│   │   └── widgets/      ← Header, Sidebar, StatusBar
│   ├── core/
│   │   ├── db.py         ← SQLite persistence (sessions, findings, notes)
│   │   ├── proxy.py      ← HTTP proxy engine (asyncio)
│   │   ├── mitm_proxy.py ← HTTPS MITM (CA gen, per-host certs, TLS)
│   │   ├── repeater.py   ← Manual request replay engine
│   │   ├── intruder.py   ← 4-mode HTTP fuzzer
│   │   ├── spider.py     ← JS-aware web crawler + passive scanner
│   │   ├── collaborator.py ← OOB callback (interactsh + built-in)
│   │   ├── scope.py      ← Scope enforcement
│   │   └── workspace.py  ← Project/workspace system
│   ├── ai/client.py      ← AI client (Groq/NVIDIA/OpenRouter/HuggingFace)
│   ├── reports/          ← HTML + PDF report generators
│   └── payloads/         ← Built-in payload lists
│
├── backend/app/
│   ├── main.py           ← FastAPI backend (hardened, SSRF-protected)
│   ├── api/scan.py       ← Scan API + WebSocket progress streaming
│   ├── api/osint.py      ← OSINT backend (Shodan, VT, OTX…)
│   ├── api/sync.py       ← Cloud sync + team WebSocket collaboration
│   ├── auth/             ← JWT auth with revocation, refresh tokens
│   └── database/db.py    ← Backend SQLite schema
│
├── install.sh            ← One-click installer
├── uninstall.sh          ← Clean uninstaller
└── README.md
```

---

## AI Features (No API Key Required)

Multi-provider fallback — always finds a working model:

```
Groq (fastest) → NVIDIA NIM → OpenRouter → HuggingFace
```

| Action | Description |
|--------|-------------|
| 🔍 **Analyze** | Deep vulnerability analysis with exploitation paths |
| 🎯 **Payload Gen** | Context-aware smart payloads for the target |
| 🧹 **False+ Filter** | Remove false positives from findings |
| 🔥 **Auto Exploit** | Full attack chain generation |
| 💻 **PoC Generator** | Working Python exploit scripts |
| 📊 **Risk Score** | CVSS v3.1 scoring with vector string |
| 📄 **Report Writer** | Professional pentest report sections |
| 🌐 **Translate** | Reports in 10 languages |
| 💬 **Chat** | Context-aware conversation (last 20 exchanges) |

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

⭐ **Star this repo** if Vexor helped you!

`penetration-testing` · `bug-bounty` · `osint` · `tui` · `kali-linux`  
`burp-suite-alternative` · `ai-pentest` · `red-team` · `nuclei` · `mitm-proxy`

</div>
