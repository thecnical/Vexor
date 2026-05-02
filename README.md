<div align="center">

```
██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

# Vexor — AI-Powered CLI Security Toolkit

**The Free, Open-Source Alternative to Burp Suite Pro**

*Penetrate. Analyze. Dominate.*

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20WSL-orange?style=flat-square&logo=linux)](https://github.com/thecnical/Vexor)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0.0-cyan?style=flat-square)](https://github.com/thecnical/Vexor/releases)
[![CI](https://github.com/thecnical/Vexor/actions/workflows/ci.yml/badge.svg)](https://github.com/thecnical/Vexor/actions)
[![Author](https://img.shields.io/badge/Author-Chandan%20Pandey-magenta?style=flat-square)](https://github.com/thecnical)

> **Vexor** is a free, AI-powered CLI security toolkit for penetration testers, bug bounty hunters, and red teamers.  
> Built for Kali Linux. Runs in your terminal. No Java. No $475/year license.

</div>

---

## Why Vexor?

| Feature | Burp Community | Burp Pro ($475/yr) | **Vexor v4 (Free)** |
|---------|:-:|:-:|:-:|
| Automated Vulnerability Scanner | ❌ | ✅ | ✅ |
| AI Analysis & Payloads | ❌ | ❌ | ✅ Unlimited |
| OSINT Intelligence Engine | ❌ | ❌ | ✅ 6-Phase |
| Nuclei Template Scanning | ❌ | ❌ | ✅ |
| Subdomain Takeover Detection | ❌ | ❌ | ✅ |
| CVE + ExploitDB Mapping | ❌ | ❌ | ✅ |
| AI-Generated PoC Exploits | ❌ | ❌ | ✅ |
| Blind XSS/SSRF Callback Server | ❌ | ✅ (Collaborator) | ✅ Built-in |
| Cloud Sync + Team Collaboration | ❌ | ❌ | ✅ |
| Scan Session Persistence | ❌ | ✅ | ✅ SQLite |
| Intruder (unlimited speed) | ❌ Throttled | ✅ | ✅ 50 parallel |
| SecLists Integration | ❌ | ❌ | ✅ Auto-download |
| CLI Native (no Java/GUI) | ❌ | ❌ | ✅ |
| **Price** | Free | **$475/year** | **Free Forever** |

---

## Features

### 🔍 28 Security Modules

```
sqli · xss · csrf · idor · ssrf · xxe · lfi · jwt_analyzer
ssl_analyzer · headers · cors · websocket · api_tester
port_scanner · rate_limit · open_redirect · file_upload
session_analyzer · fingerprinter · subdomain · dirbuster
cve_lookup · wayback · github_dork · sensitive_data
auth_bypass · nuclei · screenshot
```

### 🧠 Vexor Intelligence Engine (OSINT v4)

6-phase automated OSINT pipeline — just provide a target:

```
Phase 1 → Discovery      DNS · CT Logs · WHOIS · ASN/BGP · Passive Subs
Phase 2 → Live Check     Async httpx check on all discovered hosts
Phase 3 → Deep Recon     Ports · SSL · Tech · Wayback · Hakrawler crawl
Phase 4 → Secrets        Gf patterns: API keys · JWT · SQLi · SSRF params
Phase 5 → Threat Intel   Shodan · VirusTotal · OTX · URLScan · Chaos DB
Phase 6 → AI Correlation Attack chains · Threat profiling · PoC generation
```

### 🤖 AI Features (No API Key Required)

Multi-provider AI with automatic fallback:
```
Groq → NVIDIA NIM → OpenRouter → HuggingFace
```

- **Analyze** — Deep vulnerability analysis with exploitation paths
- **Auto Exploit** — Full attack chain generation
- **PoC Generator** — Working Python exploit scripts
- **Risk Score** — CVSS v3.1 scoring
- **Payload Gen** — Context-aware smart payloads
- **False Positive Filter** — AI-powered result validation
- **Report Writer** — Professional pentest reports
- **Translate** — Reports in 10 languages
- **Chat History** — Context-aware conversation

### 🛡️ Advanced Capabilities

- **Nuclei Integration** — 50,000+ community templates (CVE, misconfig, exposure)
- **CVE + ExploitDB** — Auto-maps CVEs to public exploits + GitHub PoCs
- **Subdomain Takeover** — Detects dangling CNAMEs (27 cloud services)
- **Blind XSS/SSRF** — Built-in OOB callback server (no Burp Collaborator needed)
- **Scope Management** — `~/.vexor/scope.txt` with wildcard + CIDR support
- **Workspace System** — Per-target project isolation
- **Notes Panel** — Persistent pentest notes (SQLite)
- **Cloud Sync** — Push findings to web dashboard
- **Team Collaboration** — Multi-user shared projects
- **SecLists** — Auto-downloads community wordlists for Intruder
- **Screenshot Module** — Visual recon via Playwright

---

## Installation

### One-Line Install (Kali Linux / Debian)

```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### Manual Install

```bash
git clone https://github.com/thecnical/Vexor
cd Vexor
chmod +x install.sh
./install.sh
```

### Update

```bash
cd ~/Vexor && git pull && ./install.sh
# or inside Vexor:
vexor update
```

### WSL / Windows

```powershell
# PowerShell (Admin)
wsl --install -d kali-linux
```
Then in Kali:
```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

### Optional: Go Tools (for full OSINT power)

```bash
# Install Go first: https://go.dev/dl/
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
```

---

## Usage

### Launch TUI

```bash
vexor
```

| Key | Screen |
|-----|--------|
| F1 | Dashboard |
| F2 | Proxy Interceptor |
| F3 | Scanner (28 modules) |
| F4 | Intruder |
| F5 | Repeater |
| F6 | AI Panel |
| F7 | Reports |
| F8 | Decoder |
| F9 | Comparer |
| F10 | OSINT Intelligence |
| `` ` `` | Config & Login |
| F12 | Plugins |
| Ctrl+N | Notes |
| Ctrl+H | Help |
| Ctrl+Q | Quit |

### CLI Commands

```bash
vexor                              # Launch TUI
vexor scan https://target.com      # Quick scan (7 modules)
vexor scan https://target.com --full   # Full scan (28 modules)
vexor scan https://target.com --module nuclei  # Nuclei only
vexor scan https://target.com --full --format pdf  # PDF report
vexor proxy                        # Start HTTP/HTTPS proxy
vexor auth login                   # Login for AI features
vexor update                       # Update to latest
vexor --offline                    # Offline mode
vexor --version                    # Show version
```

---

## Project Structure

```
Vexor/
├── cli/vexor/
│   ├── modules/        ← 28 scan modules (sqli, xss, nuclei, ...)
│   ├── tui/screens/    ← 13 TUI screens
│   ├── core/           ← db, proxy, scope, workspace, callback_server
│   ├── ai/             ← AI client (chat, PoC, analysis)
│   ├── reports/        ← HTML/PDF report templates
│   ├── payloads/       ← Built-in payload lists
│   └── plugins/        ← Plugin system
│
├── backend/app/
│   ├── ai/             ← Multi-provider AI orchestrator
│   ├── auth/           ← JWT authentication
│   └── api/            ← osint · scan · sync (cloud/team)
│
├── install.sh          ← One-click installer
└── README.md
```

---

## Backend (Self-Host or Use Ours)

Our backend is deployed at Render. To self-host:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Environment variables needed:
```env
SECRET_KEY=your-secret
GROQ_API_KEY=...
NVIDIA_API_KEY=...
OPENROUTER_API_KEY=...
HUGGINGFACE_API_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
OTX_API_KEY=...
URLSCAN_API_KEY=...
CHAOS_API_KEY=...
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

*Keywords: penetration testing · bug bounty · OSINT · vulnerability scanner · Burp Suite alternative · Kali Linux · CLI security tool · AI pentest · red team · CTF*

</div>
