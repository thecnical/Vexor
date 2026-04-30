<div align="center">

```
██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**AI-Powered CLI Security Toolkit**

*Penetrate. Analyze. Dominate.*

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-orange?style=flat-square&logo=linux)](https://github.com/thecnical/Vexor)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-cyan?style=flat-square)](https://github.com/thecnical/Vexor/releases)
[![Author](https://img.shields.io/badge/Author-Chandan%20Pandey-magenta?style=flat-square)](https://github.com/thecnical)

> Created by **[Chandan Pandey (Technical)](https://github.com/thecnical)**

</div>

---

## What is Vexor?

Vexor is a free, AI-powered CLI security toolkit that beats Burp Suite Pro in features while being completely free. It runs entirely in your terminal with a beautiful TUI — no GUI needed, no Java, no $475/year license.

**Vexor vs Burp Suite Pro:**

| Feature | Burp Community | Burp Pro ($475/yr) | Vexor (Free) |
|---------|---------------|---------------------|--------------|
| Automated Scanner | ❌ | ✅ | ✅ |
| AI Analysis | ❌ | ✅ Limited | ✅ Unlimited |
| Project Save/Load | ❌ | ✅ | ✅ |
| Intruder (unlimited) | ❌ Throttled | ✅ | ✅ |
| PDF Reports | ❌ | ✅ | ✅ |
| CLI Native | ❌ Java GUI | ❌ Java GUI | ✅ |
| Port Scanner | ❌ | ❌ | ✅ |
| Subdomain Enum | ❌ | ❌ | ✅ |
| GitHub Dorking | ❌ | ❌ | ✅ |
| Wayback Machine | ❌ | ❌ | ✅ |
| Multi AI Providers | ❌ | ❌ | ✅ |
| Price | Free | $475/year | **Free** |

---

## Features

### 26 Security Modules

| Module | Description | Severity |
|--------|-------------|----------|
| `sqli` | SQL Injection (Error + Time-based + Blind) | CRITICAL |
| `xss` | XSS (Reflected + Stored + DOM) | HIGH |
| `csrf` | CSRF (Forms + SameSite + Origin) | HIGH |
| `idor` | Insecure Direct Object Reference | HIGH |
| `ssrf` | Server-Side Request Forgery | CRITICAL |
| `xxe` | XML External Entity Injection | CRITICAL |
| `lfi` | Local/Remote File Inclusion | CRITICAL |
| `jwt_analyzer` | JWT Token Analysis & Attacks | CRITICAL |
| `ssl_analyzer` | SSL/TLS Deep Analysis (pyOpenSSL) | HIGH |
| `headers` | Security Headers Check (7+ headers) | MEDIUM |
| `cors` | CORS Misconfiguration | HIGH |
| `websocket` | WebSocket Security Testing | HIGH |
| `api_tester` | REST/GraphQL API Testing | HIGH |
| `port_scanner` | TCP Port Scanner (nmap + socket) | HIGH |
| `rate_limit` | Rate Limiting Detection | HIGH |
| `open_redirect` | Open Redirect Finder | MEDIUM |
| `file_upload` | File Upload Bypass Testing | CRITICAL |
| `session_analyzer` | Session/Cookie Security | HIGH |
| `fingerprinter` | Technology Stack Detection | INFO |
| `subdomain` | Subdomain Enumeration (100+ wordlist) | INFO |
| `dirbuster` | Directory/File Discovery (50+ paths) | HIGH |
| `cve_lookup` | CVE Lookup via NVD API | CRITICAL |
| `wayback` | Historical Endpoint Discovery | HIGH |
| `github_dork` | GitHub Secret Dorking | CRITICAL |
| `sensitive_data` | Sensitive Data Exposure (20+ patterns) | CRITICAL |
| `auth_bypass` | Authentication Bypass | CRITICAL |

### AI Features (Free — No API Key Needed)

AI runs on backend with automatic fallback chain:

```
Groq (fastest) → NVIDIA NIM → OpenRouter → HuggingFace
```

- **Analyze** — Deep vulnerability analysis
- **Explain** — Explain any HTTP request/response
- **Suggest** — Next attack step suggestions  
- **Payload** — AI-generated smart payloads
- **Filter** — False positive removal
- **Report** — Professional report writing

### World-Class Tools Integrated

| Tool | Purpose |
|------|---------|
| **mitmproxy** | HTTP/HTTPS proxy interceptor |
| **Scapy** | Packet crafting & network analysis |
| **pyOpenSSL** | Deep SSL certificate analysis |
| **python-nmap** | Port scanning via nmap |
| **Playwright** | JS-heavy site scanning |
| **Textual** | Beautiful terminal UI |

---

## Installation

### Requirements
- Linux or WSL (Windows Subsystem for Linux)
- Python 3.11+
- nmap (system package)

### Quick Install

```bash
git clone https://github.com/thecnical/Vexor
cd Vexor
chmod +x install.sh
./install.sh
```

### WSL Setup (Windows Users)

```powershell
# In PowerShell (Admin)
wsl --install -d kali-linux
```

Then in Kali/WSL:
```bash
sudo apt update && sudo apt upgrade -y
git clone https://github.com/thecnical/Vexor
cd Vexor && ./install.sh
```

### Verify Installation

```bash
python check_deps.py
vexor --version
```

---

## Usage

### Launch TUI (Recommended)

```bash
vexor
```

Beautiful terminal dashboard with:
- F1 Dashboard | F2 Proxy | F3 Scanner | F4 Intruder
- F5 Repeater | F6 AI Panel | F7 Reports
- Ctrl+H Help | Ctrl+O Offline Mode | Ctrl+Q Quit

### CLI Commands

```bash
# Quick scan (5 modules)
vexor scan https://target.com

# Full scan (26 modules)
vexor scan https://target.com --full

# Single module
vexor scan https://target.com --module sqli
vexor scan https://target.com --module xss

# Save report
vexor scan https://target.com --full --output report.html
vexor scan https://target.com --full --format pdf

# Start proxy
vexor proxy
vexor proxy --port 9090

# Auth
vexor auth login
vexor auth status
vexor auth logout

# Offline mode (no AI)
vexor --offline
vexor scan https://target.com --offline

# Version
vexor --version
```

---

## Project Structure

```
vexor/
├── cli/                    ← User tool (pip install)
│   └── vexor/
│       ├── modules/        ← 26 scan modules
│       ├── tui/            ← Terminal UI
│       ├── core/           ← Proxy, decoder, session
│       ├── ai/             ← AI client
│       ├── reports/        ← HTML/PDF reports
│       ├── payloads/       ← Built-in payload lists
│       └── plugins/        ← Plugin system
│
├── backend/                ← API server (Render deploy)
│   └── app/
│       ├── ai/             ← AI orchestrator + providers
│       ├── auth/           ← JWT authentication
│       └── api/            ← REST endpoints
│
├── install.sh              ← One-click installer
├── check_deps.py           ← Dependency checker
└── README.md
```

---

## Backend Deploy (Render)

```bash
# 1. Fork this repo
# 2. Connect to Render
# 3. Set environment variables:
GROQ_API_KEY=your_key
NVIDIA_API_KEY=your_key
OPENROUTER_API_KEY=your_key
HUGGINGFACE_API_KEY=your_key
SECRET_KEY=your_random_secret

# 4. Deploy backend/ directory
# 5. Update VEXOR_BACKEND_URL in cli/vexor/config.py
```

---

## Legal Disclaimer

> **Vexor is for authorized security testing ONLY.**
>
> Use of this tool against systems you do not own or have explicit written
> permission to test is **ILLEGAL** and may result in criminal prosecution.
>
> The author assumes no liability for misuse.

---

## License

MIT License — See [LICENSE](LICENSE)

---

<div align="center">

Made with ❤️ by **[Chandan Pandey (Technical)](https://github.com/thecnical)**

*If Vexor helped you, give it a ⭐ on [GitHub](https://github.com/thecnical/Vexor)*

</div>
