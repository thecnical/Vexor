# Vexor — Quick Start Guide

> **Legal Notice:** Only use Vexor on systems you own or have explicit written permission to test.

---

## Launch TUI (Recommended)

```bash
vexor
```

This opens the full terminal dashboard. Navigate with function keys:

| Key | Screen |
|-----|--------|
| `F1` | Dashboard — stats, recent findings |
| `F2` | Proxy — HTTP/HTTPS interceptor |
| `F3` | Scanner — 28 vulnerability modules |
| `F4` | Intruder — fuzzer/brute force |
| `F5` | Repeater — manual request editor |
| `F6` | AI Panel — AI analysis |
| `F7` | Reports — generate reports |
| `F8` | Decoder — encode/decode |
| `F9` | Comparer — diff requests |
| `F10` | OSINT — intelligence engine |
| `` ` `` | Config — settings & login |
| `F12` | Plugins — plugin manager |
| `Ctrl+N` | Notes — pentest notes |
| `Ctrl+H` | Help |
| `Ctrl+O` | Toggle offline mode |
| `Ctrl+Q` | Quit |

---

## CLI Quick Scan

```bash
# Quick scan (7 core modules)
vexor scan https://target.com

# Full scan (28 modules)
vexor scan https://target.com --full

# Single module
vexor scan https://target.com --module sqli
vexor scan https://target.com --module xss
vexor scan https://target.com --module nuclei

# Save report
vexor scan https://target.com --full --output report.html
vexor scan https://target.com --full --format pdf
vexor scan https://target.com --full --format json
```

---

## First Time Setup

### 1. Login (enables AI features)

```bash
# Via CLI
vexor auth login
# Enter email and password when prompted

# Via TUI
# Press ` (backtick) → enter email + password → click Login
```

### 2. Check backend connection

```bash
# In TUI: Dashboard shows "● Backend CONNECTED"
# Or check:
curl https://vexor-backend-fnow.onrender.com/api/v1/health
# Should return: {"status": "ok"}
```

### 3. Run your first scan

```bash
# Example: scan a test target
vexor scan https://testphp.vulnweb.com --full
```

---

## Common Workflows

### Bug Bounty Recon

```bash
# 1. OSINT first
# In TUI: F10 → enter target.com → Full Scan

# 2. Scan live hosts
vexor scan https://target.com --full

# 3. Generate report
vexor scan https://target.com --full --format pdf --output bounty_report.pdf
```

### Web App Pentest

```bash
# 1. Start proxy
vexor proxy

# 2. Configure browser: 127.0.0.1:8080

# 3. Browse the app — traffic captured in F2

# 4. Send interesting requests to Scanner/Intruder/Repeater

# 5. Run full scan
vexor scan https://target.com --full
```

### CTF / Lab

```bash
# Quick scan
vexor scan http://lab.target.com

# Specific modules
vexor scan http://lab.target.com --module sqli
vexor scan http://lab.target.com --module lfi
vexor scan http://lab.target.com --module ssti
```

---

## Offline Mode

```bash
# CLI
vexor --offline

# TUI: Ctrl+O to toggle
```

In offline mode: AI features disabled, all local modules still work.
