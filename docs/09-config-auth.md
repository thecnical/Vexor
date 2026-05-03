# Vexor Config & Authentication — Complete Guide

---

## Authentication

### Why Login?

Login enables:
- AI features (analyze, PoC generation, OSINT correlation)
- Backend threat intel (Shodan, VirusTotal, OTX)
- Cloud sync (save findings to cloud)
- Team collaboration

**Without login:** AI works in guest mode (auto-registered), basic features work.

### Login via CLI

```bash
vexor auth login
# Enter email: your@email.com
# Enter password: ••••••••
```

### Login via TUI

1. Press `` ` `` (backtick) → Config screen
2. Enter email and password
3. Click **🔑 Login**

### Check Login Status

```bash
vexor auth status
# ✓ Logged in
# or
# Not logged in  Run: vexor auth login
```

### Logout

```bash
vexor auth logout
```

### Register New Account

```bash
# Via backend API
curl -X POST https://vexor-backend-fnow.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword","username":"yourname"}'
```

---

## Config Screen (`` ` ``)

Press `` ` `` (backtick) to open Config screen.

### Backend Connection

```
Backend URL: https://vexor-backend-fnow.onrender.com
```

Click **🔗 Test Connection** to verify backend is reachable.

To use a custom backend:
1. Enter your backend URL
2. Click **💾 Save**
3. Restart Vexor

### Scan Defaults

| Setting | Default | Description |
|---------|---------|-------------|
| Timeout | 30s | Request timeout per module |
| Threads | 10 | Concurrent requests |

---

## Environment Variables

```bash
# Custom backend URL
export VEXOR_BACKEND_URL=https://your-backend.com

# Then launch
vexor
```

---

## Config File

Location: `~/.vexor/config.json`

```json
{
  "backend_url": "https://vexor-backend-fnow.onrender.com",
  "timeout": 30,
  "threads": 10
}
```

---

## Scope Management

Define which targets are in-scope for testing.

### Scope File

Location: `~/.vexor/scope.txt`

```bash
# Edit scope file
nano ~/.vexor/scope.txt
```

### Scope File Format

```
# Lines starting with # are comments

# Exact domain
example.com

# Wildcard (all subdomains)
*.example.com

# IP address
192.168.1.1

# CIDR range
192.168.1.0/24

# Exclusion (prefix with !)
!staging.example.com
!dev.example.com
```

### Rules

- Empty scope file = everything is in scope
- `!` prefix = exclude this target
- Wildcards: `*.example.com` matches all subdomains

---

## Plugins (F12)

### Plugin Location

```bash
~/.vexor/plugins/
```

### Create a Plugin

```python
# ~/.vexor/plugins/my_scanner.py
from vexor.modules.base import BaseScanner, Finding

class Scanner(BaseScanner):
    MODULE_NAME = "my_scanner"
    MODULE_DESC = "My Custom Scanner"
    
    async def scan(self) -> list[Finding]:
        async with self:
            resp = await self.get(self.target)
            if resp and "vulnerable" in resp.text:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=self.MODULE_NAME,
                    vuln="Custom Vulnerability Found",
                    endpoint=self.target,
                    evidence="Found 'vulnerable' in response",
                    description="Custom check detected an issue",
                    remediation="Fix the issue",
                ))
        return self.findings
```

### Load Plugin

1. Place `.py` file in `~/.vexor/plugins/`
2. Press `F12` → Plugins → Click **🔄 Refresh**
3. Plugin appears in list

---

## Data Storage

All Vexor data is stored in `~/.vexor/`:

```
~/.vexor/
├── config.json          # Settings
├── token.json           # Auth token
├── vexor.db             # SQLite database (findings, notes, sessions)
├── scope.txt            # Scope file
├── sessions/            # Scan sessions
├── reports/             # Generated reports
│   └── screenshots/     # Visual recon screenshots
├── logs/                # Log files
└── plugins/             # Custom plugins
```

### Backup Data

```bash
cp -r ~/.vexor ~/vexor_backup
```

### Clear All Data

```bash
rm -rf ~/.vexor
vexor  # Will recreate on next launch
```
