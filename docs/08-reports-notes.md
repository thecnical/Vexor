# Vexor Reports & Notes — Complete Guide

---

## Reports (F7)

Generate professional security reports from scan findings.

### Report Templates

| Template | Best for |
|----------|----------|
| **Full Technical** | Complete pentest report with all details |
| **Executive Summary** | Management-level overview |
| **Bug Bounty** | HackerOne/Bugcrowd submission format |
| **Pentest Report** | Professional penetration test report |
| **OSINT Intelligence** | OSINT findings report |

### Generate Report (TUI)

1. Press `F7` → Reports screen
2. Enter report title
3. Select template
4. Select format (HTML/PDF/JSON)
5. Click **📄 Generate**

### Generate Report (CLI)

```bash
# HTML report
vexor scan https://target.com --full --format html --output report.html

# PDF report
vexor scan https://target.com --full --format pdf --output report.pdf

# JSON export
vexor scan https://target.com --full --format json --output findings.json
```

### Generate from Database

Click **📊 From DB** → generates report from all persisted findings (SQLite).

### AI Enhancement

Click **🤖 AI Enhance** → AI rewrites findings in professional language.

### Report Location

```bash
ls ~/.vexor/reports/
# vexor_full_20240115_143022.html
# vexor_executive_20240115_143022.pdf
# osint_example_com_20240115_143022.json
```

---

## Notes (Ctrl+N)

Persistent pentest notes that survive app restarts.

### Open Notes

Press `Ctrl+N` → Notes screen

### Create a Note

1. Click **➕ New**
2. Enter title (required)
3. Enter target (optional — links note to a target)
4. Write content in the editor (Markdown supported)
5. Click **💾 Save Note**

### Note Format (Markdown)

```markdown
# Target: example.com

## Findings Summary
- SQL injection in /user?id=1 (CRITICAL)
- Admin panel at /admin (403 - test bypass)
- Dev subdomain: dev.example.com

## Credentials Found
- admin:password123 (login page)
- API key: AIza... (JS file)

## Next Steps
- [ ] Test admin panel bypass
- [ ] Extract database via SQLi
- [ ] Check dev subdomain for staging data

## Timeline
- 14:00 - Started recon
- 14:30 - Found SQLi
- 15:00 - Confirmed admin bypass
```

### Manage Notes

| Button | Action |
|--------|--------|
| ➕ New | Create new note |
| 💾 Save Note | Save current note |
| 🗑 Delete | Delete selected note |
| 🔄 Refresh | Reload notes from database |

### Notes Storage

Notes are stored in SQLite: `~/.vexor/vexor.db`

They persist across:
- App restarts
- System reboots
- Updates

---

## Decoder (F8)

Encode and decode data in various formats.

### Supported Formats

| Format | Encode | Decode |
|--------|--------|--------|
| Base64 | ✅ | ✅ |
| URL encoding | ✅ | ✅ |
| HTML entities | ✅ | ✅ |
| Hex | ✅ | ✅ |
| ROT13 | ✅ | ✅ |
| JWT | ❌ | ✅ (decode payload) |

### Usage

1. Press `F8` → Decoder screen
2. Paste input text
3. Select format
4. Click Encode or Decode

### Example: Decode JWT

```
Input: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx

Output:
Header: {"alg":"HS256","typ":"JWT"}
Payload: {"user":"admin"}
```

---

## Comparer (F9)

Compare two HTTP requests or responses side-by-side.

### Usage

1. Press `F9` → Comparer screen
2. Paste first request/response in left panel
3. Paste second in right panel
4. Differences are highlighted

### Use Cases

- Compare responses for true/false SQLi conditions
- Compare authenticated vs unauthenticated responses
- Compare before/after payload injection
