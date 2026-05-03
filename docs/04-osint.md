# Vexor OSINT Intelligence Engine — Complete Guide

The OSINT engine runs a **6-phase automated pipeline**. Just provide a target — Vexor does everything.

---

## TUI Usage

1. Press `F10` to open OSINT screen
2. Enter target (domain, IP, or URL)
3. Select scan mode
4. Press Enter or click **🕵️ Start OSINT**

### Scan Modes

| Mode | What it runs |
|------|-------------|
| 🚀 Full Scan | All 6 phases (recommended) |
| ⚡ Quick Scan | Direct modules only (no backend) |
| 🌐 DNS + Subdomains | Phase 1 only |
| 🔍 Threat Intel | Backend modules only (Shodan/VT/OTX) |
| 🔒 SSL + Headers | SSL chain + tech fingerprint |

---

## CLI Usage

```bash
# OSINT via scanner
vexor scan https://target.com --module osint

# Full scan includes OSINT
vexor scan https://target.com --full
```

---

## The 6 Phases

### Phase 1: Discovery

**What it does:** Finds all subdomains and infrastructure.

**Sources used:**
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- DNS zone transfer attempt
- Certificate Transparency logs (crt.sh — 200 certs)
- WHOIS (registrar, creation date, expiry)
- ASN/BGP data (BGPView — free, no key)
- HackerTarget passive DNS
- RapidDNS passive DNS
- SSL certificate SANs
- Assetfinder (if installed)
- Findomain (if installed)

**Example output:**
```
[+] DNS Records Enumerated
    A: 93.184.216.34
    MX: mail.example.com
    NS: ns1.example.com, ns2.example.com

[+] CT Logs: 47 Subdomains Found
    api.example.com
    dev.example.com
    staging.example.com
    ...

[+] WHOIS: Domain Registration Info
    Registrar: GoDaddy
    Created: 2010-03-15
    Expires: 2025-03-15
```

---

### Phase 2: Live Host Check

**What it does:** Checks which discovered subdomains are actually alive.

**Method:** Async httpx check (30 concurrent) — tries HTTPS first, then HTTP.

**Example output:**
```
[+] Live Hosts: 23 Responding
    200 https://api.example.com [API Gateway]
    200 https://dev.example.com [Development Server]
    403 https://admin.example.com [Admin Panel]
    200 https://staging.example.com [Staging]
```

---

### Phase 3: Deep Recon

**What it does:** Deep analysis of each live host.

**Checks:**
- Port scan (top 20 ports)
- SSL certificate chain analysis
- Technology fingerprinting (server, framework, CMS)
- Wayback Machine historical URLs
- Email harvesting
- SPF/DMARC/DKIM email security
- Social media presence
- Hakrawler crawl (if installed)
- Subdomain takeover detection (27 cloud services)

**Example output:**
```
[+] Open Ports: 3 found (1 high-risk)
    80/HTTP, 443/HTTPS, ⚠ 3306/MySQL

[+] Technology Stack Identified
    Web Server: nginx/1.18.0
    Framework: Laravel
    CDN: Cloudflare

[+] Subdomain Takeover: dev.example.com → Heroku
    CNAME: dev.example.com → example.herokuapp.com
    Status: CNAME target does not resolve — TAKEOVER POSSIBLE
```

---

### Phase 4: Secret Extraction (Gf Patterns)

**What it does:** Scans all discovered URLs for secrets and vulnerable parameters.

**Patterns detected:**
- API keys (AWS, GitHub, Stripe, Google, etc.)
- JWT tokens
- SQLi-prone parameters (`?id=`, `?page=`, `?cat=`)
- XSS-prone parameters (`?q=`, `?search=`, `?name=`)
- Open redirect parameters (`?url=`, `?redirect=`, `?next=`)
- SSRF parameters (`?url=`, `?host=`, `?proxy=`)
- Sensitive file extensions (`.env`, `.git`, `.sql`, `.key`)

**Example output:**
```
[HIGH] Gf Pattern [api-keys]: 3 URLs
    https://example.com/js/app.js?api_key=AIza...
    https://example.com/config.js?stripe_key=sk_live_...

[MEDIUM] Gf Pattern [sqli-params]: 12 URLs
    https://example.com/products?id=1
    https://example.com/user?page=2
```

---

### Phase 5: Threat Intelligence

**What it does:** Queries threat intel APIs for reputation, CVEs, and malware history.

**Requires:** API keys configured on Render backend.

| Module | What it provides |
|--------|-----------------|
| **Shodan** | Open ports, CVEs, banners, OS |
| **VirusTotal** | Malware history, passive DNS, reputation |
| **AlienVault OTX** | Threat pulses, malware samples |
| **URLScan.io** | Scan history, malicious resources |
| **Chaos DB** | 50M+ passive subdomains |

**Check backend status:**
In TUI OSINT screen → click **📊 Backend Status**

**Example output:**
```
[CRITICAL] Shodan: 5 ports, 2 CVEs
    IP: 93.184.216.34
    CVEs: CVE-2021-44228, CVE-2022-22965
    Open Ports: 80, 443, 8080, 8443, 22

[HIGH] VirusTotal: MALICIOUS (3 engines)
    Malicious: 3/89 engines
    Reputation: -5
```

---

### Phase 6: AI Correlation

**What it does:** Sends all findings to Vexor Intelligence AI for deep analysis.

**AI produces:**
1. Attack surface mapping
2. Top 5 critical findings with exploitation paths
3. Attack chain construction (initial access → full compromise)
4. Intelligence correlations (e.g., leaked email + no DMARC = phishing possible)
5. Threat actor profile (MITRE ATT&CK mapping)
6. Immediate action items (top 3 fixes)
7. OSINT gaps (what to investigate next)

**Requires:** Login (`vexor auth login`)

---

## Export Results

In TUI OSINT screen → click **📤 Export JSON**

Results saved to: `~/.vexor/reports/osint_[target]_[timestamp].json`

---

## Scan History

The OSINT screen shows last 5 scanned targets in the history bar.

---

## External Tools Integration

If installed, these tools are automatically used:

```bash
# Install for better subdomain discovery
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install for live site crawling
go install github.com/hakluke/hakrawler@latest

# Install for passive subdomain DB
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

Vexor auto-detects these — no configuration needed.

---

## Example: Full OSINT on a Target

```
Target: example.com

Phase 1 → Found 47 subdomains
Phase 2 → 23 alive (49%)
Phase 3 → 3 high-risk ports, 1 subdomain takeover
Phase 4 → 2 API keys, 12 SQLi params
Phase 5 → 2 CVEs on Shodan, clean on VT
Phase 6 → AI: "Chain: subdomain takeover → phishing → credential harvest"

Total findings: 34
CRITICAL: 3 | HIGH: 8 | MEDIUM: 12 | LOW: 11
```
