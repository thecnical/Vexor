# Vexor Intruder & Repeater — Complete Guide

---

## Repeater (F5)

Manually modify and resend HTTP requests.

### Usage

1. Press `F5` → Repeater screen
2. Enter URL in the URL field
3. Edit the request in the REQUEST panel
4. Click **▶ Send** or press Enter
5. Response appears in the RESPONSE panel

### Request Format

```
GET /api/user?id=1 HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Cookie: session=abc123

```

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"test"}
```

### Buttons

| Button | Action |
|--------|--------|
| ▶ Send | Send the request |
| 🔍 Send to Scanner | Run all vuln modules on this URL |
| ⚔ Send to Intruder | Send URL + request to Intruder |
| 🤖 AI Analyze | AI analysis of request/response |
| ⊘ Clear | Clear request and response |

### Example: Testing SQL Injection Manually

```
# Original request:
GET /user?id=1 HTTP/1.1
Host: target.com

# Modified request (test SQLi):
GET /user?id=1' HTTP/1.1
Host: target.com

# If error in response → SQLi confirmed
```

---

## Intruder (F4)

Automated fuzzing with 50 parallel requests.

### Usage

1. Press `F4` → Intruder screen
2. Enter target URL
3. Edit request template — mark positions with `§payload§`
4. Add payloads (one per line)
5. Select attack type
6. Click **▶ Start Attack**

### Request Template

```
POST /login HTTP/1.1
Host: target.com

username=§admin§&password=§password§
```

The `§` markers define injection positions.

### Attack Types

| Type | Description | Use case |
|------|-------------|----------|
| **Sniper** | One position at a time | Password brute force |
| **Battering Ram** | Same payload in all positions | Username = password |
| **Pitchfork** | Parallel payloads | Username list + password list |
| **Cluster Bomb** | All combinations | Full credential stuffing |

### Payload Sources

#### Built-in Payloads
Click **📚 Built-in** → selects context-appropriate payloads:
- Auth bypass: `admin`, `root`, `' OR 1=1--`
- SQLi: `'`, `' OR 1=1--`, `' UNION SELECT NULL--`
- XSS: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`

#### AI-Generated Payloads
Click **🤖 AI Payloads** → AI generates context-aware payloads based on:
- URL and request template
- Detected parameter names
- Target technology

#### SecLists (Auto-Download)
Click **📂 Load File** → automatically downloads from SecLists GitHub:
- Password form → top 1000 passwords
- Search form → XSS payloads
- ID parameter → SQLi payloads

#### Manual Payloads
Type directly in the payload box (one per line):
```
admin
administrator
root
test
guest
```

### Results Analysis

Results are sorted: **interesting first**.

"Interesting" = different from majority:
- Different status code (e.g., 200 when others return 401)
- Significantly different response length
- Slow response (>3s = possible time-based SQLi)

| Indicator | Meaning |
|-----------|---------|
| 🔓 Auth bypass? | Status 200 when others return 401/403 |
| 🔀 Redirect | 301/302 redirect |
| 💥 Server error | 500 Internal Server Error |
| 📏 Len diff X% | Response length differs significantly |
| ⏱ Slow response | Response took >3 seconds |

### Example: Brute Force Login

```
URL: https://target.com/login
Template:
  POST /login HTTP/1.1
  Host: target.com
  
  username=admin&password=§password§

Payloads:
  password
  123456
  admin
  letmein
  qwerty

Attack type: Sniper
```

### Example: Parameter Fuzzing

```
URL: https://target.com/search?q=§payload§
Template:
  GET /search?q=§payload§ HTTP/1.1
  Host: target.com

Payloads (SQLi):
  '
  ' OR 1=1--
  ' UNION SELECT NULL--
  ' AND SLEEP(3)--

Attack type: Sniper
```

### Stats Bar

During attack:
```
15.3 req/s  ·  3 interesting  ·  0 errors
```

---

## Tips

### Finding Auth Bypass

```
URL: https://target.com/admin
Payloads: (empty - just send request with bypass headers)
Use Repeater with headers:
  X-Forwarded-For: 127.0.0.1
  X-Original-URL: /admin
```

### Finding SQLi via Intruder

```
URL: https://target.com/product?id=§id§
Payloads:
  1
  1'
  1 OR 1=1
  1 AND SLEEP(3)
  1 UNION SELECT NULL

Look for: 500 errors, slow responses, different lengths
```

### Credential Stuffing

```
Attack type: Pitchfork
Position 1 (username): admin, user, test, john
Position 2 (password): password, 123456, admin, letmein

Each username paired with corresponding password
```
