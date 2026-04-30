"""
Vexor Dependency Checker
Run: python check_deps.py
"""
import sys
import importlib
import shutil

REQUIRED = [
    ("typer",        "typer",          "CLI framework"),
    ("rich",         "rich",           "Terminal colors/UI"),
    ("textual",      "textual",        "TUI framework"),
    ("httpx",        "httpx",          "Async HTTP client"),
    ("requests",     "requests",       "HTTP client"),
    ("bs4",          "beautifulsoup4", "HTML parser"),
    ("lxml",         "lxml",           "XML/HTML parser"),
    ("jwt",          "pyjwt",          "JWT analyzer"),
    ("cryptography", "cryptography",   "SSL/crypto"),
    ("OpenSSL",      "pyOpenSSL",      "Deep SSL analysis"),
    ("jinja2",       "jinja2",         "Report templates"),
    ("pydantic",     "pydantic",       "Data validation"),
    ("dotenv",       "python-dotenv",  "Config files"),
    ("dns",          "dnspython",      "DNS/subdomain enum"),
    ("websockets",   "websockets",     "WebSocket testing"),
    ("sqlalchemy",   "sqlalchemy",     "Database ORM"),
    ("aiosqlite",    "aiosqlite",      "Async SQLite"),
]

OPTIONAL = [
    ("mitmproxy",   "mitmproxy",    "HTTP/HTTPS proxy interceptor"),
    ("scapy",       "scapy",        "Packet crafting/network"),
    ("nmap",        "python-nmap",  "Port scanning"),
    ("weasyprint",  "weasyprint",   "PDF report generation"),
    ("playwright",  "playwright",   "JS-heavy site scanning"),
]

SYSTEM_TOOLS = [
    ("nmap",    "Port scanning"),
    ("openssl", "SSL operations"),
    ("curl",    "HTTP testing"),
    ("git",     "Version control"),
]

print()
print("=" * 55)
print("  VEXOR DEPENDENCY CHECKER")
print("=" * 55)

# Required
print("\n  [REQUIRED PACKAGES]")
missing_required = []
for mod, pkg, desc in REQUIRED:
    try:
        m = importlib.import_module(mod)
        ver = getattr(m, '__version__', '?')
        print(f"  \033[32m✓\033[0m  {pkg:<22} {ver:<12} {desc}")
    except ImportError:
        print(f"  \033[31m✗\033[0m  {pkg:<22} {'MISSING':<12} {desc}")
        missing_required.append(pkg)

# Optional
print("\n  [OPTIONAL PACKAGES]")
missing_optional = []
for mod, pkg, desc in OPTIONAL:
    try:
        m = importlib.import_module(mod)
        ver = getattr(m, '__version__', '?')
        print(f"  \033[32m✓\033[0m  {pkg:<22} {ver:<12} {desc}")
    except ImportError:
        print(f"  \033[33m-\033[0m  {pkg:<22} {'not installed':<12} {desc}")
        missing_optional.append(pkg)

# System tools
print("\n  [SYSTEM TOOLS]")
for tool, desc in SYSTEM_TOOLS:
    path = shutil.which(tool)
    if path:
        print(f"  \033[32m✓\033[0m  {tool:<22} {path}")
    else:
        print(f"  \033[31m✗\033[0m  {tool:<22} not found — {desc}")

# Python version
print(f"\n  [PYTHON]")
print(f"  \033[32m✓\033[0m  Python {sys.version.split()[0]}")
if sys.version_info < (3, 11):
    print(f"  \033[31m✗\033[0m  Python 3.11+ required!")

# Summary
print()
print("=" * 55)
if missing_required:
    print(f"\n  \033[31m[!] MISSING REQUIRED ({len(missing_required)}):\033[0m")
    print(f"      pip install {' '.join(missing_required)}")
    sys.exit(1)
else:
    print(f"\n  \033[32m[+] All {len(REQUIRED)} required packages OK!\033[0m")

if missing_optional:
    print(f"\n  \033[33m[i] Optional packages ({len(missing_optional)} missing):\033[0m")
    for pkg in missing_optional:
        print(f"      pip install {pkg}")

print()
