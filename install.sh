#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  VEXOR — AI-Powered CLI Security Toolkit
#  Installation Script
#  Created by Chandan Pandey (Technical)
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo "██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ "
echo "██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗"
echo "██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝"
echo "╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗"
echo " ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║"
echo "  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${MAGENTA}${BOLD}  AI-Powered CLI Security Toolkit v1.0.0${NC}"
echo -e "${DIM}  Penetrate. Analyze. Dominate.${NC}"
echo -e "${DIM}  Created by Chandan Pandey (Technical)${NC}"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

# ─── OS Check ───────────────────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "linux-musl"* ]]; then
    echo -e "${YELLOW}[!] Non-Linux detected. Vexor runs on Linux/WSL only.${NC}"
    echo -e "${YELLOW}    Windows users: Install WSL → wsl --install${NC}"
    echo ""
fi

# ─── Python Check ───────────────────────────────────────────
echo -e "${CYAN}[1/8] Checking Python 3.11+...${NC}"
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.13 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$($cmd -c "import sys; print(sys.version_info >= (3,11))" 2>/dev/null)
        if [[ "$VER" == "True" ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    echo -e "${YELLOW}[!] Python 3.11+ not found. Installing...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y python3.11 python3.11-pip python3.11-venv 2>/dev/null || \
    sudo apt-get install -y python3 python3-pip python3-venv
    PYTHON_CMD="python3"
fi

echo -e "${GREEN}    ✓ $($PYTHON_CMD --version)${NC}"
PIP_CMD="$PYTHON_CMD -m pip"

# ─── System Dependencies ────────────────────────────────────
echo -e "${CYAN}[2/8] Installing system dependencies...${NC}"
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq \
    nmap \
    openssl \
    libssl-dev \
    python3-dev \
    gcc \
    g++ \
    make \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    curl \
    git \
    wget \
    libpcap-dev \
    net-tools \
    dnsutils \
    2>/dev/null && echo -e "${GREEN}    ✓ System packages installed${NC}" || \
    echo -e "${YELLOW}    ! Some system packages may be missing${NC}"

# ─── Upgrade pip ────────────────────────────────────────────
echo -e "${CYAN}[3/8] Upgrading pip...${NC}"
$PIP_CMD install --upgrade pip setuptools wheel --quiet
echo -e "${GREEN}    ✓ pip upgraded${NC}"

# ─── Core Python Dependencies ───────────────────────────────
echo -e "${CYAN}[4/8] Installing core Python dependencies...${NC}"

CORE_DEPS=(
    "typer==0.12.3"
    "rich==13.7.1"
    "textual==0.60.0"
    "httpx==0.27.0"
    "requests==2.32.3"
    "websockets==12.0"
    "beautifulsoup4==4.12.3"
    "lxml==5.2.2"
    "pyjwt==2.8.0"
    "cryptography==42.0.8"
    "pyOpenSSL==24.1.0"
    "jinja2==3.1.4"
    "pydantic==2.7.1"
    "python-dotenv==1.0.1"
    "dnspython==2.6.1"
    "sqlalchemy==2.0.30"
    "aiosqlite==0.20.0"
    "markdown==3.6"
)

for dep in "${CORE_DEPS[@]}"; do
    $PIP_CMD install "$dep" --quiet && \
        echo -e "${GREEN}    ✓ $dep${NC}" || \
        echo -e "${YELLOW}    ! $dep failed${NC}"
done

# ─── Security Tools ─────────────────────────────────────────
echo -e "${CYAN}[5/8] Installing security tools...${NC}"

# Scapy — packet crafting (world's best)
$PIP_CMD install "scapy==2.5.0" --quiet && \
    echo -e "${GREEN}    ✓ scapy (packet crafting)${NC}" || \
    echo -e "${YELLOW}    ! scapy failed${NC}"

# mitmproxy — HTTP proxy (world's best)
$PIP_CMD install "mitmproxy==10.3.1" --quiet && \
    echo -e "${GREEN}    ✓ mitmproxy (HTTP proxy)${NC}" || \
    echo -e "${YELLOW}    ! mitmproxy failed — proxy limited${NC}"

# python-nmap — port scanning
$PIP_CMD install "python-nmap==0.7.1" --quiet && \
    echo -e "${GREEN}    ✓ python-nmap (port scanning)${NC}" || \
    echo -e "${YELLOW}    ! python-nmap failed${NC}"

# ─── Report Tools ───────────────────────────────────────────
echo -e "${CYAN}[6/8] Installing report tools...${NC}"

$PIP_CMD install "weasyprint==62.3" --quiet && \
    echo -e "${GREEN}    ✓ weasyprint (PDF reports)${NC}" || \
    echo -e "${YELLOW}    ! weasyprint failed — PDF unavailable${NC}"

# ─── Playwright (JS scanning) ───────────────────────────────
echo -e "${CYAN}[7/8] Installing Playwright (JS-heavy site scanning)...${NC}"

$PIP_CMD install "playwright==1.44.0" --quiet && \
    echo -e "${GREEN}    ✓ playwright installed${NC}" || \
    echo -e "${YELLOW}    ! playwright failed${NC}"

# Install Playwright browsers
if $PYTHON_CMD -c "import playwright" 2>/dev/null; then
    echo -e "${CYAN}    Installing Chromium browser...${NC}"
    $PYTHON_CMD -m playwright install chromium 2>/dev/null && \
        echo -e "${GREEN}    ✓ Chromium installed${NC}" || \
        echo -e "${YELLOW}    ! Chromium install failed${NC}"

    # Install system deps for Playwright
    $PYTHON_CMD -m playwright install-deps chromium 2>/dev/null || true
fi

# ─── Install Vexor ──────────────────────────────────────────
echo -e "${CYAN}[8/8] Installing Vexor...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/cli"

$PIP_CMD install -e . --quiet && \
    echo -e "${GREEN}    ✓ Vexor installed${NC}" || \
    { echo -e "${RED}    ✗ Vexor install failed${NC}"; exit 1; }

# ─── PATH Setup ─────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"

SHELL_RC="$HOME/.bashrc"
[[ -n "$ZSH_VERSION" ]] && SHELL_RC="$HOME/.zshrc"
[[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"

if ! grep -q 'HOME/.local/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
fi

# ─── Verify ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verifying installation...${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

$PYTHON_CMD -c "
import sys
ok = []
fail = []
warn = []

# Required
required = [
    ('typer', 'typer'),
    ('rich', 'rich'),
    ('textual', 'textual'),
    ('httpx', 'httpx'),
    ('requests', 'requests'),
    ('bs4', 'beautifulsoup4'),
    ('lxml', 'lxml'),
    ('jwt', 'pyjwt'),
    ('cryptography', 'cryptography'),
    ('OpenSSL', 'pyOpenSSL'),
    ('jinja2', 'jinja2'),
    ('pydantic', 'pydantic'),
    ('dotenv', 'python-dotenv'),
    ('dns', 'dnspython'),
    ('websockets', 'websockets'),
    ('sqlalchemy', 'sqlalchemy'),
    ('aiosqlite', 'aiosqlite'),
]

# Optional
optional = [
    ('mitmproxy', 'mitmproxy'),
    ('scapy', 'scapy'),
    ('nmap', 'python-nmap'),
    ('weasyprint', 'weasyprint'),
    ('playwright', 'playwright'),
]

print()
print('  REQUIRED:')
for mod, pkg in required:
    try:
        __import__(mod)
        print(f'  \033[32m✓\033[0m {pkg}')
        ok.append(pkg)
    except ImportError:
        print(f'  \033[31m✗\033[0m {pkg}  ← MISSING')
        fail.append(pkg)

print()
print('  OPTIONAL:')
for mod, pkg in optional:
    try:
        __import__(mod)
        print(f'  \033[32m✓\033[0m {pkg}')
    except ImportError:
        print(f'  \033[33m-\033[0m {pkg}  (not installed)')
        warn.append(pkg)

print()
if fail:
    print(f'  \033[31m[!] Missing required: {fail}\033[0m')
    print(f'      Fix: pip install {\" \".join(fail)}')
    sys.exit(1)
else:
    print(f'  \033[32m[+] All {len(ok)} required packages OK!\033[0m')
    if warn:
        print(f'  \033[33m[i] Optional missing: {warn}\033[0m')
"

# ─── System tools check ─────────────────────────────────────
echo ""
echo -e "  ${CYAN}SYSTEM TOOLS:${NC}"
for tool in nmap openssl curl git; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${YELLOW}!${NC} $tool not found"
    fi
done

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

if command -v vexor &>/dev/null; then
    echo -e "${GREEN}${BOLD}  ✓ VEXOR INSTALLED SUCCESSFULLY!${NC}"
    echo ""
    echo -e "  ${CYAN}Version:${NC} $(vexor --version 2>/dev/null || echo '1.0.0')"
else
    echo -e "${YELLOW}  Run: source ~/.bashrc  then: vexor${NC}"
fi

echo ""
echo -e "${MAGENTA}  COMMANDS:${NC}"
echo -e "  ${GREEN}vexor${NC}                      → Launch TUI"
echo -e "  ${GREEN}vexor scan <url>${NC}           → Quick scan"
echo -e "  ${GREEN}vexor scan <url> --full${NC}    → Full scan (25 modules)"
echo -e "  ${GREEN}vexor scan <url> --module sqli${NC} → Single module"
echo -e "  ${GREEN}vexor proxy${NC}                → Start HTTP proxy"
echo -e "  ${GREEN}vexor auth login${NC}           → Login to backend"
echo -e "  ${GREEN}vexor --offline${NC}            → Offline mode"
echo -e "  ${GREEN}vexor --help${NC}               → Full help"
echo ""
echo -e "${DIM}  Created by Chandan Pandey (Technical)${NC}"
echo -e "${DIM}  Penetrate. Analyze. Dominate.${NC}"
echo ""
