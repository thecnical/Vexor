#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  VEXOR — AI-Powered CLI Security Toolkit
#  Installation Script v1.0.1
#  Created by Chandan Pandey (Technical)
#  Fixed for Python 3.13 + Kali Linux 2024+
# ═══════════════════════════════════════════════════════════════

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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Python Check ───────────────────────────────────────────
echo -e "${CYAN}[1/8] Checking Python...${NC}"
PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$($cmd -c "import sys; print(sys.version_info >= (3,11))" 2>/dev/null)
        if [[ "$VER" == "True" ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    echo -e "${YELLOW}    ! Python 3.11+ not found. Installing...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip
    PYTHON_CMD="python3"
fi

PYTHON_VER=$($PYTHON_CMD --version 2>&1)
echo -e "${GREEN}    ✓ $PYTHON_VER${NC}"

# Always use --break-system-packages on Kali/Debian
PIP_FLAGS="--break-system-packages"
PIP_CMD="$PYTHON_CMD -m pip"

# ─── System Dependencies (apt — most reliable) ──────────────
echo -e "${CYAN}[2/8] Installing system dependencies via apt...${NC}"
sudo apt-get update -qq 2>/dev/null

# Install Python packages via apt where possible (avoids build issues)
sudo apt-get install -y -qq \
    python3-lxml \
    python3-pydantic \
    python3-cryptography \
    python3-jinja2 \
    python3-requests \
    python3-bs4 \
    python3-dnspython \
    python3-sqlalchemy \
    python3-dotenv \
    nmap \
    openssl \
    libssl-dev \
    python3-dev \
    python3-pip \
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
    curl git wget \
    libpcap-dev \
    net-tools dnsutils \
    2>/dev/null && echo -e "${GREEN}    ✓ System packages installed${NC}" || \
    echo -e "${YELLOW}    ! Some apt packages may be missing${NC}"

# ─── Upgrade pip ────────────────────────────────────────────
echo -e "${CYAN}[3/8] Upgrading pip...${NC}"
$PIP_CMD install --upgrade pip setuptools wheel $PIP_FLAGS -q 2>/dev/null && \
    echo -e "${GREEN}    ✓ pip upgraded${NC}" || \
    echo -e "${YELLOW}    ! pip upgrade skipped${NC}"

# ─── pip install helper ─────────────────────────────────────
pip_install() {
    local pkg="$1"
    $PIP_CMD install "$pkg" $PIP_FLAGS -q 2>/dev/null && \
        echo -e "${GREEN}    ✓ $pkg${NC}" || \
        echo -e "${YELLOW}    ! $pkg failed (non-critical)${NC}"
}

# ─── Core Python Dependencies (pip — latest compatible) ─────
echo -e "${CYAN}[4/8] Installing core Python dependencies...${NC}"

# Use latest versions compatible with Python 3.13
pip_install "typer>=0.12.0"
pip_install "rich>=13.0.0"
pip_install "textual>=0.60.0"
pip_install "httpx>=0.27.0"
pip_install "requests>=2.32.0"
pip_install "websockets>=12.0"
pip_install "beautifulsoup4>=4.12.0"
pip_install "pyjwt>=2.8.0"
pip_install "pyOpenSSL>=24.0.0"
pip_install "python-dotenv>=1.0.0"
pip_install "aiosqlite>=0.20.0"
pip_install "markdown>=3.6"

# lxml — try apt version first, then pip
if ! $PYTHON_CMD -c "import lxml" 2>/dev/null; then
    echo -e "${CYAN}    Installing lxml...${NC}"
    sudo apt-get install -y -qq python3-lxml 2>/dev/null || \
    $PIP_CMD install "lxml>=5.0.0" $PIP_FLAGS -q 2>/dev/null && \
        echo -e "${GREEN}    ✓ lxml${NC}" || \
        echo -e "${YELLOW}    ! lxml failed${NC}"
else
    echo -e "${GREEN}    ✓ lxml (system)${NC}"
fi

# pydantic — try latest v2
if ! $PYTHON_CMD -c "import pydantic" 2>/dev/null; then
    pip_install "pydantic>=2.0.0"
else
    echo -e "${GREEN}    ✓ pydantic (system)${NC}"
fi

# sqlalchemy
if ! $PYTHON_CMD -c "import sqlalchemy" 2>/dev/null; then
    pip_install "sqlalchemy>=2.0.0"
else
    echo -e "${GREEN}    ✓ sqlalchemy (system)${NC}"
fi

# cryptography
if ! $PYTHON_CMD -c "import cryptography" 2>/dev/null; then
    pip_install "cryptography>=42.0.0"
else
    echo -e "${GREEN}    ✓ cryptography (system)${NC}"
fi

# jinja2
if ! $PYTHON_CMD -c "import jinja2" 2>/dev/null; then
    pip_install "jinja2>=3.1.0"
else
    echo -e "${GREEN}    ✓ jinja2 (system)${NC}"
fi

# dnspython
if ! $PYTHON_CMD -c "import dns" 2>/dev/null; then
    pip_install "dnspython>=2.6.0"
else
    echo -e "${GREEN}    ✓ dnspython (system)${NC}"
fi

# ─── Security Tools ─────────────────────────────────────────
echo -e "${CYAN}[5/8] Installing security tools...${NC}"

# scapy via apt (most reliable)
sudo apt-get install -y -qq python3-scapy 2>/dev/null && \
    echo -e "${GREEN}    ✓ scapy (apt)${NC}" || \
    pip_install "scapy>=2.5.0"

# python-nmap
pip_install "python-nmap>=0.7.1"

# mitmproxy — try apt first
echo -e "${CYAN}    Installing mitmproxy...${NC}"
sudo apt-get install -y -qq mitmproxy 2>/dev/null && \
    echo -e "${GREEN}    ✓ mitmproxy (apt)${NC}" || \
    pip_install "mitmproxy>=10.0.0"

# ─── Report Tools ───────────────────────────────────────────
echo -e "${CYAN}[6/8] Installing report tools...${NC}"
sudo apt-get install -y -qq python3-weasyprint 2>/dev/null && \
    echo -e "${GREEN}    ✓ weasyprint (apt)${NC}" || \
    pip_install "weasyprint>=62.0"

# ─── Playwright ─────────────────────────────────────────────
echo -e "${CYAN}[7/8] Installing Playwright...${NC}"
pip_install "playwright>=1.40.0"

if $PYTHON_CMD -c "import playwright" 2>/dev/null; then
    $PYTHON_CMD -m playwright install chromium 2>/dev/null && \
        echo -e "${GREEN}    ✓ Chromium installed${NC}" || \
        echo -e "${YELLOW}    ! Chromium install failed (optional)${NC}"
    $PYTHON_CMD -m playwright install-deps chromium 2>/dev/null || true
else
    echo -e "${YELLOW}    ! Playwright not available (optional — JS scanning limited)${NC}"
fi

# ─── Install Vexor ──────────────────────────────────────────
echo -e "${CYAN}[8/8] Installing Vexor...${NC}"
cd "$SCRIPT_DIR/cli"

$PIP_CMD install -e . $PIP_FLAGS -q 2>/dev/null && \
    echo -e "${GREEN}    ✓ Vexor installed${NC}" || {
    # Fallback: install without strict deps
    echo -e "${YELLOW}    ! Trying fallback install...${NC}"
    $PIP_CMD install -e . $PIP_FLAGS -q --no-deps 2>/dev/null && \
        echo -e "${GREEN}    ✓ Vexor installed (no-deps mode)${NC}" || \
        echo -e "${RED}    ✗ Vexor install failed${NC}"
}

# ─── PATH Setup ─────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"
SHELL_RC="$HOME/.bashrc"
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
ok, fail = [], []
pkgs = [
    ('typer','typer'), ('rich','rich'), ('textual','textual'),
    ('httpx','httpx'), ('requests','requests'), ('bs4','beautifulsoup4'),
    ('lxml','lxml'), ('jwt','pyjwt'), ('cryptography','cryptography'),
    ('jinja2','jinja2'), ('pydantic','pydantic'),
    ('dotenv','python-dotenv'), ('dns','dnspython'),
    ('websockets','websockets'), ('sqlalchemy','sqlalchemy'),
    ('aiosqlite','aiosqlite'),
]
print()
for mod, pkg in pkgs:
    try:
        __import__(mod)
        print(f'  \033[32m✓\033[0m {pkg}')
        ok.append(pkg)
    except ImportError:
        print(f'  \033[31m✗\033[0m {pkg}  MISSING')
        fail.append(pkg)
print()
if fail:
    print(f'  \033[33m[!] Some packages missing: {fail}\033[0m')
    print(f'      Try: sudo apt install python3-{\" python3-\".join(fail)}')
else:
    print(f'  \033[32m[+] All {len(ok)} core packages OK!\033[0m')
"

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

if command -v vexor &>/dev/null; then
    echo -e "${GREEN}${BOLD}  ✓ VEXOR INSTALLED SUCCESSFULLY!${NC}"
    echo ""
    echo -e "  ${CYAN}Version:${NC} $(vexor --version 2>/dev/null || echo 'v1.0.0')"
else
    echo -e "${YELLOW}  Run: source ~/.bashrc  then: vexor${NC}"
fi

echo ""
echo -e "${MAGENTA}  COMMANDS:${NC}"
echo -e "  ${GREEN}vexor${NC}                   → Launch TUI"
echo -e "  ${GREEN}vexor scan <url>${NC}        → Quick scan"
echo -e "  ${GREEN}vexor scan <url> --full${NC} → Full scan"
echo -e "  ${GREEN}vexor proxy${NC}             → Start proxy"
echo -e "  ${GREEN}vexor auth login${NC}        → Login"
echo -e "  ${GREEN}vexor update${NC}            → Update Vexor"
echo -e "  ${GREEN}vexor --offline${NC}         → Offline mode"
echo ""
echo -e "${DIM}  Created by Chandan Pandey (Technical)${NC}"
echo ""
