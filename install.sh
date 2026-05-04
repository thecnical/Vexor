#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  VEXOR — AI-Powered CLI Security Toolkit
#  Installation Script v4.1.0
#  Created by Chandan Pandey (Technical)
# ═══════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Terminal width for centering ───────────────────────────
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

center() {
    local text="$1"
    local clean="${text//$'\033'[*m/}"   # strip ANSI for length calc
    clean=$(echo -e "$clean" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#clean}
    local pad=$(( (TERM_WIDTH - len) / 2 ))
    printf "%${pad}s" ""
    echo -e "$text"
}

clear

# ─── Centered ASCII banner ───────────────────────────────────
echo ""
center "${CYAN}██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ ${NC}"
center "${CYAN}██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗${NC}"
center "${CYAN}██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝${NC}"
center "${CYAN}╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗${NC}"
center "${CYAN} ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║${NC}"
center "${CYAN}  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝${NC}"
echo ""
center "${MAGENTA}${BOLD}AI-Powered CLI Security Toolkit  v4.1.0${NC}"
center "${DIM}Penetrate. Analyze. Dominate.${NC}"
center "${DIM}Created by Chandan Pandey (Technical)${NC}"
center "${DIM}26 Modules · 6-Phase OSINT · AI-Powered${NC}"
echo ""
center "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Python ─────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Checking Python...${NC}"
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
[[ -z "$PYTHON_CMD" ]] && PYTHON_CMD="python3"
echo -e "${GREEN}    ✓ $($PYTHON_CMD --version 2>&1)${NC}"

PIP_CMD="$PYTHON_CMD -m pip"
PIP_FLAGS="--break-system-packages --quiet"

# ─── System packages via apt ────────────────────────────────
echo -e "${CYAN}[2/6] Installing via apt (pre-built, no compilation)...${NC}"
sudo apt-get update -qq 2>/dev/null

APT_PKGS=(
    # Python packages — pre-built, no cffi/build issues
    python3-pip
    python3-lxml
    python3-pydantic
    python3-cryptography
    python3-jinja2
    python3-requests
    python3-bs4
    python3-dnspython
    python3-dotenv
    python3-aiofiles
    python3-scapy
    mitmproxy
    python3-mitmproxy
    # System tools
    nmap
    openssl
    libssl-dev
    python3-dev
    gcc
    g++
    make
    libffi-dev
    libxml2-dev
    libxslt1-dev
    libcairo2
    libpango-1.0-0
    libpangocairo-1.0-0
    libgdk-pixbuf2.0-0
    shared-mime-info
    curl
    git
    wget
    net-tools
    dnsutils
)

for pkg in "${APT_PKGS[@]}"; do
    sudo apt-get install -y -qq "$pkg" 2>/dev/null && \
        echo -e "${GREEN}    ✓ $pkg${NC}" || \
        echo -e "${DIM}    - $pkg (skipped)${NC}"
done

# ─── pip packages (only what apt doesn't have) ──────────────
echo -e "${CYAN}[3/6] Installing remaining pip packages...${NC}"

pip_safe() {
    local pkg="$1"
    $PIP_CMD install "$pkg" $PIP_FLAGS 2>/dev/null && \
        echo -e "${GREEN}    ✓ $pkg${NC}" || \
        echo -e "${YELLOW}    ! $pkg (optional — skipped)${NC}"
}

# click + typer — must be compatible versions
# click 8.1.x works with typer 0.12.x
echo -e "${CYAN}    Installing click + typer (compatible versions)...${NC}"
$PIP_CMD install "click==8.1.7" $PIP_FLAGS 2>/dev/null
$PIP_CMD install "typer==0.9.4" $PIP_FLAGS 2>/dev/null && \
    echo -e "${GREEN}    ✓ typer + click (compatible)${NC}" || \
    pip_safe "typer>=0.9.0"

pip_safe "rich>=13.0.0"
pip_safe "textual>=0.60.0"
pip_safe "httpx>=0.27.0"
pip_safe "websockets>=12.0"
pip_safe "pyjwt>=2.8.0"
pip_safe "pyOpenSSL>=24.0.0"
pip_safe "aiosqlite>=0.20.0"
pip_safe "markdown>=3.6"
pip_safe "python-nmap>=0.7.1"
pip_safe "weasyprint>=62.0"

# sqlalchemy — apt version broken on Python 3.13, use pip latest
echo -e "${CYAN}    Installing sqlalchemy (Python 3.13 compatible)...${NC}"
$PIP_CMD install "sqlalchemy>=2.0.36" $PIP_FLAGS 2>/dev/null && \
    echo -e "${GREEN}    ✓ sqlalchemy (pip latest)${NC}" || \
    echo -e "${YELLOW}    ! sqlalchemy failed${NC}"

# Playwright — optional, may fail on Python 3.13
echo -e "${CYAN}    Installing playwright (optional)...${NC}"
$PIP_CMD install "playwright>=1.40.0" $PIP_FLAGS 2>/dev/null && {
    echo -e "${GREEN}    ✓ playwright${NC}"
    $PYTHON_CMD -m playwright install chromium 2>/dev/null && \
        echo -e "${GREEN}    ✓ Chromium${NC}" || true
    $PYTHON_CMD -m playwright install-deps chromium 2>/dev/null || true
} || echo -e "${YELLOW}    ! playwright (optional — skipped)${NC}"

# ─── Fix egg-info permissions ───────────────────────────────
echo -e "${CYAN}[4/6] Fixing permissions...${NC}"
EGG_DIR="$SCRIPT_DIR/cli/vexor.egg-info"
if [[ -d "$EGG_DIR" ]]; then
    rm -rf "$EGG_DIR"
    echo -e "${GREEN}    ✓ Cleaned old egg-info${NC}"
fi
# Also clean any __pycache__
find "$SCRIPT_DIR/cli" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR/cli" -name "*.pyc" -delete 2>/dev/null || true

# ─── Install Vexor ──────────────────────────────────────────
echo -e "${CYAN}[5/6] Installing Vexor...${NC}"
cd "$SCRIPT_DIR/cli"

# Try editable install
$PIP_CMD install -e . $PIP_FLAGS 2>/dev/null && \
    echo -e "${GREEN}    ✓ Vexor installed (editable)${NC}" || {

    # Fallback: no-deps editable
    echo -e "${YELLOW}    ! Trying no-deps install...${NC}"
    $PIP_CMD install -e . $PIP_FLAGS --no-deps 2>/dev/null && \
        echo -e "${GREEN}    ✓ Vexor installed (no-deps)${NC}" || {

        # Last resort: copy to site-packages manually
        echo -e "${YELLOW}    ! Trying manual install...${NC}"
        SITE_PKG=$($PYTHON_CMD -c "import site; print(site.getusersitepackages())" 2>/dev/null)
        if [[ -n "$SITE_PKG" ]]; then
            mkdir -p "$SITE_PKG"
            cp -r "$SCRIPT_DIR/cli/vexor" "$SITE_PKG/"
            echo -e "${GREEN}    ✓ Vexor copied to $SITE_PKG${NC}"
        else
            echo -e "${RED}    ✗ Install failed${NC}"
        fi
    }
}

# ─── Optional OSINT tools (Go binaries) ─────────────────────
echo -e "${CYAN}[6b/6] Installing optional OSINT tools...${NC}"

# nmap — already in apt list above, just confirm
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}    ✓ nmap (already installed)${NC}"
else
    sudo apt-get install -y -qq nmap 2>/dev/null && \
        echo -e "${GREEN}    ✓ nmap${NC}" || \
        echo -e "${DIM}    - nmap (skipped)${NC}"
fi

# findomain
if ! command -v findomain &>/dev/null; then
    echo -e "${CYAN}    Installing findomain...${NC}"
    FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-i386.zip"
    wget -q "$FINDOMAIN_URL" -O /tmp/findomain.zip 2>/dev/null && \
        unzip -q /tmp/findomain.zip -d /tmp/ 2>/dev/null && \
        chmod +x /tmp/findomain && \
        sudo mv /tmp/findomain /usr/local/bin/ 2>/dev/null && \
        echo -e "${GREEN}    ✓ findomain${NC}" || \
        echo -e "${DIM}    - findomain (skipped — install manually)${NC}"
    rm -f /tmp/findomain.zip 2>/dev/null
else
    echo -e "${GREEN}    ✓ findomain (already installed)${NC}"
fi

# Go tools — only if Go is installed
if command -v go &>/dev/null; then
    echo -e "${CYAN}    Go detected — installing OSINT tools...${NC}"
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"

    go install github.com/tomnomnom/assetfinder@latest 2>/dev/null && \
        echo -e "${GREEN}    ✓ assetfinder${NC}" || \
        echo -e "${DIM}    - assetfinder (skipped)${NC}"

    go install github.com/hakluke/hakrawler@latest 2>/dev/null && \
        echo -e "${GREEN}    ✓ hakrawler${NC}" || \
        echo -e "${DIM}    - hakrawler (skipped)${NC}"

    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        echo -e "${GREEN}    ✓ nuclei${NC}" && \
        nuclei -update-templates -silent 2>/dev/null && \
        echo -e "${GREEN}    ✓ nuclei templates updated${NC}" || \
        echo -e "${DIM}    - nuclei (skipped)${NC}"

    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
        echo -e "${GREEN}    ✓ subfinder${NC}" || \
        echo -e "${DIM}    - subfinder (skipped)${NC}"

    # Add GOPATH/bin to PATH permanently
    if ! grep -q 'GOPATH/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH="$HOME/go/bin:$PATH"' >> "$SHELL_RC"
    fi
else
    echo -e "${DIM}    - Go not found — skipping assetfinder/hakrawler${NC}"
    echo -e "${DIM}      Install Go: https://go.dev/dl/ then re-run install.sh${NC}"
fi


echo -e "${CYAN}[6/6] Setting up vexor command...${NC}"

# Create vexor wrapper script
VEXOR_BIN="$HOME/.local/bin/vexor"
mkdir -p "$HOME/.local/bin"

cat > "$VEXOR_BIN" << EOF
#!/bin/bash
exec $PYTHON_CMD -m vexor.main "\$@"
EOF
chmod +x "$VEXOR_BIN"
echo -e "${GREEN}    ✓ vexor command created at $VEXOR_BIN${NC}"

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"
SHELL_RC="$HOME/.bashrc"
[[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
if ! grep -q 'HOME/.local/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
fi

# ─── Verify ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verifying...${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

$PYTHON_CMD -c "
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
        print(f'  \033[31m✗\033[0m {pkg}')
        fail.append(pkg)
print()
if fail:
    print(f'  \033[33m[!] Missing: {fail}\033[0m')
    print(f'      Fix: sudo apt install ' + ' '.join([f'python3-{p}' for p in fail]))
else:
    print(f'  \033[32m[+] All {len(ok)} packages OK!\033[0m')
"

# ─── Done ───────────────────────────────────────────────────
echo ""
center "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

if command -v vexor &>/dev/null || [[ -f "$VEXOR_BIN" ]]; then
    center "${GREEN}${BOLD}✓ VEXOR v4.1.0 INSTALLED SUCCESSFULLY!${NC}"
else
    center "${YELLOW}Run: source ~/.bashrc  then: vexor${NC}"
fi

echo ""
center "${MAGENTA}${BOLD}COMMANDS${NC}"
echo ""
echo -e "  ${GREEN}vexor${NC}                   → Launch TUI"
echo -e "  ${GREEN}vexor scan <url>${NC}        → Quick scan"
echo -e "  ${GREEN}vexor scan <url> --full${NC} → Full scan (26 modules)"
echo -e "  ${GREEN}vexor proxy${NC}             → Start proxy"
echo -e "  ${GREEN}vexor auth login${NC}        → Login"
echo -e "  ${GREEN}vexor update${NC}            → Update to latest"
echo -e "  ${GREEN}vexor --offline${NC}         → Offline mode"
echo ""
echo -e "  ${DIM}F11 inside TUI → Config & Login${NC}"
echo -e "  ${DIM}F10 inside TUI → OSINT Intelligence Engine${NC}"
echo ""
center "${DIM}Vexor v4.1.0 · Created by Chandan Pandey (Technical)${NC}"
echo ""
