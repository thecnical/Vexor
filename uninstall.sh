#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  VEXOR — Uninstall Script (Linux/WSL/Kali)
#  Removes Vexor completely from Linux system
# ═══════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${RED}"
echo "  ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ "
echo "  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║ "
echo "   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${RED}  VEXOR — Uninstall Script${NC}"
echo ""
echo -e "${YELLOW}  This will remove Vexor from your system.${NC}"
echo ""
read -p "  Are you sure? Type 'YES' to confirm: " CONFIRM

if [[ "$CONFIRM" != "YES" ]]; then
    echo -e "${YELLOW}  Cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${CYAN}  Removing Vexor...${NC}"
echo ""

# ─── Remove pip package ─────────────────────────────────────
echo -e "${CYAN}  [1/5] Removing pip package...${NC}"
pip3 uninstall vexor -y 2>/dev/null && \
    echo -e "${GREEN}  ✓ pip package removed${NC}" || \
    echo -e "${YELLOW}  - pip package not found${NC}"

# ─── Remove vexor command ───────────────────────────────────
echo -e "${CYAN}  [2/5] Removing vexor command...${NC}"
VEXOR_BIN=$(which vexor 2>/dev/null)
if [[ -n "$VEXOR_BIN" ]]; then
    rm -f "$VEXOR_BIN"
    echo -e "${GREEN}  ✓ vexor binary removed: $VEXOR_BIN${NC}"
else
    # Check common locations
    for loc in "$HOME/.local/bin/vexor" "/usr/local/bin/vexor" "/usr/bin/vexor"; do
        if [[ -f "$loc" ]]; then
            rm -f "$loc"
            echo -e "${GREEN}  ✓ Removed: $loc${NC}"
        fi
    done
fi

# ─── Remove Vexor data directory ────────────────────────────
echo -e "${CYAN}  [3/5] Removing Vexor data (~/.vexor)...${NC}"
if [[ -d "$HOME/.vexor" ]]; then
    rm -rf "$HOME/.vexor"
    echo -e "${GREEN}  ✓ ~/.vexor removed${NC}"
else
    echo -e "${YELLOW}  - ~/.vexor not found${NC}"
fi

# ─── Remove Vexor repo ──────────────────────────────────────
echo -e "${CYAN}  [4/5] Removing Vexor repo...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Remove ~/Vexor if it exists
if [[ -d "$HOME/Vexor" ]]; then
    rm -rf "$HOME/Vexor"
    echo -e "${GREEN}  ✓ ~/Vexor removed${NC}"
fi

# Remove current directory if it's the Vexor repo
if [[ -f "$SCRIPT_DIR/install.sh" ]] && [[ "$SCRIPT_DIR" != "$HOME" ]]; then
    echo -e "${YELLOW}  ! Current directory is Vexor repo${NC}"
    echo -e "${YELLOW}    Delete manually: rm -rf $SCRIPT_DIR${NC}"
fi

# ─── Clean shell config ─────────────────────────────────────
echo -e "${CYAN}  [5/5] Cleaning shell config...${NC}"

for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$RC" ]]; then
        if grep -q "vexor\|VEXOR" "$RC" 2>/dev/null; then
            sed -i '/vexor/Id' "$RC"
            sed -i '/VEXOR/d' "$RC"
            echo -e "${GREEN}  ✓ Cleaned: $RC${NC}"
        fi
    fi
done

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}  ║   ✓ Vexor uninstalled successfully   ║${NC}"
echo -e "${GREEN}  ╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}  To reinstall: ./install.sh${NC}"
echo -e "${YELLOW}  Or: git clone https://github.com/thecnical/Vexor${NC}"
echo ""
