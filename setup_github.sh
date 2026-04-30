#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  Vexor — GitHub Push Script
#  Repo 1: thecnical/Vexor       (CLI — Public)
#  Repo 2: thecnical/Vexor-Backend (Backend — Private)
# ═══════════════════════════════════════════════════════════════

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     VEXOR — GitHub Push                  ║"
echo "  ║     CLI → Public  |  Backend → Private   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Git config check ───────────────────────────────────────
if [[ -z "$(git config --global user.name 2>/dev/null)" ]]; then
    read -p "  Git name: " GIT_NAME
    git config --global user.name "$GIT_NAME"
fi
if [[ -z "$(git config --global user.email 2>/dev/null)" ]]; then
    read -p "  Git email: " GIT_EMAIL
    git config --global user.email "$GIT_EMAIL"
fi

# ═══════════════════════════════════════════════════════════════
#  REPO 1 — CLI (Public)
#  https://github.com/thecnical/Vexor
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  REPO 1: thecnical/Vexor (CLI — Public)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cd "$SCRIPT_DIR"

# Init git if needed
if [[ ! -d ".git" ]]; then
    git init
    echo -e "${GREEN}  ✓ Git initialized${NC}"
fi

# Make sure backend/ is excluded
if ! grep -q "^backend/" .gitignore 2>/dev/null; then
    echo "backend/" >> .gitignore
fi

echo -e "${CYAN}  Staging CLI files (backend excluded)...${NC}"
git add .
git reset HEAD backend/ 2>/dev/null || true  # unstage backend if accidentally added

# Show what will be committed
echo -e "${CYAN}  Files to commit:${NC}"
git status --short | grep -v "^??" | head -30

echo ""
git commit -m "🔥 Vexor v1.0.0 — AI-Powered CLI Security Toolkit

26 security modules: SQLi, XSS, CSRF, IDOR, SSRF, XXE, LFI,
JWT, SSL, CORS, Headers, WebSocket, API, Port Scanner,
Rate Limit, Open Redirect, File Upload, Session, Fingerprint,
Subdomain, DirBust, CVE, Wayback, GitHub Dork, Sensitive Data, Auth Bypass

Features:
- Beautiful TUI (Textual)
- AI analysis (Groq → NVIDIA → OpenRouter → HuggingFace)
- Offline mode
- HTML/PDF reports
- Plugin system
- One-click install

Created by Chandan Pandey (Technical)
Penetrate. Analyze. Dominate." 2>/dev/null || \
git commit --allow-empty -m "🔥 Vexor v1.0.0 — AI-Powered CLI Security Toolkit"

git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/thecnical/Vexor.git
git branch -M main

echo ""
echo -e "${YELLOW}  Make sure https://github.com/thecnical/Vexor exists (Public)${NC}"
read -p "  Press Enter to push CLI repo..."

git push -u origin main
echo -e "${GREEN}  ✓ CLI pushed to https://github.com/thecnical/Vexor${NC}"

# ═══════════════════════════════════════════════════════════════
#  REPO 2 — Backend (Private)
#  https://github.com/thecnical/Vexor-Backend
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  REPO 2: thecnical/Vexor-Backend (Private)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cd "$SCRIPT_DIR/backend"

if [[ ! -d ".git" ]]; then
    git init
    echo -e "${GREEN}  ✓ Git initialized for backend${NC}"
fi

git add .
git status --short | head -20

git commit -m "🔒 Vexor Backend v1.0.0

FastAPI backend with AI orchestration:
- Groq, NVIDIA NIM, OpenRouter, HuggingFace providers
- JWT authentication
- AI analyze, explain, suggest, payload, filter, report
- Docker + Render ready

PRIVATE — Contains AI routing logic
Created by Chandan Pandey (Technical)" 2>/dev/null || \
git commit --allow-empty -m "🔒 Vexor Backend v1.0.0"

git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/thecnical/Vexor-Backend.git
git branch -M main

echo ""
echo -e "${YELLOW}  Create https://github.com/thecnical/Vexor-Backend (PRIVATE)${NC}"
echo -e "${YELLOW}  Go to: https://github.com/new${NC}"
echo -e "${YELLOW}  Name: Vexor-Backend | Visibility: Private${NC}"
read -p "  Press Enter to push backend repo..."

git push -u origin main
echo -e "${GREEN}  ✓ Backend pushed to https://github.com/thecnical/Vexor-Backend${NC}"

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ Both repos pushed successfully!${NC}"
echo ""
echo -e "  ${CYAN}Public CLI:${NC}      https://github.com/thecnical/Vexor"
echo -e "  ${CYAN}Private Backend:${NC} https://github.com/thecnical/Vexor-Backend"
echo ""
echo -e "  ${YELLOW}Next: Deploy backend to Render${NC}"
echo -e "  See: docs/RENDER_DEPLOY.md"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""
