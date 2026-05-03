# Vexor — Installation Guide

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| OS | Kali Linux / Debian / Ubuntu | WSL also works |
| Python | 3.11+ | 3.13 recommended |
| RAM | 512MB+ | 1GB+ recommended |
| Disk | 500MB | For dependencies |

---

## Quick Install (One Command)

```bash
git clone https://github.com/thecnical/Vexor && cd Vexor && ./install.sh
```

---

## Step-by-Step Install

### Step 1: Clone the repository

```bash
git clone https://github.com/thecnical/Vexor
cd Vexor
```

### Step 2: Run installer

```bash
./install.sh
```

The installer automatically:
- Installs Python dependencies
- Installs system packages (nmap, mitmproxy, etc.)
- Installs optional Go tools (nuclei, assetfinder, hakrawler)
- Creates the `vexor` command
- Adds to PATH

### Step 3: Verify installation

```bash
vexor --version
# Output: Vexor v4.0.0 by Chandan Pandey (Technical)
```

```bash
python check_deps.py
# Shows which packages are installed
```

---

## WSL / Windows Setup

### Step 1: Install Kali Linux on WSL

```powershell
# Run in PowerShell as Administrator
wsl --install -d kali-linux
```

### Step 2: Open Kali terminal and install

```bash
sudo apt update && sudo apt upgrade -y
git clone https://github.com/thecnical/Vexor
cd Vexor
./install.sh
```

---

## Optional: Go Tools (for full OSINT power)

Install Go first: https://go.dev/dl/

```bash
# After installing Go:
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update nuclei templates
nuclei -update-templates
```

---

## Update Vexor

```bash
# Method 1: Using vexor command
vexor update

# Method 2: Manual
cd ~/Vexor
git pull
./install.sh
```

---

## Uninstall

```bash
cd ~/Vexor
./uninstall.sh
```

---

## Troubleshooting

### "vexor: command not found"

```bash
source ~/.bashrc
# or
export PATH="$HOME/.local/bin:$PATH"
vexor
```

### "ModuleNotFoundError"

```bash
pip install -e cli/ --break-system-packages
```

### "Permission denied: install.sh"

```bash
chmod +x install.sh
./install.sh
```

### Python version too old

```bash
sudo apt install python3.11 python3.11-pip
python3.11 -m pip install -e cli/ --break-system-packages
```
