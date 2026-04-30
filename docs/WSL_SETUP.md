# WSL + Kali Linux Setup Guide
## For Windows Users — Vexor Installation

---

## Step 1: Install WSL on Windows

Open **PowerShell as Administrator** and run:

```powershell
# Enable WSL
wsl --install

# Install Kali Linux specifically
wsl --install -d kali-linux
```

**Restart your PC** after this.

---

## Step 2: First Launch of Kali

After restart, open **Kali Linux** from Start Menu.

Set your username and password when prompted.

```bash
# Update everything
sudo apt update && sudo apt full-upgrade -y

# Install essential tools
sudo apt install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    nmap \
    net-tools \
    dnsutils \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev
```

---

## Step 3: Install Vexor

```bash
# Clone the repo
git clone https://github.com/thecnical/Vexor
cd Vexor

# Make install script executable
chmod +x install.sh

# Run installer
./install.sh
```

---

## Step 4: Verify

```bash
# Check all dependencies
python3 check_deps.py

# Check vexor command
vexor --version

# Launch TUI
vexor
```

---

## Step 5: Login to Backend

```bash
# Register (first time)
# Go to: https://vexor-backend.onrender.com/docs
# Register via API

# Login
vexor auth login
```

---

## Useful WSL Tips

```bash
# Access Windows files from WSL
cd /mnt/c/Users/YourName/

# Access WSL files from Windows
# Open File Explorer → \\wsl$\kali-linux\home\username\

# Run Vexor from Windows Terminal
wsl -d kali-linux vexor scan https://target.com

# Set Kali as default WSL
wsl --set-default kali-linux
```

---

## Troubleshooting

**vexor command not found:**
```bash
source ~/.bashrc
# or
export PATH="$HOME/.local/bin:$PATH"
```

**Permission denied:**
```bash
chmod +x install.sh
```

**Python version too old:**
```bash
sudo apt install python3.11 python3.11-pip
```

**nmap not found:**
```bash
sudo apt install nmap
```
