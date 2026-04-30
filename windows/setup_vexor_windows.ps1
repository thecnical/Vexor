# ═══════════════════════════════════════════════════════════════
#  VEXOR — Windows Auto Setup Script
#  Run as Administrator in PowerShell
#  This script installs WSL + Kali Linux + Vexor automatically
# ═══════════════════════════════════════════════════════════════

$ErrorActionPreference = "Continue"

function Write-Color($text, $color = "Cyan") {
    Write-Host $text -ForegroundColor $color
}

Clear-Host
Write-Color @"
  ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
  ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
  ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
  ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
   ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
    ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"@ "Cyan"

Write-Color "  AI-Powered CLI Security Toolkit — Windows Setup" "Magenta"
Write-Color "  Created by Chandan Pandey (Technical)" "DarkGray"
Write-Color ""

# ─── Check Admin ────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Color "  [!] Run as Administrator!" "Red"
    Write-Color "  Right-click PowerShell → Run as Administrator" "Yellow"
    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Color "  [✓] Running as Administrator" "Green"
Write-Color ""

# ─── Check Windows Version ──────────────────────────────────
$winVer = [System.Environment]::OSVersion.Version
Write-Color "  [*] Windows Version: $($winVer.Major).$($winVer.Minor)" "Cyan"

if ($winVer.Major -lt 10) {
    Write-Color "  [!] Windows 10 or higher required for WSL2" "Red"
    exit 1
}

# ─── Step 1: Enable WSL ─────────────────────────────────────
Write-Color ""
Write-Color "  [1/4] Enabling WSL..." "Cyan"

$wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
if ($wslFeature.State -ne "Enabled") {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    Write-Color "  [✓] WSL feature enabled" "Green"
} else {
    Write-Color "  [✓] WSL already enabled" "Green"
}

# Enable Virtual Machine Platform
$vmFeature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
if ($vmFeature.State -ne "Enabled") {
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
    Write-Color "  [✓] Virtual Machine Platform enabled" "Green"
}

# ─── Step 2: Install WSL2 ───────────────────────────────────
Write-Color ""
Write-Color "  [2/4] Installing WSL2 + Kali Linux..." "Cyan"

# Check if wsl command exists
$wslExists = Get-Command wsl -ErrorAction SilentlyContinue
if ($wslExists) {
    # Update WSL
    wsl --update 2>$null
    Write-Color "  [✓] WSL updated" "Green"

    # Check if Kali is installed
    $kaliInstalled = wsl -l -v 2>$null | Select-String "kali"
    if (-not $kaliInstalled) {
        Write-Color "  [*] Installing Kali Linux (this may take 5-10 minutes)..." "Yellow"
        wsl --install -d kali-linux --no-launch
        Write-Color "  [✓] Kali Linux installed" "Green"
    } else {
        Write-Color "  [✓] Kali Linux already installed" "Green"
    }
} else {
    Write-Color "  [*] Installing WSL + Kali Linux..." "Yellow"
    wsl --install -d kali-linux --no-launch
}

# ─── Step 3: Create Kali Setup Script ───────────────────────
Write-Color ""
Write-Color "  [3/4] Creating Vexor setup script for Kali..." "Cyan"

$kaliScript = @'
#!/bin/bash
# Vexor Auto Setup for Kali Linux

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   VEXOR — Kali Linux Setup           ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Update
echo "  [1/4] Updating Kali..."
sudo apt-get update -qq && sudo apt-get upgrade -y -qq
echo "  ✓ Updated"

# Install dependencies
echo "  [2/4] Installing dependencies..."
sudo apt-get install -y -qq \
    git python3 python3-pip python3-venv \
    nmap curl wget build-essential \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    net-tools dnsutils 2>/dev/null
echo "  ✓ Dependencies installed"

# Clone Vexor
echo "  [3/4] Cloning Vexor..."
cd ~
if [ -d "Vexor" ]; then
    cd Vexor && git pull
else
    git clone https://github.com/thecnical/Vexor
    cd Vexor
fi
echo "  ✓ Vexor cloned"

# Install Vexor
echo "  [4/4] Installing Vexor..."
chmod +x install.sh
./install.sh

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   ✓ VEXOR READY!                     ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  Run: vexor"
echo "  Run: vexor auth login"
echo "  Run: vexor scan https://testphp.vulnweb.com"
echo ""
'@

# Save script to Windows temp
$scriptPath = "$env:TEMP\vexor_kali_setup.sh"
$kaliScript | Out-File -FilePath $scriptPath -Encoding UTF8 -NoNewline

Write-Color "  [✓] Setup script created" "Green"

# ─── Step 4: Run in Kali ────────────────────────────────────
Write-Color ""
Write-Color "  [4/4] Running setup in Kali Linux..." "Cyan"
Write-Color "  (This will take 5-10 minutes)" "Yellow"
Write-Color ""

# Convert Windows path to WSL path
$wslScriptPath = "/mnt/c/Users/$env:USERNAME/AppData/Local/Temp/vexor_kali_setup.sh"

try {
    wsl -d kali-linux bash -c "chmod +x $wslScriptPath && bash $wslScriptPath"
    Write-Color ""
    Write-Color "  ╔══════════════════════════════════════════╗" "Green"
    Write-Color "  ║   ✓ VEXOR INSTALLED SUCCESSFULLY!        ║" "Green"
    Write-Color "  ╚══════════════════════════════════════════╝" "Green"
    Write-Color ""
    Write-Color "  HOW TO USE:" "Cyan"
    Write-Color "  1. Open 'Kali Linux' from Start Menu" "White"
    Write-Color "  2. Type: vexor" "White"
    Write-Color "  3. Or: vexor scan https://testphp.vulnweb.com" "White"
    Write-Color ""
} catch {
    Write-Color ""
    Write-Color "  [!] Auto setup failed. Manual steps:" "Yellow"
    Write-Color ""
    Write-Color "  1. Open 'Kali Linux' from Start Menu" "White"
    Write-Color "  2. Run these commands:" "White"
    Write-Color ""
    Write-Color "     git clone https://github.com/thecnical/Vexor" "Cyan"
    Write-Color "     cd Vexor && ./install.sh" "Cyan"
    Write-Color ""
}

Write-Color ""
Write-Color "  NOTE: If PC restart is needed, restart and run this script again." "Yellow"
Write-Color ""
Read-Host "  Press Enter to exit"
