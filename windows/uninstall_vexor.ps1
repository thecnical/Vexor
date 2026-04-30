# ═══════════════════════════════════════════════════════════════
#  VEXOR — Complete Uninstall Script
#  Removes Vexor from system completely
#  Run as Administrator in PowerShell
# ═══════════════════════════════════════════════════════════════

function Write-Color($text, $color = "Cyan") {
    Write-Host $text -ForegroundColor $color
}

Clear-Host
Write-Color @"
  ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"@ "Red"
Write-Color "  VEXOR — Uninstall Script" "Red"
Write-Color ""
Write-Color "  This will remove Vexor from your system." "Yellow"
Write-Color ""

# ─── Confirm ────────────────────────────────────────────────
Write-Color "  What do you want to remove?" "Cyan"
Write-Color ""
Write-Color "  [1] Vexor only (keep Kali Linux + WSL)" "White"
Write-Color "  [2] Vexor + Kali Linux (keep WSL)" "White"
Write-Color "  [3] Everything (Vexor + Kali + WSL)" "White"
Write-Color "  [4] Cancel" "White"
Write-Color ""

$choice = Read-Host "  Enter choice (1-4)"

if ($choice -eq "4" -or $choice -eq "") {
    Write-Color "  Cancelled." "Yellow"
    exit 0
}

Write-Color ""
$confirm = Read-Host "  Are you sure? Type 'YES' to confirm"
if ($confirm -ne "YES") {
    Write-Color "  Cancelled." "Yellow"
    exit 0
}

Write-Color ""

# ─── Remove Vexor from Kali ─────────────────────────────────
$wslCmd = Get-Command wsl -ErrorAction SilentlyContinue

if ($wslCmd -and ($choice -eq "1" -or $choice -eq "2" -or $choice -eq "3")) {
    Write-Color "  [*] Removing Vexor from Kali Linux..." "Cyan"

    $uninstallScript = @'
#!/bin/bash
echo "  Removing Vexor..."

# Uninstall pip package
pip3 uninstall vexor -y 2>/dev/null && echo "  ✓ pip package removed" || echo "  - pip package not found"

# Remove Vexor repo
if [ -d ~/Vexor ]; then
    rm -rf ~/Vexor
    echo "  ✓ ~/Vexor directory removed"
fi

# Remove Vexor data directory
if [ -d ~/.vexor ]; then
    rm -rf ~/.vexor
    echo "  ✓ ~/.vexor data removed"
fi

# Remove vexor from PATH entries in .bashrc
if grep -q "vexor" ~/.bashrc 2>/dev/null; then
    sed -i '/vexor/d' ~/.bashrc
    echo "  ✓ .bashrc cleaned"
fi

# Remove vexor from .zshrc if exists
if [ -f ~/.zshrc ] && grep -q "vexor" ~/.zshrc 2>/dev/null; then
    sed -i '/vexor/d' ~/.zshrc
    echo "  ✓ .zshrc cleaned"
fi

echo "  ✓ Vexor removed from Kali"
'@

    $scriptPath = "$env:TEMP\vexor_uninstall.sh"
    $uninstallScript | Out-File -FilePath $scriptPath -Encoding UTF8 -NoNewline
    $wslPath = "/mnt/c/Users/$env:USERNAME/AppData/Local/Temp/vexor_uninstall.sh"

    wsl -d kali-linux bash -c "chmod +x $wslPath && bash $wslPath" 2>$null
    Write-Color "  ✓ Vexor removed from Kali" "Green"
}

# ─── Remove Kali Linux ──────────────────────────────────────
if ($choice -eq "2" -or $choice -eq "3") {
    Write-Color ""
    Write-Color "  [*] Removing Kali Linux..." "Cyan"

    $kali = wsl -l -v 2>$null | Select-String "kali"
    if ($kali) {
        wsl --unregister kali-linux 2>$null
        Write-Color "  ✓ Kali Linux removed" "Green"
    } else {
        Write-Color "  - Kali Linux not found" "Yellow"
    }
}

# ─── Remove WSL ─────────────────────────────────────────────
if ($choice -eq "3") {
    Write-Color ""
    Write-Color "  [*] Disabling WSL..." "Cyan"

    # Check if other distros exist
    $otherDistros = wsl -l -v 2>$null | Where-Object { $_ -match '\S' -and $_ -notmatch "NAME" -and $_ -notmatch "kali" }
    if ($otherDistros) {
        Write-Color "  ! Other WSL distros found — keeping WSL enabled:" "Yellow"
        $otherDistros | ForEach-Object { Write-Color "    $_" "White" }
    } else {
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        Write-Color "  ✓ WSL disabled (restart required)" "Green"
    }
}

# ─── Done ───────────────────────────────────────────────────
Write-Color ""
Write-Color "  ══════════════════════════════════════════" "DarkGray"
Write-Color ""

switch ($choice) {
    "1" {
        Write-Color "  ╔══════════════════════════════════════╗" "Green"
        Write-Color "  ║   ✓ Vexor removed successfully       ║" "Green"
        Write-Color "  ║   Kali Linux + WSL still installed   ║" "Green"
        Write-Color "  ╚══════════════════════════════════════╝" "Green"
    }
    "2" {
        Write-Color "  ╔══════════════════════════════════════╗" "Green"
        Write-Color "  ║   ✓ Vexor + Kali removed             ║" "Green"
        Write-Color "  ║   WSL still installed                ║" "Green"
        Write-Color "  ╚══════════════════════════════════════╝" "Green"
    }
    "3" {
        Write-Color "  ╔══════════════════════════════════════╗" "Green"
        Write-Color "  ║   ✓ Everything removed               ║" "Green"
        Write-Color "  ║   Restart PC to complete             ║" "Green"
        Write-Color "  ╚══════════════════════════════════════╝" "Green"
    }
}

Write-Color ""
Write-Color "  To reinstall: Run setup_vexor_windows.ps1" "DarkGray"
Write-Color ""
Read-Host "  Press Enter to exit"
