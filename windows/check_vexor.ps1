# ═══════════════════════════════════════════════════════════════
#  VEXOR — System Check Script
#  Checks if Vexor and all dependencies are properly installed
# ═══════════════════════════════════════════════════════════════

function Write-Color($text, $color = "Cyan") {
    Write-Host $text -ForegroundColor $color
}

Clear-Host
Write-Color @"
  ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗ 
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"@ "Cyan"
Write-Color "  VEXOR — System Check" "Magenta"
Write-Color "  Created by Chandan Pandey (Technical)" "DarkGray"
Write-Color ""
Write-Color "  ══════════════════════════════════════════" "DarkGray"

$allOk = $true

# ─── Windows Info ───────────────────────────────────────────
Write-Color ""
Write-Color "  [WINDOWS]" "Magenta"
$winVer = [System.Environment]::OSVersion.Version
$winName = (Get-WmiObject Win32_OperatingSystem).Caption
Write-Color "  ✓  $winName ($($winVer.Major).$($winVer.Minor))" "Green"

# ─── WSL Check ──────────────────────────────────────────────
Write-Color ""
Write-Color "  [WSL]" "Magenta"

$wslCmd = Get-Command wsl -ErrorAction SilentlyContinue
if ($wslCmd) {
    Write-Color "  ✓  WSL installed" "Green"

    # WSL version
    $wslVersion = wsl --version 2>$null | Select-Object -First 1
    if ($wslVersion) {
        Write-Color "  ✓  $wslVersion" "Green"
    }

    # List distros
    $distros = wsl -l -v 2>$null
    Write-Color "  ✓  Installed distros:" "Green"
    $distros | ForEach-Object {
        if ($_ -match '\S') {
            Write-Color "     $_" "White"
        }
    }

    # Check Kali
    $kali = wsl -l -v 2>$null | Select-String "kali"
    if ($kali) {
        Write-Color "  ✓  Kali Linux found" "Green"
    } else {
        Write-Color "  ✗  Kali Linux NOT installed" "Red"
        $allOk = $false
    }
} else {
    Write-Color "  ✗  WSL not installed" "Red"
    $allOk = $false
}

# ─── Vexor Check (in Kali) ──────────────────────────────────
Write-Color ""
Write-Color "  [VEXOR IN KALI]" "Magenta"

if ($wslCmd) {
    # Check vexor command
    $vexorCheck = wsl -d kali-linux bash -c "command -v vexor 2>/dev/null" 2>$null
    if ($vexorCheck) {
        Write-Color "  ✓  vexor command found: $vexorCheck" "Green"

        # Get version
        $vexorVersion = wsl -d kali-linux bash -c "vexor --version 2>/dev/null" 2>$null
        if ($vexorVersion) {
            Write-Color "  ✓  Version: $vexorVersion" "Green"
        }
    } else {
        Write-Color "  ✗  vexor command not found in Kali" "Red"
        $allOk = $false
    }

    # Check Python
    $pythonCheck = wsl -d kali-linux bash -c "python3 --version 2>/dev/null" 2>$null
    if ($pythonCheck) {
        Write-Color "  ✓  $pythonCheck" "Green"
    } else {
        Write-Color "  ✗  Python3 not found" "Red"
        $allOk = $false
    }

    # Check nmap
    $nmapCheck = wsl -d kali-linux bash -c "nmap --version 2>/dev/null | head -1" 2>$null
    if ($nmapCheck) {
        Write-Color "  ✓  $nmapCheck" "Green"
    } else {
        Write-Color "  !  nmap not found (optional)" "Yellow"
    }

    # Check Vexor repo
    $repoCheck = wsl -d kali-linux bash -c "test -d ~/Vexor && echo 'found'" 2>$null
    if ($repoCheck -eq "found") {
        Write-Color "  ✓  Vexor repo at ~/Vexor" "Green"
    } else {
        Write-Color "  !  Vexor repo not found at ~/Vexor" "Yellow"
    }
}

# ─── Backend Check ──────────────────────────────────────────
Write-Color ""
Write-Color "  [BACKEND]" "Magenta"

try {
    $response = Invoke-WebRequest -Uri "https://vexor-backend-fnow.onrender.com/api/v1/health" -TimeoutSec 15 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Color "  ✓  Backend LIVE: https://vexor-backend-fnow.onrender.com" "Green"
        Write-Color "  ✓  Response: $($response.Content)" "Green"
    }
} catch {
    Write-Color "  !  Backend sleeping (normal on free tier)" "Yellow"
    Write-Color "     First request takes 30-60 sec to wake up" "DarkGray"
}

# ─── Python Packages (in Kali) ──────────────────────────────
Write-Color ""
Write-Color "  [PYTHON PACKAGES IN KALI]" "Magenta"

if ($wslCmd) {
    $packages = @("typer", "rich", "textual", "httpx", "bs4", "jwt", "cryptography", "jinja2", "pydantic", "dns", "mitmproxy")
    foreach ($pkg in $packages) {
        $check = wsl -d kali-linux bash -c "python3 -c 'import $pkg' 2>/dev/null && echo 'ok'" 2>$null
        if ($check -eq "ok") {
            Write-Color "  ✓  $pkg" "Green"
        } else {
            Write-Color "  ✗  $pkg missing" "Red"
            $allOk = $false
        }
    }
}

# ─── Summary ────────────────────────────────────────────────
Write-Color ""
Write-Color "  ══════════════════════════════════════════" "DarkGray"
Write-Color ""

if ($allOk) {
    Write-Color "  ╔══════════════════════════════════════╗" "Green"
    Write-Color "  ║   ✓ ALL CHECKS PASSED — VEXOR READY  ║" "Green"
    Write-Color "  ╚══════════════════════════════════════╝" "Green"
    Write-Color ""
    Write-Color "  Open Kali Linux and run: vexor" "Cyan"
} else {
    Write-Color "  ╔══════════════════════════════════════╗" "Yellow"
    Write-Color "  ║   ! SOME CHECKS FAILED               ║" "Yellow"
    Write-Color "  ╚══════════════════════════════════════╝" "Yellow"
    Write-Color ""
    Write-Color "  Fix: Run setup_vexor_windows.ps1 as Administrator" "Cyan"
}

Write-Color ""
Read-Host "  Press Enter to exit"
