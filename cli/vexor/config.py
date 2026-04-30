"""
Vexor Configuration
"""
import os
from pathlib import Path

# Directories
HOME_DIR = Path.home() / ".vexor"
CONFIG_FILE = HOME_DIR / "config.json"
SESSIONS_DIR = HOME_DIR / "sessions"
REPORTS_DIR = HOME_DIR / "reports"
LOGS_DIR = HOME_DIR / "logs"
PLUGINS_DIR = HOME_DIR / "plugins"

# Backend
BACKEND_URL = os.getenv("VEXOR_BACKEND_URL", "https://vexor-backend-fnow.onrender.com")
API_VERSION = "v1"
API_BASE = f"{BACKEND_URL}/api/{API_VERSION}"

# Auth
TOKEN_FILE = HOME_DIR / "token.json"

# Tool info
TOOL_NAME = "Vexor"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "Chandan Pandey (Technical)"
TOOL_DESCRIPTION = "AI-Powered CLI Security Toolkit"
TOOL_TAGLINE = "Penetrate. Analyze. Dominate."

# Colors (Rich)
COLOR_PRIMARY = "bright_cyan"
COLOR_SECONDARY = "bright_magenta"
COLOR_SUCCESS = "bright_green"
COLOR_ERROR = "bright_red"
COLOR_WARNING = "bright_yellow"
COLOR_INFO = "bright_blue"
COLOR_DIM = "dim white"

# Proxy defaults
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

# Scanner defaults
SCAN_TIMEOUT = 30
SCAN_THREADS = 10
MAX_RETRIES = 3

# Offline mode
OFFLINE_MODE = False

# Payload files
PAYLOADS_DIR = Path(__file__).parent / "payloads"

def ensure_dirs():
    """Create all required directories"""
    for d in [HOME_DIR, SESSIONS_DIR, REPORTS_DIR, LOGS_DIR, PLUGINS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
