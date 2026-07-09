#!/usr/bin/env bash
#
# GhostMCP Client Installer
# ==========================
# Sets up GhostMCP OSINT toolkit for use with opencode (or any MCP client).
# Run once on a new machine or after updates.
#
# Usage:
#   ./install.sh                       # Basic install (search + OSINT tools)
#   ./install.sh --render              # + headless Chromium (ghost_render)
#   ./install.sh --full                # + Chromium + all optional deps
#   ./install.sh --help
#
# What it does:
#   1. Creates ~/.ghostmcp/client/ with source + venv
#   2. Installs Python dependencies (httpx, phonenumbers, etc.)
#   3. Optionally installs Playwright/Chromium for browser rendering
#   4. Generates opencode.json MCP config snippet
#   5. Tests basic functionality
#
# What it does NOT do:
#   - Modify your existing opencode.json (prints snippet to paste)
#   - Store API keys (prints empty placeholders)
#   - Require root access

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# --- Defaults ---
INSTALL_DIR="${HOME}/.ghostmcp/client"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_RENDER=false
INSTALL_FULL=false
PYTHON=""

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --render)       INSTALL_RENDER=true; shift ;;
        --full)         INSTALL_FULL=true; INSTALL_RENDER=true; shift ;;
        --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--render] [--full] [--install-dir DIR]"
            echo ""
            echo "Options:"
            echo "  --render        Install Playwright + Chromium for ghost_render"
            echo "  --full          All optional dependencies (render + stealth + extras)"
            echo "  --install-dir   Install location (default: ~/.ghostmcp/client)"
            echo ""
            echo "After install, add the generated MCP config to your opencode.json"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Detect Python ---
detect_python() {
    for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver="$($candidate -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
            local major="${ver%%.*}"
            local minor="${ver#*.}"
            if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
                PYTHON="$candidate"
                return
            fi
        fi
    done
    error "Python 3.9+ not found. Install python3 and try again."
    exit 1
}

# --- Main ---
main() {
    echo ""
    echo "============================================="
    echo "  GhostMCP Client Installer"
    echo "============================================="
    echo ""

    detect_python
    info "Using Python: ${PYTHON} ($(${PYTHON} --version 2>&1))"
    info "Install dir:  ${INSTALL_DIR}"
    info "Render:       ${INSTALL_RENDER}"
    echo ""

    # Step 1: Create install directory
    step "Creating install directory..."
    mkdir -p "${INSTALL_DIR}"

    # Step 2: Copy source
    step "Copying GhostMCP source..."
    if [ -d "${SCRIPT_DIR}/ghostmcp" ]; then
        cp -r "${SCRIPT_DIR}/ghostmcp" "${INSTALL_DIR}/"
        info "Source copied from ${SCRIPT_DIR}/ghostmcp"
    else
        error "Cannot find ghostmcp/ directory. Run this script from the GhostMCP repo root."
        exit 1
    fi

    # Copy requirements
    if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
        cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
    fi

    # Step 3: Create Python venv + install dependencies
    step "Creating Python virtual environment..."
    if [ ! -d "${INSTALL_DIR}/.venv" ]; then
        ${PYTHON} -m venv "${INSTALL_DIR}/.venv"
    fi

    step "Installing core dependencies..."
    "${INSTALL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
    "${INSTALL_DIR}/.venv/bin/pip" install --quiet \
        "httpx[brotli]>=0.27.0" \
        "cryptography>=41.0.0" \
        "phonenumbers>=8.13.0" \
        "websockets>=12.0"

    info "Core dependencies installed"

    # Step 4: Optional — Playwright/Chromium for ghost_render
    if [ "$INSTALL_RENDER" = true ]; then
        step "Installing Playwright + Chromium (this may take a minute)..."
        "${INSTALL_DIR}/.venv/bin/pip" install --quiet "playwright>=1.40.0"
        "${INSTALL_DIR}/.venv/bin/playwright" install chromium 2>&1 | tail -3
        info "Playwright + Chromium installed"
    fi

    # Step 5: Optional — full extras
    if [ "$INSTALL_FULL" = true ]; then
        step "Installing full extras..."
        "${INSTALL_DIR}/.venv/bin/pip" install --quiet \
            "starlette>=0.37.0" \
            "uvicorn>=0.29.0" \
            "curl_cffi" 2>/dev/null || true
        info "Full extras installed"
    fi

    # Step 6: Quick smoke test
    step "Running smoke test..."
    if "${INSTALL_DIR}/.venv/bin/python3" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from ghostmcp.mcp import TOOLS
print(f'  Tools loaded: {len(TOOLS)}')
" 2>/dev/null; then
        info "Smoke test passed"
    else
        warn "Smoke test failed — install may have issues"
    fi

    # Step 7: Generate opencode.json config snippet
    step "Generating opencode.json config..."
    echo ""
    cat <<CONFIG
┌─────────────────────────────────────────────────────────────────┐
│  Add this to your opencode.json under "mcp": { ... }            │
└─────────────────────────────────────────────────────────────────┘

    "ghostmcp": {
      "type": "local",
      "command": [
        "${INSTALL_DIR}/.venv/bin/python3",
        "-m", "ghostmcp"
      ],
      "enabled": true,
      "environment": {
        "PYTHONPATH": "${INSTALL_DIR}",
        "GHOST_BRAVE_KEY": "",
        "GHOST_PERPLEXITY_KEY": "",
        "GHOST_SEARXNG_URL": "",
        "GHOST_HUNTER_KEY": "",
        "GHOST_COURTLISTENER_TOKEN": "",
        "GHOST_REGRID_KEY": "",
        "GHOST_SERPER_KEY": ""
      }
    }

CONFIG

    echo ""
    echo "============================================="
    echo "  Installation Complete"
    echo "============================================="
    echo ""
    echo "  Install dir:    ${INSTALL_DIR}"
    echo "  Python venv:    ${INSTALL_DIR}/.venv/"
    echo "  Config:         Paste the snippet above into your opencode.json"
    echo ""
    echo "  API Keys (optional — tools work without them but with reduced capability):"
    echo "    GHOST_BRAVE_KEY         — Brave Search API (brave.com/search/api)"
    echo "    GHOST_PERPLEXITY_KEY    — Perplexity AI (perplexity.ai)"
    echo "    GHOST_SEARXNG_URL       — Self-hosted SearXNG instance URL"
    echo "    GHOST_SERPER_KEY        — Serper.dev Google Search API"
    echo "    GHOST_HUNTER_KEY        — Hunter.io email enrichment"
    echo "    GHOST_COURTLISTENER_TOKEN — CourtListener court records"
    echo "    GHOST_REGRID_KEY        — Regrid property/parcel data"
    echo ""
    echo "  To update later, re-run this script. It will overwrite source"
    echo "  but preserve your .venv (only installs missing deps)."
    echo ""
}

main
