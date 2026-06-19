#!/usr/bin/env bash
set -e

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Helpers ──────────────────────────────────────────────────────────────────
info()  { echo -e "${BLUE}▸${RESET} $*"; }
pass()  { echo -e "${GREEN}✔${RESET} $*"; }
fail()  { echo -e "${RED}✘${RESET} $*"; }
warn()  { echo -e "${YELLOW}⚠${RESET} $*"; }
header() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${CYAN}  $*${RESET}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ─── Pre-flight checks ────────────────────────────────────────────────────────
preflight() {
    local missing=0

    if ! command -v pytest &>/dev/null; then
        fail "pytest not found — install with: pip install pytest"
        missing=1
    fi

    if ! python -c "import pytest_asyncio" &>/dev/null 2>&1; then
        fail "pytest-asyncio not found — install with: pip install pytest-asyncio"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        echo ""
        fail "Pre-flight checks failed. Install missing dependencies and retry."
        exit 1
    fi

    pass "Pre-flight: pytest and pytest-asyncio available"
}

# ─── Paid mode key check ─────────────────────────────────────────────────────
check_paid_keys() {
    local keys=(
        GHOST_SERPER_KEY
        GHOST_SHODAN_KEY
        GHOST_CENSYS_ID
        GHOST_CENSYS_SECRET
        GHOST_VT_KEY
        GHOST_GREYNOISE_KEY
        GHOST_ABUSEIPDB_KEY
        GHOST_URLSCAN_KEY
        GHOST_HUNTER_KEY
        GHOST_SECTRAILS_KEY
        GHOST_BINARYEDGE_KEY
        GHOST_FULLHUNT_KEY
        GHOST_LEAKIX_KEY
        GHOST_NETLAS_KEY
        GHOST_ZOOMEYE_KEY
    )

    local set_count=0
    local missing_keys=()

    for key in "${keys[@]}"; do
        if [[ -n "${!key}" ]]; then
            ((set_count++))
        else
            missing_keys+=("$key")
        fi
    done

    echo ""
    info "Paid API keys: ${GREEN}${set_count}${RESET}/${#keys[@]} configured"

    if [[ ${#missing_keys[@]} -gt 0 ]]; then
        warn "Missing keys (tests requiring these will be skipped):"
        for key in "${missing_keys[@]}"; do
            echo -e "    ${DIM}${key}${RESET}"
        done
        echo ""
    fi
}

# ─── Parse results from pytest output ────────────────────────────────────────
parse_results() {
    local output="$1"
    local passed=0 failed=0 skipped=0 errors=0

    # Extract from pytest's summary line (e.g., "5 passed, 2 skipped, 1 failed")
    if echo "$output" | grep -qE "[0-9]+ passed"; then
        passed=$(echo "$output" | grep -oP '\d+ passed' | grep -oP '\d+' | tail -1)
    fi
    if echo "$output" | grep -qE "[0-9]+ failed"; then
        failed=$(echo "$output" | grep -oP '\d+ failed' | grep -oP '\d+' | tail -1)
    fi
    if echo "$output" | grep -qE "[0-9]+ skipped"; then
        skipped=$(echo "$output" | grep -oP '\d+ skipped' | grep -oP '\d+' | tail -1)
    fi
    if echo "$output" | grep -qE "[0-9]+ error"; then
        errors=$(echo "$output" | grep -oP '\d+ error' | grep -oP '\d+' | tail -1)
    fi

    echo ""
    echo -e "${BOLD}━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${GREEN}Passed:${RESET}  ${passed:-0}"
    echo -e "  ${YELLOW}Skipped:${RESET} ${skipped:-0}"
    echo -e "  ${RED}Failed:${RESET}  ${failed:-0}"
    if [[ ${errors:-0} -gt 0 ]]; then
        echo -e "  ${RED}Errors:${RESET}  ${errors}"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
MODE="${1:-unit}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

preflight

case "$MODE" in
    unit)
        header "Running UNIT tests"
        PYTEST_CMD="pytest tests/ -v --tb=short"
        ;;
    integration)
        header "Running INTEGRATION tests (free APIs, live endpoints)"
        PYTEST_CMD="pytest -m integration -v --tb=short"
        ;;
    paid)
        header "Running PAID tests (requires API keys)"
        check_paid_keys
        PYTEST_CMD="pytest -m paid -v --tb=short"
        ;;
    all)
        header "Running ALL tests (unit + integration + paid)"
        check_paid_keys
        PYTEST_CMD="pytest -m '' -v --tb=short"
        ;;
    quick)
        header "Running QUICK tests (stop on first failure)"
        PYTEST_CMD="pytest tests/ -x -q"
        ;;
    *)
        fail "Unknown mode: $MODE"
        echo ""
        echo "Usage: $0 [unit|integration|paid|all|quick]"
        echo ""
        echo "  unit         Unit tests only (default)"
        echo "  integration  Free API integration tests"
        echo "  paid         Tests requiring paid API keys"
        echo "  all          Everything"
        echo "  quick        Fast run, stop on first failure"
        exit 1
        ;;
esac

info "Command: ${DIM}${PYTEST_CMD}${RESET}"
echo ""

# Run with timer
START_TIME=$(date +%s)

set +e
OUTPUT=$(eval "$PYTEST_CMD" 2>&1)
EXIT_CODE=$?
set -e

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Print pytest output
echo "$OUTPUT"

# Summary
parse_results "$OUTPUT"
echo ""
info "Elapsed: ${BOLD}${ELAPSED}s${RESET}"

if [[ $EXIT_CODE -eq 0 ]]; then
    echo ""
    pass "${BOLD}All tests passed${RESET}"
else
    echo ""
    fail "${BOLD}Tests failed (exit code: ${EXIT_CODE})${RESET}"
fi

exit $EXIT_CODE
