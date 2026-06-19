#!/usr/bin/env bash

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Key definitions by tier ─────────────────────────────────────────────────
# Format: "ENV_VAR_NAME|Description|Monthly cost estimate"

FREE_KEYS=(
    "GHOST_SERPER_KEY|Serper.dev (Google search)|Free tier: 2500 queries/mo"
)

BUDGET_KEYS=(
    "GHOST_SHODAN_KEY|Shodan (internet scanning)|\$59/mo (membership)"
    "GHOST_ABUSEIPDB_KEY|AbuseIPDB (IP reputation)|Free tier: 1000 checks/day"
    "GHOST_URLSCAN_KEY|urlscan.io (URL analysis)|Free tier: 50 scans/day"
    "GHOST_HUNTER_KEY|Hunter.io (email finder)|Free tier: 25 searches/mo"
    "GHOST_GREYNOISE_KEY|GreyNoise (IP context)|Community: free"
    "GHOST_LEAKIX_KEY|LeakIX (exposed services)|Free tier available"
)

PRO_KEYS=(
    "GHOST_VT_KEY|VirusTotal (malware/URL)|Free tier: 4 lookups/min"
    "GHOST_CENSYS_ID|Censys App ID (host search)|Free tier: 250 queries/mo"
    "GHOST_CENSYS_SECRET|Censys API Secret|—"
    "GHOST_SECTRAILS_KEY|SecurityTrails (DNS intel)|\$50/mo"
    "GHOST_BINARYEDGE_KEY|BinaryEdge (threat intel)|\$10/mo starter"
    "GHOST_FULLHUNT_KEY|FullHunt (attack surface)|\$55/mo"
    "GHOST_NETLAS_KEY|Netlas (internet intel)|Free tier: 50 queries/day"
    "GHOST_ZOOMEYE_KEY|ZoomEye (cyberspace search)|Free tier: 20 queries/day"
)

# ─── Display helpers ──────────────────────────────────────────────────────────
check_key() {
    local entry="$1"
    local varname desc cost

    IFS='|' read -r varname desc cost <<< "$entry"

    if [[ -n "${!varname}" ]]; then
        local masked="${!varname:0:4}****"
        echo -e "  ${GREEN}✔${RESET}  ${BOLD}${varname}${RESET}"
        echo -e "      ${desc} ${DIM}[${masked}]${RESET}"
        return 0
    else
        echo -e "  ${RED}✘${RESET}  ${DIM}${varname}${RESET}"
        echo -e "      ${desc} ${DIM}(${cost})${RESET}"
        return 1
    fi
}

tier_header() {
    echo ""
    echo -e "${BOLD}${CYAN}┌─ $1 ─────────────────────────────────────────────────┐${RESET}"
}

tier_footer() {
    local set=$1 total=$2
    local color="${GREEN}"
    if [[ $set -eq 0 ]]; then color="${RED}"; fi
    if [[ $set -lt $total ]]; then color="${YELLOW}"; fi
    echo -e "${BOLD}${CYAN}└─ ${color}${set}/${total} configured${CYAN} ────────────────────────────────────────────┘${RESET}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${CYAN}  GhostMCP API Key Status${RESET}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

TOTAL_SET=0
TOTAL_KEYS=0

# ─── Free Tier ────────────────────────────────────────────────────────────────
tier_header "Free Tier"
tier_set=0
for entry in "${FREE_KEYS[@]}"; do
    if check_key "$entry"; then ((tier_set++)); fi
    ((TOTAL_KEYS++))
done
tier_footer $tier_set ${#FREE_KEYS[@]}
TOTAL_SET=$((TOTAL_SET + tier_set))

# ─── Budget Tier ──────────────────────────────────────────────────────────────
tier_header "Budget Tier (\$0-\$59/mo)"
tier_set=0
for entry in "${BUDGET_KEYS[@]}"; do
    if check_key "$entry"; then ((tier_set++)); fi
    ((TOTAL_KEYS++))
done
tier_footer $tier_set ${#BUDGET_KEYS[@]}
TOTAL_SET=$((TOTAL_SET + tier_set))

# ─── Pro Tier ─────────────────────────────────────────────────────────────────
tier_header "Pro Tier (\$10-\$55/mo per service)"
tier_set=0
for entry in "${PRO_KEYS[@]}"; do
    if check_key "$entry"; then ((tier_set++)); fi
    ((TOTAL_KEYS++))
done
tier_footer $tier_set ${#PRO_KEYS[@]}
TOTAL_SET=$((TOTAL_SET + tier_set))

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

if [[ $TOTAL_SET -eq $TOTAL_KEYS ]]; then
    echo -e "  ${GREEN}${BOLD}All ${TOTAL_KEYS} keys configured${RESET}"
    echo ""
    echo -e "  ${DIM}Estimated monthly cost (if all paid tiers active):${RESET}"
    echo -e "  ${BOLD}~\$175-\$235/mo${RESET} ${DIM}(varies by usage)${RESET}"
elif [[ $TOTAL_SET -eq 0 ]]; then
    echo -e "  ${RED}${BOLD}No keys configured${RESET}"
    echo -e "  ${DIM}Unit tests will work. Integration/paid tests will skip.${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}${TOTAL_SET}/${TOTAL_KEYS} keys configured${RESET}"
    echo -e "  ${DIM}Tests requiring missing keys will be skipped.${RESET}"
fi

echo ""
echo -e "  ${DIM}Set keys in your shell profile or .env file:${RESET}"
echo -e "  ${DIM}  export GHOST_SERPER_KEY=\"your-key-here\"${RESET}"
echo ""
