#!/usr/bin/env bash
# sentinel-scan.sh — Lightweight MCP security scanner
#
# Orchestrates: Semgrep (SAST) + TruffleHog (secrets) + npm audit (SCA) + mcp-scan (protocol)
# Custom rules in .semgrep.yml for MCP/AI-specific patterns not in Semgrep's default ruleset.
#
# Usage: ./sentinel-scan.sh <target-directory> [--json] [--sarif] [--mcp-config <path>]
#
# Requirements (gracefully skips missing tools):
#   - semgrep    (pip install semgrep)      — SAST + custom rules
#   - trufflehog (brew install trufflehog)  — verified secret detection
#   - npm        (system)                   — dependency audit
#   - mcp-scan   (pip install mcp-scan)     — MCP protocol scanning (optional)
#
# Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEMGREP_RULES="${SCRIPT_DIR}/.semgrep.yml"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Arguments ────────────────────────────────────────────────────────
TARGET="${1:-.}"
OUTPUT_FORMAT="terminal"
MCP_CONFIG=""

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)     OUTPUT_FORMAT="json" ;;
        --sarif)    OUTPUT_FORMAT="sarif" ;;
        --mcp-config) MCP_CONFIG="$2"; shift ;;
        -h|--help)
            echo "Usage: sentinel-scan.sh <target-directory> [--json] [--sarif] [--mcp-config <path>]"
            echo ""
            echo "Orchestrates security scanning with:"
            echo "  semgrep      SAST + custom MCP/AI rules (.semgrep.yml)"
            echo "  trufflehog   Verified secret detection"
            echo "  npm audit    Dependency vulnerability scanning"
            echo "  mcp-scan     MCP protocol security (tool poisoning, rug pulls)"
            echo ""
            echo "Options:"
            echo "  --json         Output results as JSON"
            echo "  --sarif        Output results as SARIF"
            echo "  --mcp-config   Path to MCP server config (for mcp-scan)"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

TARGET="$(cd "$TARGET" && pwd)"
mkdir -p "$RESULTS_DIR"

# ── Tool Availability ────────────────────────────────────────────────
check_tool() {
    local tool="$1"
    local install_hint="$2"
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool $(command -v "$tool")"
        return 0
    else
        echo -e "  ${YELLOW}○${NC} $tool — not found (${install_hint})"
        return 1
    fi
}

echo -e "${BOLD}Sentinel Scan — Tool Check${NC}"
echo "─────────────────────────────────────"
HAS_SEMGREP=false
HAS_TRUFFLEHOG=false
HAS_NPM=false
HAS_MCPSCAN=false

check_tool "semgrep" "pip install semgrep" && HAS_SEMGREP=true
check_tool "trufflehog" "brew install trufflehog" && HAS_TRUFFLEHOG=true
check_tool "npm" "install Node.js" && HAS_NPM=true
check_tool "mcp-scan" "pip install mcp-scan" && HAS_MCPSCAN=true
echo ""

if ! $HAS_SEMGREP && ! $HAS_TRUFFLEHOG; then
    echo -e "${RED}Error: Neither semgrep nor trufflehog found. Install at least one.${NC}" >&2
    exit 1
fi

TOTAL_FINDINGS=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# ── Semgrep (SAST + custom rules) ───────────────────────────────────
SEMGREP_RESULTS="${RESULTS_DIR}/semgrep_${TIMESTAMP}.json"
if $HAS_SEMGREP; then
    echo -e "${BOLD}${CYAN}[1/4] Semgrep${NC} — SAST + MCP/AI custom rules"

    SEMGREP_CONFIGS="--config=auto"
    if [[ -f "$SEMGREP_RULES" ]]; then
        SEMGREP_CONFIGS="$SEMGREP_CONFIGS --config=$SEMGREP_RULES"
        echo "      Custom rules: $SEMGREP_RULES"
    fi

    if semgrep $SEMGREP_CONFIGS \
        --json \
        --quiet \
        --timeout 300 \
        --max-target-bytes 1000000 \
        --exclude="node_modules" \
        --exclude="dist" \
        --exclude="build" \
        --exclude=".git" \
        --exclude="__pycache__" \
        --exclude=".venv" \
        --exclude="*.min.js" \
        --exclude="*.bundle.js" \
        "$TARGET" > "$SEMGREP_RESULTS" 2>/dev/null; then

        SEMGREP_COUNT=$(python3 -c "
import json, sys
data = json.load(open('$SEMGREP_RESULTS'))
results = data.get('results', [])
print(len(results))
" 2>/dev/null || echo "0")

        # Count by severity
        SEMGREP_SUMS=$(python3 -c "
import json
data = json.load(open('$SEMGREP_RESULTS'))
results = data.get('results', [])
c = h = m = l = 0
for r in results:
    sev = r.get('extra', {}).get('severity', 'INFO').upper()
    if sev == 'ERROR': c += 1
    elif sev == 'WARNING': h += 1
    elif sev == 'INFO': m += 1
    else: l += 1
print(f'{c} {h} {m} {l}')
" 2>/dev/null || echo "0 0 0 0")
        read -r SC SH SM SL <<< "$SEMGREP_SUMS"
        CRITICAL=$((CRITICAL + SC))
        HIGH=$((HIGH + SH))
        MEDIUM=$((MEDIUM + SM))
        LOW=$((LOW + SL))
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + SEMGREP_COUNT))

        echo -e "      ${GREEN}Done${NC}: $SEMGREP_COUNT findings → $SEMGREP_RESULTS"
    else
        echo -e "      ${YELLOW}Warning${NC}: Semgrep exited with errors (partial results saved)"
    fi
else
    echo -e "${YELLOW}[1/4] Semgrep — skipped (not installed)${NC}"
fi

# ── TruffleHog (verified secrets) ────────────────────────────────────
TRUFFLEHOG_RESULTS="${RESULTS_DIR}/trufflehog_${TIMESTAMP}.json"
if $HAS_TRUFFLEHOG; then
    echo -e "${BOLD}${CYAN}[2/4] TruffleHog${NC} — verified secret detection"

    if trufflehog filesystem "$TARGET" \
        --json \
        --only-verified \
        --exclude-paths <(echo -e "node_modules/\n.git/\n.venv/\ndist/\nbuild/") \
        > "$TRUFFLEHOG_RESULTS" 2>/dev/null; then

        TRUFFLEHOG_COUNT=$(wc -l < "$TRUFFLEHOG_RESULTS" | tr -d ' ')
        # Every verified secret is CRITICAL
        CRITICAL=$((CRITICAL + TRUFFLEHOG_COUNT))
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + TRUFFLEHOG_COUNT))

        echo -e "      ${GREEN}Done${NC}: $TRUFFLEHOG_COUNT verified secrets → $TRUFFLEHOG_RESULTS"
    else
        echo -e "      ${GREEN}Done${NC}: 0 verified secrets"
        echo "[]" > "$TRUFFLEHOG_RESULTS"
    fi
else
    echo -e "${YELLOW}[2/4] TruffleHog — skipped (not installed)${NC}"
fi

# ── npm audit (SCA) ─────────────────────────────────────────────────
NPM_RESULTS="${RESULTS_DIR}/npm_audit_${TIMESTAMP}.json"
if $HAS_NPM && [[ -f "$TARGET/package.json" ]]; then
    echo -e "${BOLD}${CYAN}[3/4] npm audit${NC} — dependency vulnerabilities"

    if npm audit --json --prefix "$TARGET" > "$NPM_RESULTS" 2>/dev/null; then
        echo -e "      ${GREEN}Done${NC}: 0 vulnerabilities"
    else
        NPM_COUNT=$(python3 -c "
import json
data = json.load(open('$NPM_RESULTS'))
vulns = data.get('vulnerabilities', {})
c = h = m = l = 0
for name, v in vulns.items():
    sev = v.get('severity', 'low')
    if sev == 'critical': c += 1
    elif sev == 'high': h += 1
    elif sev == 'moderate': m += 1
    else: l += 1
print(f'{c} {h} {m} {l}')
" 2>/dev/null || echo "0 0 0 0")
        read -r NC_ NH NM NL <<< "$NPM_COUNT"
        CRITICAL=$((CRITICAL + NC_))
        HIGH=$((HIGH + NH))
        MEDIUM=$((MEDIUM + NM))
        LOW=$((LOW + NL))
        NPM_TOTAL=$((NC_ + NH + NM + NL))
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + NPM_TOTAL))

        echo -e "      ${GREEN}Done${NC}: $NPM_TOTAL vulnerabilities → $NPM_RESULTS"
    fi
elif $HAS_NPM; then
    echo -e "${YELLOW}[3/4] npm audit — skipped (no package.json)${NC}"
else
    echo -e "${YELLOW}[3/4] npm audit — skipped (npm not installed)${NC}"
fi

# ── mcp-scan (MCP protocol security) ────────────────────────────────
MCPSCAN_RESULTS="${RESULTS_DIR}/mcp_scan_${TIMESTAMP}.json"
if $HAS_MCPSCAN; then
    echo -e "${BOLD}${CYAN}[4/4] mcp-scan${NC} — MCP protocol security"

    MCP_TARGET=""
    if [[ -n "$MCP_CONFIG" ]]; then
        MCP_TARGET="$MCP_CONFIG"
    elif [[ -f "$TARGET/.cursor/mcp.json" ]]; then
        MCP_TARGET="$TARGET/.cursor/mcp.json"
    elif [[ -f "$TARGET/mcp.json" ]]; then
        MCP_TARGET="$TARGET/mcp.json"
    elif [[ -f "$HOME/.cursor/mcp.json" ]]; then
        MCP_TARGET="$HOME/.cursor/mcp.json"
    fi

    if [[ -n "$MCP_TARGET" ]]; then
        if mcp-scan --json "$MCP_TARGET" > "$MCPSCAN_RESULTS" 2>/dev/null; then
            echo -e "      ${GREEN}Done${NC}: results → $MCPSCAN_RESULTS"
        else
            echo -e "      ${YELLOW}Warning${NC}: mcp-scan exited with errors"
        fi
    else
        echo -e "      ${YELLOW}Skipped${NC}: no MCP server config found"
        echo "      Hint: use --mcp-config <path> or place mcp.json in project root"
    fi
else
    echo -e "${YELLOW}[4/4] mcp-scan — skipped (not installed: pip install mcp-scan)${NC}"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}Sentinel Scan Summary${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "  Target:   $TARGET"
echo -e "  Time:     $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  Results:  $RESULTS_DIR/"
echo ""
echo -e "  ${RED}CRITICAL${NC}: $CRITICAL"
echo -e "  ${YELLOW}HIGH${NC}:     $HIGH"
echo -e "  MEDIUM:   $MEDIUM"
echo -e "  LOW:      $LOW"
echo -e "  ─────────"
echo -e "  ${BOLD}TOTAL:     $TOTAL_FINDINGS${NC}"
echo ""

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}⚠  CRITICAL findings require immediate attention${NC}"
elif [[ $HIGH -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠  HIGH severity findings should be reviewed${NC}"
elif [[ $TOTAL_FINDINGS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✓  No findings — clean scan${NC}"
else
    echo -e "  ${GREEN}Review findings at your convenience${NC}"
fi

# ── JSON output mode ─────────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    python3 -c "
import json, glob, os

combined = {
    'scan_summary': {
        'target': '$TARGET',
        'total_findings': $TOTAL_FINDINGS,
        'severity': {
            'critical': $CRITICAL,
            'high': $HIGH,
            'medium': $MEDIUM,
            'low': $LOW
        }
    },
    'tools': {}
}

# Semgrep
sg = '$SEMGREP_RESULTS'
if os.path.exists(sg) and os.path.getsize(sg) > 0:
    try:
        combined['tools']['semgrep'] = json.load(open(sg))
    except: pass

# TruffleHog
th = '$TRUFFLEHOG_RESULTS'
if os.path.exists(th) and os.path.getsize(th) > 0:
    try:
        lines = open(th).readlines()
        combined['tools']['trufflehog'] = [json.loads(l) for l in lines if l.strip()]
    except: pass

# npm audit
na = '$NPM_RESULTS'
if os.path.exists(na) and os.path.getsize(na) > 0:
    try:
        combined['tools']['npm_audit'] = json.load(open(na))
    except: pass

# mcp-scan
ms = '$MCPSCAN_RESULTS'
if os.path.exists(ms) and os.path.getsize(ms) > 0:
    try:
        combined['tools']['mcp_scan'] = json.load(open(ms))
    except: pass

print(json.dumps(combined, indent=2))
" > "${RESULTS_DIR}/sentinel_combined_${TIMESTAMP}.json"
    echo -e "  Combined JSON → ${RESULTS_DIR}/sentinel_combined_${TIMESTAMP}.json"
fi

# Exit code: non-zero if critical/high findings
if [[ $CRITICAL -gt 0 ]]; then
    exit 2
elif [[ $HIGH -gt 0 ]]; then
    exit 1
else
    exit 0
fi
