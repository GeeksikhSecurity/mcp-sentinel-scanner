#!/usr/bin/env bash
# factory-droid-validate.sh — Minimal PoC wrapper Factory Droids invoke to
# validate an MCP server against the mcp-sentinel-scanner rubric.
#
# Input:  MCP repo URL or local path
# Output: Droid-consumable JSON verdict on stdout
# Exit:   0 = APPROVE, 1 = FIX needed, 2 = scan error
#
# Usage:
#   ./scripts/factory-droid-validate.sh <repo-url-or-path> [--name <label>]
#
# Rubric (binary — do not edit without updating Template 6):
#   APPROVE: 0 CRITICAL findings AND <=1 HIGH findings
#   FIX:     anything else
#
# The wrapper intentionally does not judge MCP-specific rule hits; it surfaces
# them in the JSON output for the Droid (or human) to reason about.

set -euo pipefail

TARGET="${1:?usage: factory-droid-validate.sh <repo-url-or-path> [--name <label>]}"
NAME=""
shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="${SCRIPT_DIR}/sentinel-scan.sh"
RESULTS_DIR="${SCRIPT_DIR}/results"

[[ -x "$SENTINEL" ]] || { echo "error: sentinel-scan.sh not found at $SENTINEL" >&2; exit 2; }

WORK_DIR=""
if [[ "$TARGET" =~ ^https?:// || "$TARGET" =~ ^git@ ]]; then
    WORK_DIR=$(mktemp -d)
    trap 'rm -rf "$WORK_DIR"' EXIT
    git clone --depth 1 --quiet "$TARGET" "$WORK_DIR/repo" >&2 || {
        echo '{"verdict":"ERROR","reason":"clone failed","target":"'"$TARGET"'"}'
        exit 2
    }
    SCAN_PATH="$WORK_DIR/repo"
    NAME="${NAME:-$(basename "${TARGET%.git}")}"
else
    [[ -d "$TARGET" ]] || { echo '{"verdict":"ERROR","reason":"target not found"}'; exit 2; }
    SCAN_PATH="$(cd "$TARGET" && pwd)"
    NAME="${NAME:-$(basename "$SCAN_PATH")}"
fi

# Run scan (log to stderr, capture exit code, keep going on non-zero)
SCAN_EXIT=0
"$SENTINEL" "$SCAN_PATH" --json 1>&2 || SCAN_EXIT=$?

COMBINED=$(ls -t "${RESULTS_DIR}/sentinel_combined_"*.json 2>/dev/null | head -1 || true)
if [[ -z "${COMBINED:-}" || ! -f "$COMBINED" ]]; then
    echo '{"verdict":"ERROR","reason":"no scan output produced","target":"'"$NAME"'","sentinel_exit":'"$SCAN_EXIT"'}'
    exit 2
fi

python3 - "$COMBINED" "$NAME" "$SCAN_EXIT" <<'PY'
import json, sys, os
path, name, scan_exit = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path) as f:
    data = json.load(f)

sev = data.get("scan_summary", {}).get("severity", {})
crit = int(sev.get("critical", 0))
high = int(sev.get("high", 0))
med  = int(sev.get("medium", 0))
low  = int(sev.get("low", 0))

# Surface MCP/AI-specific custom rule hits — rule ids defined in .semgrep.yml.
# The Droid uses this list to write specific FIX reasons; the wrapper does not
# gate on it.
CUSTOM_RULE_MARKERS = (
    "mcp-", "mcp_",
    "prompt-", "prompt_",
    "unsafe-llm", "llm-",
    "react-app-secret", "next-public-secret",
    "npm-lifecycle", "yaml-unsafe",
    "tool-description", "tool-output",
    "localstorage-sensitive",
)
custom = []
for r in data.get("tools", {}).get("semgrep", {}).get("results", []):
    rid = r.get("check_id", "") or ""
    low_id = rid.lower()
    if any(m in low_id for m in CUSTOM_RULE_MARKERS):
        custom.append({
            "rule": rid.split(".")[-1],
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "severity": r.get("extra", {}).get("severity"),
            "message": (r.get("extra", {}).get("message") or "")[:240],
        })

reasons = []
if crit > 0:
    reasons.append(f"{crit} CRITICAL finding(s)")
if high > 1:
    reasons.append(f"{high} HIGH findings (rubric allows <=1)")
if scan_exit == 2 and not reasons:
    reasons.append("sentinel-scan exited with critical-findings code but severity sum is zero (investigate)")

verdict = "APPROVE" if not reasons else "FIX"

out = {
    "target": name,
    "verdict": verdict,
    "severity": {"critical": crit, "high": high, "medium": med, "low": low},
    "fix_reasons": reasons,
    "mcp_rule_hits": custom[:20],
    "mcp_rule_hit_count": len(custom),
    "scan_report": os.path.relpath(path, os.getcwd()) if path.startswith(os.getcwd()) else path,
}
print(json.dumps(out, indent=2))
sys.exit(0 if verdict == "APPROVE" else 1)
PY
