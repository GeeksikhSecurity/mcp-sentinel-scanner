#!/usr/bin/env bash
# Phase 2 production-style tuning (append to same results file).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS="${CORPUS:-/Volumes/2TBSSD/phase2-corpus}"
RESULTS="${PHASE2_RESULTS:-/Volumes/2TBSSD/phase2-results.txt}"
TMP="${PHASE2_TMP:-/Volumes/2TBSSD/phase2-tmp}"
SCANNER="${SCANNER:-$ROOT/scripts/sentinel_cli.py}"
CONFIG="${CONFIG:-$ROOT/configs/security_rules.json}"
PYTHON="${PYTHON:-python3}"

mkdir -p "$TMP"
cd "$CORPUS"

{
  echo "=== PRODUCTION SCAN (Phase 2 Config) ==="
  echo "Timestamp: $(date)"
  echo "Corpus: $CORPUS"
  echo ""
} >> "$RESULTS"

for repo in */; do
  repo_name="${repo%/}"
  echo "Scanning: $repo_name (PRODUCTION CONFIG)" | tee -a "$RESULTS"

  if ! "$PYTHON" "$SCANNER" "$repo_name" \
    -c "$CONFIG" \
    --exclude node_modules dist build .git vendor target __pycache__ .venv venv .cargo \
    --secret-shannon-entropy-min 3.5 \
    --parallel-workers 12 \
    -f json \
    -o "$TMP/production-${repo_name}.json" \
    -q
  then
    echo "  SCAN FAILED" | tee -a "$RESULTS"
    echo "" >> "$RESULTS"
    continue
  fi

  TOTAL=$("$PYTHON" -c "import json,sys; p=json.load(open(sys.argv[1])); print(len(p.get('findings',[])))" "$TMP/production-${repo_name}.json" 2>/dev/null || echo "ERR")
  CRITICAL=$("$PYTHON" -c "import json,sys; p=json.load(open(sys.argv[1])); print(len([f for f in p.get('findings',[]) if f.get('severity')=='CRITICAL']))" "$TMP/production-${repo_name}.json" 2>/dev/null || echo "ERR")

  echo "  Total Findings: $TOTAL | CRITICAL: $CRITICAL" | tee -a "$RESULTS"
  echo "" >> "$RESULTS"
done

echo "Done. JSON under $TMP ; summary appended: $RESULTS"
