# Session Handoff — cubic review remediation (resume here)

_Last updated: 2026-06-11. Pick up from the "Open / next" sections._

## TL;DR
Three repos worked this session, each via cubic.dev review → verify-against-code →
fix → test → commit. The throughline lesson, now codified: **a prose rule isn't
prevention until it's a mechanical CI check.**

---

## 1. mcp-sentinel-scanner  ← MAIN ACTIVE WORK (PR #7)

**Branch:** `pr/cubic-review-20260407-193437` → PR **#7** (open, base `main`). All
pushed. CI: cubic ✅, all lint-and-test/test matrices ✅, security-scan ✅,
repo-corpus-nightly fixed (was malformed YAML).

**Landed this session (newest first):**
- `2b1b07c` fix nightly workflow malformed `on:` block
- `5a793c2` docs: lessons learned
- `ffade40` **invariant lint** `scripts/lint-invariants.py` + CI (I1 entropy ceiling,
  I2 mcp-insecure-random no-op, I3 KQL injection, I4 reintroduced adapters)
- `60bfbd1` **FP context gates** — subprocess (shell=True only) + weak_crypto
  (skip usedforsecurity=False); aws-mcp's 5 FPs eliminated; regression test added
- `2ce7934` **full-delete semgrep/trufflehog/codeql adapters**; registry analyzer-only
- `093c10b` docs/mcp-corpus-test-findings.md (40-repo corpus + aws-mcp FP validation)
- earlier: entropy floor 6.0→3.5 + recall gate + fail-loud guard; prose-analyzer
  feature; phase2 script + KQL fixes; tabulate/colorama dep + stderr-test fix

**Verification env (to re-run):**
```
python3 -m venv /tmp/sentinel-scan-venv && /tmp/sentinel-scan-venv/bin/pip install -e . pytest pytest-mock pytest-asyncio
cd <repo> && PYTHONPATH=. /tmp/sentinel-scan-venv/bin/python -m pytest tests/ -o addopts="" -q   # 267 pass
python3 scripts/lint-invariants.py    # invariant gate (green)
```
Corpus re-run: `PYTHONPATH=. .../python scripts/run_repo_corpus.py --tier nightly --manifest /tmp/mcp20_manifest.json --cache-dir /tmp/mcp20_cache --output-dir /tmp/mcp20_out`

**Open issues filed:** #8 (silent adapters — resolved by removal), #9 (language
coverage Rust/Kotlin/Swift), #10 (subprocess CWE-95→78 mislabel), #11 (duplicated
detector logic in `src/mcp_sentinel_scanner.py` vs `src/sentinel/core/scanner.py`).

**Open / next:**
- [ ] **#11 — consolidate the two duplicated scanner modules** (highest structural
  risk: the FP fix had to be applied twice). One source of truth for patterns/detectors.
- [ ] #10 — relabel subprocess/os.system CWE-95 → CWE-78/77.
- [ ] #9 — extend analyzer coverage to .rs/.kt/.swift.
- [ ] Merge PR #7 once reviewed.
- [ ] Untracked, unrelated dirs left alone deliberately: `mggraph-intune-samples/`,
  `scripts/m365-*`, `scripts/*.ps1`, `docs/roadmap/`, `optimization_log.jsonl`.

---

## 2. securityleaderai-blog (PR #1)

**Branch:** `ci/code-invariants-completion-integrity` → PR **#1** (open). All pushed,
CI green (the "Invariants, type-check, build" gate I added passes).
- Landed: `lint-code-invariants.mjs` + CI; fixed 5 cubic findings (topic counts,
  ISO dates, video type, JSON-LD escape, robots host); removed unused video
  subsystem; RULES.md §8/§9/§10; updated `~/.claude/CLAUDE.md`.
- **Open / next:** merge PR #1. (`tsconfig.json` shows modified — pre-existing,
  not mine; leave it.)

---

## 3. translit-search-poc  ← HAS UNFINISHED WORK

**Branch:** `fix/cubic-review-dataset` (LOCAL ONLY — no git remote; nothing pushed).
- Done: `b182b17` make_record() single source; `f1653fe` faithful Shahmukhi display.
- **`a4482fb` is WIP / INCOMPLETE:** build_dataset.py emits `data/normalization.json`
  (single source for SHAH_UNIFY + harakat) but **`lib/search.ts` still hardcodes the
  duplicate tables** — the Python/TS drift fix is half-done.
  - [ ] **RESUME:** edit `lib/search.ts` to `import normalization from "@/data/normalization.json"`
    and derive `SHAH_UNIFY = normalization.shah_unify` + build `HARAKAT` regex from
    `normalization.harakat`, removing the hardcoded literals. Then `npx tsc --noEmit`
    (tsconfig has `resolveJsonModule: true`, `@/*` paths). Re-run `build_dataset.py`
    via the bench venv (`../pdl-translation-bench/.venv/bin/python`) → confirm
    records.json no-op diff. Then drop the WIP and commit properly.
  - Optional follow-up: `--check` mode on build_dataset.py (rebuild→diff→exit 1) +
    the F-3 sacred-badge decision was "leave as-is" (no change).

---

## 4. gingerCube / maxRVU audit
Delivered out-of-band (confidential — named recipients only until T0 rotation +
history scrub confirmed). Artifacts: plain-language briefing, backdoor explainers,
regression tests, T0 rotation runbook, sanitized Jira stubs, one-pager. Not code in
these repos. See the private channel; do not reference findings here.

---

## How I work these (the agreed loop)
read folder → verify each cubic finding against real code (never trust the capture;
re-run, line numbers drift) → fix → **prove** (test/empirical) → commit small →
push → **convert each accepted finding into a mechanical guard** → document the
lesson. Rules live in `~/.claude/CLAUDE.md` (global) + blog `RULES.md`.
