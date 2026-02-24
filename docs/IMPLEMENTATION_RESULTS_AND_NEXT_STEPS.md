# Implementation Results and Planned Next Steps

**Date:** February 2026  
**Version:** 1.5.0  

## 1. Results Implemented

### 1.1 Fix import / add `src/types.py`

- **Done.** Added [src/types.py](../src/types.py) with `VulnerabilityFinding`, `ScanSummary`, and `ScanResult` dataclasses and a `TYPE_CHECKING` import for `AdvancedFinding` to avoid circular imports.
- Package import and scanner/tests now run without `ModuleNotFoundError: No module named 'src.types'`.

### 1.2 Verify FP reduction (tests and corpus)

- **Done.** Core tests pass (`tests/test_scanner.py`, `tests/test_repo_corpus_runner.py`). Smoke corpus runs successfully with `PYTHONPATH=. python scripts/run_repo_corpus.py --tier smoke`.
- Smoke tier: 2 local fixtures (fixture-mcp-servers, fixture-mcp-typescript). Output under `reports/repo_corpus/`.

### 1.3 Add nightly tier and run nightly corpus

- **Done.** [configs/repo_corpus.json](../configs/repo_corpus.json) version 2: remote GitHub repos (modelcontextprotocol/servers, python-sdk, typescript-sdk) use tier `nightly`.
- [scripts/run_repo_corpus.py](../scripts/run_repo_corpus.py) accepts `--tier smoke|full|nightly|all`. [.github/workflows/repo-corpus-nightly.yml](../.github/workflows/repo-corpus-nightly.yml) default tier is `nightly`; run with network to clone and scan remote repos.
- Nightly corpus run completed; output under `reports/repo_corpus_nightly/` (3 repos, JSON/SARIF per repo).

### 1.4 Enrich corpus manifest with MCP repos

- **Done.** Full tier now includes local MCP repos under `test_repos/`: local-fastmcp, local-mcp-python, local-mcp-typescript, local-mcp-servers, local-mcp-use, local-mcp-quickstart (relative paths from repo root). Running `--tier full` scans these when present.

### 1.5 Add test fixtures from findings

- **Done.** [tests/fixtures/scanner_regression/](../tests/fixtures/scanner_regression/) added:
  - `command_injection_fixture.py` – `subprocess.run(..., shell=True)` with variable (expect command_injection).
  - `hardcoded_secret_fixture.py` – quoted `CLIENT_SECRET` (expect hardcoded_secret).
  - `fp_negative_fixture.py` – variable names only, no quoted secrets (expect no hardcoded_secret).
- [tests/test_scanner.py](../tests/test_scanner.py): `test_scanner_regression_fixtures()` asserts expected categories per fixture.

### 1.6 Repo debloat (scans/ and test_repos/)

- **Deferred.** Plan was to remove or stop tracking `scans/` and `test_repos/` in the main repo. Not done in this pass because:
  - Full-tier corpus uses `test_repos/` (local MCP repos).
  - Removing or untracking would require either moving those repos to a separate clone/cache (e.g. CI-only) or documenting them as optional developer data.
- Recommended next step: add `scans/` and `test_repos/` to `.gitignore` and document that full corpus expects a separate clone of MCP repos into `test_repos/`, or introduce a manifest-only “full” tier that clones on demand (like nightly) and drop in-repo `test_repos/`.

---

## 2. Resumed work (latest)

- **CLI / scanner tests:** FP reduction is on by default in `MCPSentinelScanner`, so scanning `tests/` yielded 0 findings and broke tests that assert on categories/findings. Fixed by:
  - Adding [configs/test_config.json](../configs/test_config.json) with `"falsePositives": { "enabled": false }`.
  - [tests/test_cli.py](../tests/test_cli.py) `test_cli_respects_output_file` now uses `-c configs/test_config.json`.
  - [tests/test_scanner.py](../tests/test_scanner.py) uses `_TEST_CONFIG` (same config) for tests that assert on finding categories (test_scan_detects_expected_categories, test_ast_detects_dangerous_calls, test_advanced_detection_identifies_semantic_issues, test_scanner_regression_fixtures, test_report_serialisers).
- **Result:** Core tests (test_cli, test_scanner, test_repo_corpus_runner, test_integration) all pass (19 tests).

---

## 3. Planned Next Steps

1. **Run full test suite** (all 150+ tests) and fix any remaining failures; ensure CI runs with `PYTHONPATH=.` or equivalent when invoking `scripts/run_repo_corpus.py`.
2. **Pin nightly refs:** In [configs/repo_corpus.json](../configs/repo_corpus.json), replace `"ref": "main"` with pinned commit SHAs for deterministic nightly runs.
3. **Repo debloat:** Decide policy for `scans/` and `test_repos/` (ignore and document, or clone-on-demand for full tier); update [STATUS.md](../STATUS.md) and [Makefile](../Makefile) if present.
4. **Optional:** Port enriched corpus manifest and FP improvements from the sbq worktree into main (e.g. additional local paths, nightly-only repos) and re-run corpus; document in this file.
5. **Optional:** Add a short “Corpus run” section to [STATUS.md](../STATUS.md) (smoke / full / nightly tiers, where outputs live, how to run).

---

## 4. Quick reference

| Tier    | Repos | Location / notes |
|---------|-------|-------------------|
| smoke   | 2     | tests/fixtures/repo_corpus (mcp-servers, mcp-typescript) |
| full    | 6     | test_repos/* (fastmcp, mcp-python, mcp-typescript, mcp-servers, mcp-use, mcp-quickstart) |
| nightly | 3     | Remote GitHub (modelcontextprotocol/servers, python-sdk, typescript-sdk); clone to .cache/repo_corpus |

Run smoke: `make corpus-smoke` or `PYTHONPATH=. python scripts/run_repo_corpus.py --tier smoke`  
Run full: `make corpus-full` (requires test_repos/ populated)  
Run nightly: `make corpus-nightly` or `PYTHONPATH=. python scripts/run_repo_corpus.py --tier nightly` (requires network)

---

## 5. Blog posts (SecurityLeader.ai / whitepaper / conferences)

Markdown posts for security research and publication are in [docs/blog/](blog/):

1. **[01 – MCP security landscape and sentinel tooling](blog/01-mcp-security-landscape-and-the-need-for-sentinel-tooling.md)** — Threat landscape, research foundation, role of MCP-aware scanning (intro for blog or SANS/BSIDES whitepaper).
2. **[02 – Corpus methodology and real-world findings](blog/02-corpus-methodology-and-real-world-findings.md)** — Tiered corpus design, detection categories, FP reduction, example results, reproducibility (methods and results section).
3. **[03 – Operationalizing MCP security scanning](blog/03-operationalizing-mcp-security-scanning.md)** — CLI, corpus runs, CI/CD, reports, using results in whitepapers and talks (recommendations / practitioner track).

See [docs/blog/README.md](blog/README.md) for suggested use (SecurityLeader.ai, SANS, BSIDES).
