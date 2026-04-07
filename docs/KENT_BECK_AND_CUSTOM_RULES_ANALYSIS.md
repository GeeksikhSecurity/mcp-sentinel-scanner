# Codebase Analysis: Kent Beck Rules & Custom Rules

**Date:** March 2026  
**Scope:** mcp-sentinel-scanner (Python codebase)  
**Applied fixes:** March 2026 — all high-priority no-inline-import fixes applied (see §6).

This document applies **Kent Beck’s Simple Design and TDD-related principles** and the **workspace custom rules** (no-inline-imports, typescript-exhaustive-switch) to the codebase.

---

## 1. Custom Rules

### 1.1 No inline imports

**Rule:** Imports at top of module; no inline imports in function bodies unless strict circular-dependency reason, documented.

**Findings:**

| Location | Issue | Recommendation |
|----------|--------|----------------|
| `src/sentinel/adapters/codeql.py` ~229 | `import yaml` inside function | Move to top; `yaml` is a normal dependency. |
| `src/codeql_optimizer.py` ~229 | Same `import yaml` inside function | Same as above. |
| `src/sentinel/core/scanner.py` ~197, ~206, ~336 | Lazy imports for reporters and `ContextAnalyzer` | Documented as circular-dependency / lazy load — **acceptable** if comment stays. Prefer moving to top behind `TYPE_CHECKING` or a dedicated loader if structure allows. |
| `src/mcp_sentinel_scanner.py` ~197, ~206, ~336 | Same reporter/context lazy imports | Same as scanner — acceptable if documented. |
| `src/sentinel/analyzers/builtin.py` ~30 | `from ..core.scanner import MCPSentinelScanner` in `_get_scanner()` | Documented circular import — **acceptable**. |
| `src/sentinel/cli/main.py` ~31–48, ~124, ~175, ~264 | Imports inside `_build_registry()`, `import json`, `import shutil`, `import json` in `init` | **Violations.** Move `json` and `shutil` to top. Optional-adapter try/except imports in `_build_registry()` are a pattern choice; consider documenting. |
| `tests/unit/test_error_handling.py` ~36, ~46 | `from scripts.sentinel_cli import load_config` inside tests | Move to top of file. |
| `tests/test_unified_scanner.py` ~130 | `from src.mcp_sentinel_scanner import ScanResult` inside test | Move to top. |
| `scripts/benchmark.py` ~52, ~179 | `import psutil`, `import shutil` inside functions | Move to top (or document if optional deps). |
| `src/sentinel/utils/anonymizer/result_anonymizer.py` ~138 | `import sys` in `if __name__ == '__main__'` | Acceptable for script block. |
| `src/anonymizer/result_anonymizer.py` ~138 | Same | Acceptable. |
| `src/test_reliability.py` ~181 | `import asyncio` in try block | Acceptable for optional/version-dependent use. |

**Summary:** Several clear violations (codeql, codeql_optimizer, sentinel cli main, benchmark, two test files). TYPE_CHECKING and documented circular-import lazy loads align with the rule.

### 1.2 TypeScript exhaustive switch

**Rule:** In switch over discriminated unions or enums, use a `never` check in the default case.

**Finding:** No TypeScript/TS switch statements in the repo (only JSX fixtures). **N/A.**

---

## 2. Kent Beck – Four Rules of Simple Design

### 2.1 Passes tests

- Tests exist under `tests/` (e.g. `test_scanner.py`, `test_cli.py`, `test_repo_corpus_runner.py`, `test_integration.py`, unit tests).
- Core 19 tests pass (see IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md).
- FP reduction is toggled via config (`configs/test_config.json`) so tests can assert on categories.
- **Verdict:** Compliant; test suite is used and passing.

### 2.2 Reveals intention

- Module and function names are generally clear (e.g. `MCPSentinelScanner`, `apply_false_positive_filter`, `ScanPipeline`, `detect_project_type`).
- Comments explain non-obvious choices (e.g. “Lazy import to avoid circular dependency”, “1 = findings found” for semgrep return code).
- **Verdict:** Largely good; a few long `elif` chains (e.g. in `enhanced_fp_filter`) could be refactored to named helpers to reveal intention even more.

### 2.3 No duplication (DRY)

- **Parallel trees:** Both `src/` and `src/sentinel/` contain overlapping concepts (e.g. `filters/`, `adapters/`, `reporters/`, `fp_reducer/`, `analyzers/`). Same logic appears in both (e.g. `mcp_sentinel_scanner.py` vs `sentinel/core/scanner.py`, `filters/config_filter.py` vs `sentinel/filters/config_filter.py`). This is structural duplication and increases maintenance cost.
- **Inline import pattern:** Same lazy-import pattern repeated in `mcp_sentinel_scanner.py` and `sentinel/core/scanner.py` for reporters and context analyzer.
- **Verdict:** Duplication exists; consolidating on one tree (e.g. `src/sentinel/`) and sharing implementation would better satisfy this rule.

### 2.4 Fewest elements

- Optional adapters use try/except inline imports in multiple places; a single “plugin loader” or registry that handles optional deps could reduce repetition.
- Two code paths (legacy `src/` and `sentinel/`) mean two of many components (scanner, filters, adapters, etc.); unifying would reduce elements.
- **Verdict:** Room to reduce elements by removing duplicate trees and centralizing optional imports.

---

## 3. Kent Beck – TDD / Test Design

- Tests are named by behavior (`test_malformed_config_file`, `test_scanner_regression_fixtures`, `test_cli_respects_output_file`), which supports readability and refactoring.
- Some tests use inline imports (`load_config`, `ScanResult`); moving those to the top would align with the custom rule and keep test code consistent.
- Regression fixtures under `tests/fixtures/scanner_regression/` are a good way to lock behavior.
- **Verdict:** Test design is in good shape; applying the no-inline-import rule in tests would strengthen it.

---

## 4. Single Level of Abstraction / Small Functions

- `sentinel/cli/main.py`: `_build_registry()` does registration and optional imports; `doctor()` mixes table building with tool checks and inline `shutil`. Moving stdlib imports to top and extracting “list of external tools” and “check one tool” would clarify abstraction.
- Long `elif` chains in FP filters (e.g. file_type, directory_type) could be replaced with small functions or data-driven checks to keep one level of abstraction per function.
- **Verdict:** Mostly fine; a few hotspots would benefit from extraction and top-level imports.

---

## 5. Summary Table

| Criterion | Status | Notes |
|-----------|--------|-------|
| **Custom: No inline imports** | Violations | Fix codeql, codeql_optimizer, sentinel cli main, benchmark, test_error_handling, test_unified_scanner; keep documented circular/lazy imports. |
| **Custom: Exhaustive switch (TS)** | N/A | No TS switch usage. |
| **Kent Beck: Passes tests** | OK | Tests present and used. |
| **Kent Beck: Reveals intention** | OK | Naming and comments generally good. |
| **Kent Beck: No duplication** | Weak | Parallel `src/` and `src/sentinel/`; repeated lazy-import pattern. |
| **Kent Beck: Fewest elements** | Weak | Two trees; repeated optional-import pattern. |
| **TDD / test design** | OK | Move test imports to top. |
| **Single level of abstraction** | Minor | Improve in CLI and FP filter branches. |

---

## 6. Recommended Next Steps (Priority)

1. **Fix no-inline-import violations (high):** ✅ **DONE (March 2026)**
   - Moved `json` and `shutil` to top in `src/sentinel/cli/main.py`.
   - Moved `yaml` to top in `src/sentinel/adapters/codeql.py` and `src/codeql_optimizer.py`.
   - Moved `psutil` (optional try/except at top) and `shutil` to top in `scripts/benchmark.py`.
   - Moved `load_config` import to top in `tests/unit/test_error_handling.py`.
   - Moved `ScanResult` import to top in `tests/test_unified_scanner.py`.

2. **Reduce duplication (medium):**
   - Decide canonical path: `src/` vs `src/sentinel/`, and migrate callers to one tree; deprecate or remove the other to satisfy “no duplication” and “fewest elements.”

3. **Refine abstraction (low):**
   - In `sentinel/cli/main.py`, extract external-tool list and use top-level `shutil`/`json`.
   - ~~In FP filters, extract long `elif` chains into small functions or data-driven logic.~~ ✅ **DONE** — see §7.

Applying the custom rules and Kent Beck’s rules consistently will keep the codebase easier to change and reason about.

---

## 7. Modularity refactor: `enhanced_fp_filter.py` (V = N×K/T × σ)

Refactored **one specific file** to increase **N** (modularity) and reduce **T** (time to change), illustrating the Real Options / “Make it Right” value formula.

### Formula reminder

$$V = \frac{N \times K}{T} \times \sigma$$

- **N** = number of independent modules/choices (modularity).
- **K** = parallel experiments (team bandwidth).
- **T** = time to run an experiment (deployment / change latency).
- **σ** = uncertainty (value of options in a changing market).

### Before (single “tangled” module)

| Aspect | Before | Effect on formula |
|--------|--------|--------------------|
| **N** | One logical “blob”: file + directory + scoring + recommendation all expressed as long `if`/`elif` chains inside a few methods. | Low effective N: changing one rule risked touching shared control flow; no clear “module” per concern. |
| **T** | Adding a new file-type rule or penalty required editing nested conditionals and duplicating the structure of existing branches. | **T** high: every change required careful reading of long methods. |
| **K** | Hard to run “experiments” (e.g. try a new threshold or rule) without editing the same big methods. | **K** limited by coupling. |

### After (data + small functions)

| Aspect | After | Effect on formula |
|--------|--------|--------------------|
| **N** | **Data modules:** `FILE_TYPE_RULES`, `DIRECTORY_TYPE_RULES`, `CONTEXT_PENALTY_MULTIPLIERS`, `ENTROPY_CONFIG_KEY_BY_VULN`, `RECOMMENDATION_BANDS`. **Pure helpers:** `_classify_by_keywords`, `_classify_path_parts`, `_classify_file_extension`, `_get_entropy_threshold`, `_apply_context_penalties`, `_recommendation_for_confidence`. Each has one responsibility; rules can be swapped or extended without rewriting control flow. | **N** increased: many small, testable units and explicit data tables. |
| **T** | New file-type or directory-type rule = add one row to a list of tuples. New penalty = add one dict entry. New recommendation band = add one tuple. No need to touch `_calculate_confidence_score` or long `elif` chains. | **T** reduced: change latency drops because edits are local to data or a single helper. |
| **K** | Different team members (or experiments) can adjust rules, thresholds, or bands in parallel by editing different data structures or helpers. | **K** can increase (fewer merge conflicts, clearer ownership of “this table” vs “that function”). |

### Summary

- **Before:** One file, few “modules” in the options sense; long branches made **T** high and **N** low.
- **After:** Same file, but **N** is higher (data tables + pure functions), **T** is lower (data-driven edits), so **V** improves for future experiments (e.g. tuning FP rules or adding a new context type).

**File refactored:** `src/sentinel/filters/enhanced_fp_filter.py`. Public API (`FilterResult`, `EnhancedFPFilter`, `analyze_finding`, `batch_filter`) unchanged; behavior preserved.
