# MCP Corpus Test — Findings & Validation (2026-06)

Test of the improved scanner against **40 public MCP repositories** (two batches of
20), spanning 7 language SDKs and 12+ categories (cloud, database, browser, search,
DevOps, SaaS, vector DB, payments, design). Run with the **core scanner**
(`unified:false`) to exercise the restored secret detection directly.

## Headline result — the secret-detection fix works on real code

`punkpeye/fastmcp : fastmcp-analytics.js:6 — hardcoded_secret (CWE-798), entropy=3.80`

At the broken floor the optimizer had reached (6.0), this was **invisible**; at the
restored default (3.5) it is caught. `3.5 ≤ 3.80 < 6.0` is exactly the gap closed by
the entropy fix. (It is a client-side Amplitude analytics key — low sensitivity — but
a genuine true positive.)

## Batch totals (core scanner)

| Batch | Repos | Files | Findings | Severity |
|-------|-------|-------|----------|----------|
| 1 | 20 | 5,797 | 9 | 1C / 5H / 3M |
| 2 | 20 | 4,227 | 19 | 19H |

Density ≈ 1.6–4.5 findings / 1,000 files — a conservative, low-noise posture
(compare a `unified:true` internal-analyzer run: 24/1,000, mostly npm-advisory noise).

## aws-mcp deep-dive — all 5 findings are FALSE POSITIVES

The core run flagged 5 issues in `awslabs/mcp`. On inspection of the actual code,
**every one is a false positive** — and the code even carries the exact markers that
should have suppressed them:

| Finding | Location | Verdict | Why it's a FP |
|---------|----------|---------|---------------|
| `dangerous_function` subprocess.Popen (HIGH) | `aws-transform-mcp-server/.../oauth.py:51,55` | **FP** | `subprocess.Popen(['open', url])` / `['xdg-open', url]` — **list args, no `shell=True`**, opens the OAuth authorize URL (public PKCE values, no tokens) in the browser. The standard, safe browser-open idiom. |
| `dangerous_function` subprocess.Popen (HIGH) | `dynamodb-mcp-server/.../model_validation_utils.py:777` | **FP** | `subprocess.Popen(cmd, ...)` launches **DynamoDB Local** (a fixed Java argv list, no user input, no shell). |
| `weak_crypto` MD5 (MEDIUM) | `aws-healthomics-mcp-server/.../s3_search_engine.py:931` | **FP** | `hashlib.md5(key_str.encode(), usedforsecurity=False)` — a **cache key**, explicitly marked non-security. |
| `weak_crypto` MD5 (MEDIUM) | `.../genomics_search_orchestrator.py:1148` | **FP** | Same: `hashlib.md5(..., usedforsecurity=False)` for a pagination cache key. |

### Root cause (scanner-side)

Two rules are **name-match heuristics** that ignore the safety context present in the
code:

1. **`dangerous_function` / subprocess.Popen** fires on the call name alone. It does
   not check whether `shell=True` is set or whether the arguments are a fixed list
   vs. an interpolated string. A list-arg `Popen` without `shell=True` is not a
   command-injection surface.
2. **`weak_crypto` / hashlib.md5** fires on `md5`/`sha1` regardless of the
   `usedforsecurity=False` flag — the standard Python signal that the digest is for
   caching/checksums, not security.

(Both also relate to issue #10 — `subprocess.Popen` is mislabeled CWE-95; it should be
CWE-78/CWE-77 when it *is* a real finding.)

### Recommended scanner fix

Add context gates before flagging:
- **subprocess**: only flag when `shell=True` **or** an argument is a non-literal
  (interpolated/concatenated) string. Suppress fixed-list `Popen`/`run` without a shell.
- **weak hash**: suppress `hashlib.md5(...)/sha1(...)` when `usedforsecurity=False` is
  passed.

This is the same lesson as the documented `mcp-insecure-random` rule: a bare
name-match pattern over-reports. Context-awareness converts these FPs to silence
without losing the true-positive case (a `shell=True` Popen with interpolated input, or
an MD5 used as a password hash).

## Net

- ✅ Secret detection restored and proven against real public code.
- ✅ Conservative, low-noise core scanner across 40 diverse MCP repos, zero crashes.
- ⚠️ FP sources to fix: subprocess and weak-hash rules need context gates (this doc);
  language coverage is Python/JS/TS-centric (issue #9); CWE-95 mislabel (issue #10);
  unified adapters fail silently (issue #8).

## Lessons learned (resolved this round)

1. **Prose rule ≠ prevention.** `CLAUDE.md` already documented the entropy-floor
   hazard, yet the phase2 scripts re-baked it (6.5/6.0) because nothing *checked*
   the committed scripts. Fix: `scripts/lint-invariants.py` + CI — the invariant
   is now a commit-time gate (reads the ceiling from the scanner so it can't
   drift). **When a reviewer catches what your rule already forbade, ship the
   missing check, not just the fix.**
2. **Silent tooling is worse than missing tooling.** The semgrep/trufflehog
   adapters returned `[]` on timeout/error with no warning → false coverage
   confidence. Removed them (issue #8); run those tools dedicated. A precise core
   beats a silent aggregate.
3. **Name-match detectors over-report; gate on context.** `subprocess.Popen`
   without `shell=True` isn't command injection; `hashlib.md5(...,
   usedforsecurity=False)` isn't weak crypto. Context gates + a regression test
   eliminated 5 aws-mcp false positives with zero true-positive loss.
4. **Duplicated logic drifts.** The same detectors live in
   `src/mcp_sentinel_scanner.py` AND `src/sentinel/core/scanner.py`; both needed
   the same fix. Consolidating to one source of truth is open follow-up.
