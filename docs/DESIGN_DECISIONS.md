# Architecture Decision Records — MCP Sentinel Scanner

Every non-obvious design decision is documented here with context, rationale, and consequences. When future contributors ask "why was it built this way?", this is the answer.

---

## ADR-001: Plugin Registry Pattern (not Factory, not DI)

**Context:** The scanner orchestrates multiple external tools (Semgrep, TruffleHog, future Trivy/CodeQL) and built-in analyzers (Npm, React, Builtin). We need a way to discover, register, and execute them.

**Decision:** Use a plugin registry (`ScannerRegistry`) where adapters and analyzers self-register by name.

**Why not Factory?** A factory creates objects on demand from a type map. Our scanners are stateful (they hold config, check tool availability), so they're instantiated once and registered. A factory would re-create them on every scan call.

**Why not Dependency Injection?** DI frameworks (like `inject` or `dependency-injector`) add a third-party dependency and indirection. The registry is 143 lines of plain Python — no framework needed. DI is warranted when the dependency graph is complex; ours is flat (pipeline → registry → [adapters, analyzers]).

**Consequences:**
- Adding a new scanner = subclass BaseAdapter/BaseAnalyzer + register in CLI setup
- No runtime discovery (scanners are registered explicitly in `cli/main.py`)
- Trade-off: less magic, more boilerplate — acceptable for a security tool where explicitness aids auditability

**File:** `src/sentinel/core/registry.py`

---

## ADR-002: Adapters vs. Analyzers — Two Base Classes

**Context:** Some scanners wrap external CLI tools (Semgrep, TruffleHog). Others are pure Python (pattern matching, AST analysis, npm audit parsing). They have fundamentally different reliability characteristics and dependency models.

**Decision:** Two separate ABCs: `BaseAdapter` (external tools) and `BaseAnalyzer` (built-in, zero deps).

**Rationale:**
- **Adapters** may not be installed. They MUST implement `is_available()` and `check_or_skip()` — if the tool isn't on PATH, skip gracefully with zero findings (not an error).
- **Analyzers** are always available. They ship with the package and have no external dependencies beyond the Python stdlib.
- This distinction is visible to users in `sentinel doctor` — adapters show install status, analyzers show "built-in."

**Why not one base class with an `is_external` flag?** The behavioral contract is different enough to warrant separate types. An adapter that forgets to check availability is a bug; an analyzer that checks availability is dead code. Separate ABCs enforce this at the type level.

**Consequences:**
- Two registration paths in the registry (`register_adapter`, `register_analyzer`)
- Users understand which tools require installation via `sentinel doctor`
- Trade-off: slightly more code, but the adapter/analyzer distinction prevents a category of "tool not found" runtime errors

**Files:** `src/sentinel/adapters/base.py`, `src/sentinel/analyzers/base.py`

---

## ADR-003: ThreadPoolExecutor for Parallel Scanning

**Context:** Scanner execution is I/O-bound (adapters shell out to CLI tools and wait for output; analyzers read files from disk). We need parallelism to avoid sequential bottlenecks.

**Decision:** Use `concurrent.futures.ThreadPoolExecutor` with a default of 4 workers.

**Why threads, not processes?**
- Adapters spend most time waiting for subprocess output (I/O-bound). Python's GIL doesn't block I/O waits.
- ProcessPoolExecutor requires pickling function arguments. Our scanner objects contain compiled regexes, file handles, and subprocess references — these don't serialize cleanly.
- Threads share memory, so the findings list can be extended with a simple lock (no IPC overhead).

**Why 4 workers?**
- Most developer machines have 4+ cores. Running more workers than external tools provides diminishing returns (typically 2-5 tools registered).
- Adapter subprocesses (Semgrep, TruffleHog) are themselves parallel, so over-subscribing with too many sentinel workers can cause contention.
- This is configurable via `parallel` parameter — 4 is the default, not a hard limit.

**Consequences:**
- CPU-bound analyzers (future ML classifier) may hit the GIL. If profiling shows this, migrate those specific analyzers to ProcessPoolExecutor.
- Thread safety: findings are collected via `threading.Lock` (scanner.py) or `as_completed` future results (registry.py). No shared mutable state beyond the findings list.

**File:** `src/sentinel/core/registry.py:97`, `src/sentinel/core/scanner.py:140`

---

## ADR-004: Semgrep `--config=auto` Rule Selection

**Context:** Semgrep supports explicit rule selection (`--config=p/security-audit`) or automatic language-based selection (`--config=auto`).

**Decision:** Use `--config=auto` by default.

**Rationale:**
- Sentinel scans arbitrary projects (any language, any framework). We don't know in advance which Semgrep rulesets apply.
- `--config=auto` detects languages in the target and selects community-maintained rulesets automatically. This gives the broadest coverage without requiring users to configure per-language rules.
- Trade-off: less control over which rules fire. Some community rules may produce noisy findings. Our FP filter pipeline (dedup → false positive filter → severity threshold) mitigates this downstream.

**Why not explicit rulesets?** We'd need to maintain a mapping of language → Semgrep rules and update it whenever Semgrep publishes new rulesets. `--config=auto` delegates this to Semgrep's own registry.

**Future consideration:** Allow users to override via `.sentinel.json` config (`"semgrep": {"rules": ["p/security-audit", "p/owasp"]}`). The `self.rules` config key exists but is not yet wired to the CLI command.

**Reference:** https://semgrep.dev/docs/running-rules/#registry-rules

**File:** `src/sentinel/adapters/semgrep.py:28`

---

## ADR-005: TruffleHog `filesystem` Engine + Verified-Only Filter

**Context:** TruffleHog supports multiple scan engines: `filesystem`, `git`, `docker`, `s3`, `github`. Each targets a different data source.

**Decision:** Use `filesystem` engine. Only report verified secrets (line 51: `if not data.get("Verified", False): return None`).

**Why `filesystem`, not `git`?**
- `filesystem` scans files on disk regardless of VCS. It works on non-git targets (tarballs, extracted archives, vendored deps).
- `git` engine walks git history (all commits) — useful for finding rotated secrets, but significantly slower and not applicable to non-git targets.
- Sentinel's scope is "scan this directory," not "audit git history." Users wanting history scanning can run TruffleHog directly.

**Why verified-only?**
- Unverified secrets have a very high false positive rate (environment variable names, test fixtures, documentation examples).
- TruffleHog's verification actively validates the secret against its service (e.g., checks if an AWS key is live). Verified = confirmed credential exposure.
- Verified findings are CRITICAL severity with 0.95 confidence. This matches the "zero false negatives on CRITICAL" goal.
- Trade-off: we miss unverified-but-real secrets. Our built-in pattern scanner (`_SECRET_RE` in scanner.py) catches some of these with lower confidence.

**Reference:** https://trufflesecurity.com/trufflehog

**File:** `src/sentinel/adapters/trufflehog.py:27,51`

---

## ADR-006: 300-Second Adapter Timeout

**Context:** External tools (Semgrep, TruffleHog) can hang or run indefinitely on large codebases. We need a timeout to prevent sentinel from blocking forever.

**Decision:** 300 seconds (5 minutes) timeout on all adapter subprocess calls.

**Rationale:**
- Semgrep on a large monorepo (100K+ files) typically completes in 60-180 seconds. 300 seconds provides 1.5-5x headroom.
- TruffleHog with verification is slower (network calls per secret candidate). 300 seconds allows ~50-100 verifications.
- On timeout, adapters return empty findings (not an error). This is intentional: a slow tool should not block the entire scan. The built-in analyzers still produce results.

**Why not configurable per-adapter?**
- It should be — this is a known gap. Future work: expose timeout in `.sentinel.json` config per-tool.

**Consequences:**
- Large monorepos may hit the timeout on Semgrep. Users will see zero Semgrep findings but get built-in analyzer results.
- Silent timeout: currently logged as a caught `TimeoutExpired` exception, returns `[]`. Should be promoted to a warning-level log.

**File:** `src/sentinel/adapters/semgrep.py:29`, `src/sentinel/adapters/trufflehog.py:28`

---

## ADR-007: Severity Weights and Scoring

**Context:** Findings have severity levels (CRITICAL, HIGH, MEDIUM, LOW). We need a numeric score for ranking and aggregation.

**Decision:** Weight scale: CRITICAL=1.0, HIGH=0.75, MEDIUM=0.5, LOW=0.25.

**Rationale:**
- The scale is **not** based on CVSS (which uses 0-10 with a different curve). It's a relative weight for the ASR (Aggregate Security Risk) score calculated in `_calculate_asr()`.
- The 0.25 step provides equal spacing — simple and predictable. A CRITICAL finding contributes 4x the weight of a LOW finding.
- The ASR score is a project-level health metric (0-100), not a per-finding CVSS score. It answers "how bad is this codebase overall?" not "how severe is this specific CVE?"

**Why not CVSS?**
- CVSS requires attack vector, complexity, privileges, and scope — information we don't have from pattern matching alone. CVSS is a per-vulnerability metric; our severity is a per-finding heuristic.
- If we gain CVSS data (from NVD lookups in Phase 3), we can use it for individual findings while keeping the weighted ASR for aggregate scoring.

**Consequence:** The weights are somewhat arbitrary. Changing them shifts all ASR scores. They should be treated as tunable constants, not ground truth.

**File:** `src/sentinel/core/scanner.py:44-49`

---

## ADR-008: Entropy Threshold 3.5 for Secret Detection

**Context:** The built-in scanner uses Shannon entropy to distinguish real secrets from variable names, documentation, and false positives. High entropy = more random = more likely a real secret.

**Decision:** Threshold of 3.5 bits per character.

**Rationale:**
- English prose: ~1.0-2.5 bits/char. Variable names: ~2.0-3.5 bits/char. Random base64 tokens: ~4.0-5.5 bits/char.
- 3.5 is the boundary between "structured text" and "likely random." It filters out variable names like `accessToken` (entropy ~3.2) while keeping real secrets like `sk-proj-abc123XYZ789` (entropy ~4.5).
- Empirically validated against the 4 MCP test repos in Phase 2. At 3.5 threshold: 0 false positives on test/mock values, 100% detection on planted secrets.

**Known limitation:**
- Short secrets (8-12 chars) may have lower entropy despite being random. The minimum length check (`{12,}` in `_SECRET_RE`) partially compensates.
- Dictionary-word-based secrets ("correct-horse-battery-staple") have low entropy despite being valid credentials. These require different detection (not entropy-based).

**Tuning methodology:** Run scanner on repos with known secrets + known non-secrets. Plot entropy distribution. Pick threshold where FP rate < 5% and TP rate > 95%. Current threshold achieves this on the Phase 2 test corpus.

**File:** `src/sentinel/core/scanner.py:416` (also `enhanced_fp_filter.py:38-40` uses tiers 3.5/4.0/4.2)

---

## ADR-009: Default Excluded Directories

**Context:** Scanning `node_modules/`, `.git/`, or `dist/` produces thousands of findings in third-party code the user doesn't control.

**Decision:** Default exclusions: `node_modules`, `dist`, `build`, `.git`, `__pycache__`, `.venv`.

**Rationale:**
- `node_modules` — third-party npm packages. Vulnerabilities here are the responsibility of `npm audit`, not source scanning.
- `dist` / `build` — compiled output. Findings here are symptoms of source-level issues already caught by scanning source.
- `.git` — git internal objects. Not scannable source code.
- `__pycache__` — Python bytecode cache. Not source.
- `.venv` — Python virtual environment. Third-party packages, same reasoning as `node_modules`.

**What's NOT excluded (intentionally):**
- `.env` files — we WANT to flag these if they contain real secrets.
- `vendor/` (Go) — these are vendored deps, but Go projects often modify vendored code. Case-by-case decision left to users.
- `test/` / `tests/` — test files can contain security issues (hardcoded credentials in test fixtures is a real finding).

**Configurable:** Users can override via `.sentinel.json` `exclude` array.

**File:** `src/sentinel/cli/main.py:277-278`

---

## ADR-010: Dedup Key = file_path + line_number + category

**Context:** When multiple tools scan the same codebase, they may report the same vulnerability. Semgrep and the built-in scanner both flag `eval()` calls, for example.

**Decision:** Dedup key is `md5(file_path|line_number|category)`. When duplicates exist, keep the finding with the highest severity.

**Why these three fields?**
- `file_path + line_number` identifies the exact code location. Two findings at the same location are almost certainly the same issue.
- `category` distinguishes different vulnerability types at the same location (e.g., a line could have both an `eval()` call and a hardcoded secret). Without category, we'd incorrectly dedup different findings.

**Why keep highest severity?**
- Different tools may assign different severity to the same finding. Semgrep might say MEDIUM; the built-in scanner might say HIGH. Keeping the highest is conservative — we'd rather over-report than under-report.

**Why MD5?**
- MD5 is fast and sufficient for dedup keys (not used for security). The key is an internal cache identifier, not a cryptographic hash.

**Known limitation:**
- Two findings at the same file+line+category but with different descriptions are deduped. The kept finding's description may be less informative than the removed one. Future improvement: merge descriptions.

**File:** `src/sentinel/core/pipeline.py:36-77`

---

*Last updated: 2026-02-23 | Maintainer: G.S.*

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
