# Corpus Methodology and Real-World MCP Scan Findings

**Author:** Gurvinder Singh | [SecurityLeader.ai](https://securityleader.ai)
**Audience:** Security researchers, SANS/BSIDES whitepaper authors, SecurityLeader.ai readers
**Use:** SecurityLeader.ai blog; whitepaper "Methods" and "Results" sections
**Date:** February 2026

---

## Abstract

We describe a tiered repo-corpus methodology for benchmarking and researching MCP security at scale, and summarize results from scanning official Model Context Protocol SDKs and popular MCP server repositories. Findings include command injection, hardcoded secrets, npm vulnerabilities, and semantic issues; we also discuss false-positive reduction so that numbers are suitable for publication and operational use.

---

## 1. Corpus Design

To make results reproducible and useful for whitepapers and conferences, we use a **manifest-driven corpus** with three tiers:

| Tier    | Purpose              | Repos | How |
|---------|----------------------|-------|-----|
| **Smoke** | Fast regression      | 2     | Local fixtures (minimal MCP samples). |
| **Full**  | Extended coverage    | 6     | Local clones of MCP repos (e.g., FastMCP, mcp-python, mcp-servers, mcp-use, mcp-quickstart). |
| **Nightly** | Upstream snapshot | 3     | Remote GitHub (modelcontextprotocol/servers, python-sdk, typescript-sdk); clone on demand, optional cache. |

- **Smoke** runs in seconds and validates the scanner on every change.
- **Full** exercises a broad set of real codebases when local clones are available.
- **Nightly** tracks upstream MCP repos for trend analysis and research; outputs (JSON, SARIF) can be archived for papers and dashboards.

All tiers support configurable exclusions (e.g., `node_modules`, `dist`, `build`, `.git`) and per-repo timeouts. The design is documented in the project’s [Implementation Results and Next Steps](../IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md) and can be cited in a whitepaper “Methods” section.

---

## 2. Detection Categories (What We Measure)

The scanner reports findings in categories aligned with common vulnerabilities and with the MCP attack taxonomy (e.g., Zhao et al.):

- **command_injection** — Unsafe shell execution (e.g., `subprocess.run(..., shell=True)` with user-controlled input).
- **hardcoded_secret** — Quoted secrets (API keys, tokens, passwords) detected by pattern + entropy; filtered by placeholder and identifier heuristics to reduce false positives.
- **sql_injection** — String concatenation in SQL-like patterns.
- **dangerous_function** — Use of `eval`, `exec`, `subprocess.Popen`, and similar.
- **insecure_deserialization** — e.g., `pickle.loads`, unsafe `yaml.load`.
- **weak_crypto** — e.g., MD5/SHA1 in security-sensitive contexts.
- **path_traversal** — Relative path patterns that may escape intended directories.
- **npm_vulnerability** — Findings from npm audit (when the unified pipeline is used).
- **Semantic / advanced** — Auth-bypass patterns, crypto misuse, complexity metrics (from the advanced detection module).

Severity is mapped (CRITICAL/HIGH/MEDIUM/LOW), and an **Attack Success Rate (ASR)–style score** aggregates severity so reports are suitable for risk summaries and research metrics.

---

## 3. False-Positive Reduction (Research Validity)

Raw pattern and AST hits would be too noisy for CI and for publishable research. We apply:

- **Context-based filtering:** Test files, common test paths, and `nosec`-style markers reduce findings in test code when appropriate.
- **Secret-specific rules:** Only quoted values matching explicit secret-like keys (e.g., `client_secret=`, `api_key=`) are reported; variable names and identifiers are suppressed.
- **Placeholder detection:** Example values (e.g., `your-client-secret`) are filtered so that real secrets are highlighted.

Default behavior is tuned so that **corpus runs produce actionable findings** while keeping regression tests stable (via a dedicated test config that can disable FP reduction where assertions require it). For whitepapers, we recommend reporting both “raw” and “after FP reduction” counts if space allows, or clearly stating that reported numbers are post-FP-reduction.

---

## 4. Example Results (Nightly Corpus)

Runs over the **nightly** tier (official MCP servers and Python/TypeScript SDKs) yield, for example:

- **Files scanned:** Hundreds per repo (e.g., 200+ for servers, 500+ for python-sdk).
- **Findings:** Mix of HIGH/MEDIUM severity (e.g., command injection, hardcoded-secret patterns, npm advisories).
- **ASR score:** Computed per run for risk prioritization.
- **Outputs:** JSON and SARIF per repo, plus a corpus-level summary, suitable for inclusion in appendices or supplementary material.

Concrete numbers and breakdowns by category/severity can be taken from the latest `reports/repo_corpus_nightly/` (or equivalent) and updated in the whitepaper at publication time.

---

## 5. Regression Fixtures (Reproducibility)

To lock in behavior and support peer review, we maintain **scanner regression fixtures** that encode expected outcomes:

- **command_injection_fixture.py** — `subprocess.run(..., shell=True)` with variable input → must be reported as command_injection.
- **hardcoded_secret_fixture.py** — Quoted `CLIENT_SECRET` value → must be reported as hardcoded_secret.
- **fp_negative_fixture.py** — Variable names only (e.g., `resource_key`, `access_token`) → must *not* be reported as hardcoded_secret.

These fixtures are run in CI and can be referenced in a whitepaper “Reproducibility” or “Validation” subsection.

---

## 6. How to Cite This in a Whitepaper or Talk

Suggested wording for a **Methods** section:

> We evaluated MCP security using a tiered corpus of official and community MCP repositories. Scans were performed with the MCP Sentinel Scanner (v1.5), which applies pattern-based and AST-based static analysis plus false-positive reduction. The corpus comprises smoke (local fixtures), full (local MCP repos), and nightly (upstream GitHub) tiers; results are exported in JSON and SARIF for reproducibility.

For **Results**, use the latest corpus summary (e.g., `corpus_summary.json`) and report:

- Number of repositories and files scanned.
- Counts by finding category and severity.
- ASR (or equivalent) aggregate metric.
- Brief note on false-positive handling (e.g., “findings reported after context-aware and secret-specific filtering”).

---

## 7. Takeaways for Researchers and Practitioners

- A **manifest-driven, tiered corpus** makes MCP security scanning reproducible and suitable for papers and conferences.
- **Explicit FP reduction** keeps reported findings actionable and defensible in peer review.
- **Regression fixtures** and CI integration support repeatability and future extensions (e.g., OWASP ASVS/AISVS alignment).
- Sharing methodology and results (e.g., via SecurityLeader.ai, SANS, BSIDES) helps the community adopt consistent baselines and improve MCP security across the ecosystem.

---

## References

- Zhao, X., Ortega, L., Chen, Q., & Musa, R. (2025). *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation*. arXiv:2509.24272.
- MCP Sentinel Scanner – [Implementation Results and Next Steps](../IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md)
- Corpus manifest and runner: `configs/repo_corpus.json`, `scripts/run_repo_corpus.py`

---

> **Disclaimer:** The views, opinions, and research presented on [SecurityLeader.ai](https://securityleader.ai) are solely those of the author, Gurvinder Singh, in a personal capacity. They do not represent or reflect the views, positions, or policies of the American Psychological Association (APA), APA.org, or any other affiliated organization or employer. All content is provided for educational and informational purposes only.
