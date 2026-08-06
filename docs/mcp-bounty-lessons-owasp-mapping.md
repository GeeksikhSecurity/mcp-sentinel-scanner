# MCP Bug-Bounty Lessons → OWASP/CWE Mapping & Semgrep Rules (2026-08)

Source: mcp-huntr sweep (`MCP-SCAN-LESSONS.md`, external repo,
`/Volumes/2TBSSD/BugBounty_PenTesting/Targets/mcp-huntr/`), 9 archetypes
ranked by actual disclosure yield. This doc maps those archetypes to OWASP/CWE
standards and records which archetypes now have a mechanical check in this
repo vs. which are still prose-only.

Per this project's own rule: **a prose lesson is not prevention until it's a
check that fails CI.** The table below is the audit of that gap, not a
restatement of the lessons doc.

## Archetype → standard → mechanical-check status

| # | Archetype | OWASP LLM Top 10 (2025) | OWASP API Top 10 (2023) | CWE | Check in this repo |
|---|---|---|---|---|---|
| 1 | Bypass-of-fix (fix quality, not popularity) | LLM06: Excessive Agency | — | varies | **Prose only** — inherently requires reading the fix's diff, not a static pattern. No mechanical check proposed. |
| 2 | Guard-asymmetry (tools vs. resources/prompts) | LLM06: Excessive Agency | API3: Broken Object Property Level Authorization | CWE-285 | **Not implemented.** This is the archetype the lessons doc explicitly flags as the class *generic scanners miss* (tool-only coverage) — this scanner is tool-only today. Biggest real gap; needs an MCP-protocol-aware analyzer (SDK request-handler mapping), not a regex rule. |
| 3 | Incomplete denylist/blocklist | LLM05: Improper Output Handling | — | CWE-20 | **Not implemented** as a dedicated rule; partially subsumed by existing `mcp-unvalidated-input` regex (`configs/security_rules.json`), which flags missing validation generically but doesn't specifically detect denylist-vs-allowlist shape. |
| 4 | Shell-string exec vs. argv | LLM01: Prompt Injection | — | CWE-78 | **Implemented.** `.semgrep.yml`: `mcp-nodejs-shell-string-interpolation`, `mcp-python-shell-true-interpolation`. Also fixed the Python-side AST/regex discriminator in [`src/sentinel/analyzers/multi_language.py`](../src/sentinel/analyzers/multi_language.py) and its legacy duplicate — see commit history. |
| 5 | Prefix/`startsWith` allowlist | LLM06: Excessive Agency | API8: Security Misconfiguration | CWE-918 (as URL) / CWE-863 (as authz) | **Implemented** (partial). `.semgrep.yml`: `mcp-insecure-url-allowlist` (URL/domain case). Path-prefix case covered by archetype #9's rule below. |
| 6 | Export/attachment side-channel | LLM02: Sensitive Information Disclosure | API1: Broken Object Level Authorization | CWE-284 | **Prose only.** Requires knowing which tool is the "hardened" CRUD path vs. the secondary export/output_path tool — app-specific, not a generic pattern. No rule proposed. |
| 7 | Access-control / BOLA / fail-open authz / OAuth leak | LLM02: Sensitive Information Disclosure | API1: Broken Object Level Authorization | CWE-862 / CWE-863 | **Prose only.** Only applies to remote/hosted multi-user MCPs; requires session/tenant-boundary modeling this scanner doesn't do. |
| 8 | SSRF-filter bypass (mapped IPv6, DNS rebind) | LLM06: Excessive Agency | API8: Security Misconfiguration | CWE-918 | **Not implemented** as its own rule. `mcp-insecure-url-allowlist` catches the prefix-allowlist *variant* of this archetype but not the IPv4-mapped-IPv6 / DNS-rebind / redirect-revalidation cases, which need real network-call analysis, not source pattern-matching. |
| 9 | Symlink/realpath sandbox escape | LLM06: Excessive Agency | — | CWE-22 | **Implemented.** `.semgrep.yml`: `mcp-lexical-path-containment-bypass`. |

**Net: 3 of 9 archetypes have a mechanical check (4, 5-partial, 9); archetype
2 is the highest-priority gap** — it's the one the source doc calls out by
name as invisible to tool-only scanners, which describes this scanner.

## OWASP CI/CD Top 10 (context, not yet actionable here)

For MCPs embedded in build/agent pipelines (e.g., a `git`/`docker` tool
invoked by a CI-resident LLM agent):

| CI/CD Risk | Archetype | Why |
|---|---|---|
| CICD-SEC-04: Poisoned Pipeline Execution | 4 (shell-string exec) | A command-injectable `git`/`docker` MCP tool run inside a CI job lets an attacker poison the runner's execution environment via the same sink `mcp-nodejs-shell-string-interpolation`/`mcp-python-shell-true-interpolation` catch. |
| CICD-SEC-02: Inadequate Identity & Access Mgmt | 7 (BOLA/authz) | A cloud-hosted MCP without tenant isolation lets an attacker pivot from their own pipeline into another org's. |

No new check follows from this section — it's the same archetype-4 and
archetype-7 rows above, just reframed for a CI/CD-hosted MCP. Recorded here
so the mapping doesn't need re-deriving next time a client conversation needs
the CI/CD framing.

## Semgrep rules added — validation notes

All 4 new rules in `.semgrep.yml` were run against dedicated true-positive/
true-negative fixtures (`tests/semgrep/fixtures/`, exercised by
`tests/test_semgrep_mcp_bounty_rules.py`) before being accepted, per this
project's rule that an externally-proposed finding/pattern is a hypothesis
until confirmed against real code. Two of the four *as originally proposed*
contained non-functional patterns that would never have matched real code:

- `mcp-nodejs-shell-string-interpolation` had a `pattern-not: exec("...", ...)`
  intended to exclude static-string `exec()` calls. It's a no-op: a bare
  `"..."` string pattern in Semgrep matches the literal three-character
  string `"..."`, not "any string" — so it never excluded anything. Removed;
  the `pattern-either` already only matches interpolated forms, so no
  functional loss.
- `mcp-insecure-url-allowlist`'s `startsWith("https://...")` sub-pattern only
  matched the literal string `"https://..."` — real code never contains that
  exact string, so this branch would never have fired. Fixed to
  `startsWith("...")` (ellipsis as the whole string argument, which *is* the
  documented Semgrep syntax for "any string literal").

Confirmed via `semgrep scan --config .semgrep.yml --validate` (0 config
errors, 15 rules) and a full scan of `src/` (0 findings — no self-flagging).
`semgrep --test` itself crashes on this repo's path layout (semgrep 1.172.0,
`IndexError` in `relatively_eq`); the pytest harness in
`tests/test_semgrep_mcp_bounty_rules.py` reads the same `# ruleid:`/`# ok:`
markers a normal semgrep test fixture would use and drives
`semgrep scan --json` directly instead, so the regression coverage doesn't
depend on the broken command.
