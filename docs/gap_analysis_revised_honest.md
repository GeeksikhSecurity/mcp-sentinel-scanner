# Competitive Gap & Alignment Analysis (Revised — Honest Assessment)
## NIST test_code_eval × Promptfoo × PyRIT × MCP Sentinel Scanner

**Prepared for:** G.S. — SecurityLeader.ai / GeeksikhSecurity
**Date:** February 23, 2026
**Revision note:** This version incorporates the Sentinel Sustainability & 80/20 Assessment findings. Previous analysis overstated MCP Sentinel's shipping capabilities based on architectural docs rather than actual code. This revision reflects ground truth.

---

## Executive Summary

Four tools addressing different layers of the same problem: **"How do we know AI-connected systems are safe?"**

| Tool | Core Mission | Funding | MCP-Specific? |
|------|-------------|---------|---------------|
| **NIST test_code_eval** | Measure AI-generated test code quality | US Government | No |
| **Promptfoo** | LLM red teaming + vulnerability scanning | $18.4M Series A (Jul 2025) | Yes — dedicated MCP plugin, provider, security testing guide |
| **PyRIT** | AI red teaming automation framework | Microsoft (open source) | No native MCP support |
| **MCP Sentinel Scanner** | Source code SAST orchestrator (branded as MCP tool) | Independent | **No — scans source code of projects that happen to be MCP servers, not the MCP protocol itself** |

**The critical honest finding:** MCP Sentinel Scanner, despite the name, does not scan anything MCP-specific. It is a commodity SAST wrapper that orchestrates Semgrep, TruffleHog, npm audit, and custom regex patterns. Actual MCP protocol security tools (Invariant MCP-Scan, Proximity, Cisco MCP Scanner) address fundamentally different problems — tool poisoning, rug pulls, cross-origin escalation — that Sentinel does not touch.

**The strategic opportunity:** Pivot from commodity SAST orchestrator to actual MCP protocol security scanner (Option D), using NIST evaluation methodology as the quality framework and Promptfoo/PyRIT research as the dynamic testing layer.

---

## Ground Truth: What MCP Sentinel Actually Ships

Before comparing, we need an honest inventory of what Sentinel does today vs. what existing tools already do better.

| What Sentinel Ships | What Already Does It Better | Gap |
|---|---|---|
| 7 regex patterns (SQLi, cmd injection, etc.) | Semgrep: 2,500+ rules with AST-aware matching | Commodity |
| Entropy-based secret detection | TruffleHog: verified credential checks (validates against live APIs) | Commodity |
| Python-only intraprocedural taint analysis | Semgrep: interprocedural, multi-language taint | Commodity |
| React analyzer (3 patterns) | Semgrep React ruleset | Commodity |
| npm audit wrapper | npm audit directly | Commodity |
| FP filtering (1,043 lines, 4 overlapping systems) | Compensates for weakness of own regex; Semgrep already has low FP rates | Overhead |
| **CodeQL prompt-injection query (209 lines)** | **No direct equivalent — covers OpenAI/Anthropic/HuggingFace/LangChain sinks** | **Novel IP** |

**The 80/20 reality:** A shell script running `semgrep --config=auto . && trufflehog filesystem . && npm audit` achieves ~80% of Sentinel's findings in 5 minutes of setup. Custom `.semgrep.yml` rules get to ~95% in 2 hours.

**The one genuinely novel artifact:** The CodeQL prompt-injection query (209 lines) that detects unsafe data flows from user input to LLM API sinks across OpenAI, Anthropic, HuggingFace, and LangChain.

---

## The MCP Security Tool Landscape (Honest Map)

### Protocol-Level MCP Scanners (What Sentinel Is Not)

| Tool | What It Actually Scans | Approach |
|------|----------------------|----------|
| **Invariant MCP-Scan** | Tool poisoning, rug pulls, cross-origin escalation | Protocol-level analysis of MCP tool definitions at runtime |
| **Proximity** | MCP server security evaluation | NOVA rules engine for runtime security assessment |
| **Cisco MCP Scanner** | MCP server behavior | YARA rules + LLM-as-judge for behavioral analysis |
| **Promptfoo MCP Plugin** | Live MCP server responses under adversarial input | Dynamic red teaming — generates attacks, evaluates responses |

### Source-Level Scanners (Where Sentinel Currently Sits)

| Tool | What It Actually Scans | Approach |
|------|----------------------|----------|
| **Semgrep** | Source code patterns, taint flows, secrets | AST-aware, 2,500+ rules, multi-language |
| **TruffleHog** | Credentials in repos | Verified detection (validates against live APIs) |
| **CodeQL** | Deep semantic code analysis | GitHub-native, data flow analysis |
| **MCP Sentinel** | Source code of MCP server projects | Orchestrates the above tools + custom regex |

### Model/Prompt-Level Scanners (Adjacent Space)

| Tool | What It Actually Scans | Approach |
|------|----------------------|----------|
| **Promptfoo** | LLM application behavior under adversarial input | 50+ vulnerability types, YAML config, CI/CD |
| **PyRIT** | GenAI system risk under orchestrated attacks | Multi-modal, multi-turn, DuckDB memory |
| **Garak** | LLM vulnerabilities via probes | 100 attack vectors, 20K+ prompts per run |

**Key insight:** These are three distinct layers — protocol, source, and model. Sentinel sits in the source layer but brands itself as if it covers the protocol layer. The pivot (Option D) would move it to actually cover the protocol layer.

---

## Dimension-by-Dimension Comparison (Revised)

### 1. What They Actually Test

| Dimension | NIST test_code_eval | Promptfoo | PyRIT | MCP Sentinel (actual) | Invariant MCP-Scan |
|-----------|-------------------|-----------|-------|----------------------|-------------------|
| AI-generated code quality | ✅ Primary | ❌ | ❌ | ❌ | ❌ |
| LLM prompt/output safety | ❌ | ✅ Primary | ✅ Primary | ❌ | ❌ |
| MCP tool poisoning | ❌ | ✅ Plugin | ❌ | ❌ | ✅ Primary |
| MCP rug pulls | ❌ | ❌ | ❌ | ❌ | ✅ |
| MCP cross-origin escalation | ❌ | ❌ | ❌ | ❌ | ✅ |
| MCP server manifest analysis | ❌ | ✅ Provider | ❌ | ❌ | ✅ |
| General source code SAST | ❌ | ⚠️ Code scanning (new) | ❌ | ✅ (commodity) | ❌ |
| Secret/credential detection | ❌ | ❌ | ❌ | ✅ (commodity) | ❌ |
| Prompt injection to LLM sinks | ❌ | ✅ Dynamic | ❌ | ⚠️ CodeQL query only | ❌ |
| Supply chain (npm audit) | ❌ | ❌ | ❌ | ✅ (wrapper) | ❌ |
| Adversarial input generation | ❌ | ✅ AI-driven | ✅ Core | ❌ | ❌ |
| Multi-turn attack conversations | ❌ | ✅ | ✅ | ❌ | ❌ |
| Multi-modal (image/audio) | ❌ | ⚠️ Limited | ✅ Full | ❌ | ❌ |

### 2. Architecture & Methodology

| Dimension | NIST test_code_eval | Promptfoo | PyRIT | MCP Sentinel (actual) |
|-----------|-------------------|-----------|-------|----------------------|
| **Approach** | Evaluate → Score → Report | Generate attacks → Eval → Report | Orchestrate → Convert → Score | Run Semgrep + TruffleHog + regex → Dedup → Report |
| **Config format** | .ini + env vars | YAML (declarative) | Python notebooks | JSON config |
| **Execution** | CLI scripts | CLI + Web UI + CI/CD | Jupyter notebooks | CLI + Docker |
| **Known-good baselines** | ✅ Code bank | ❌ | ❌ | ❌ |
| **Validation step** | ✅ Separate validator | ⚠️ Config validation | ❌ | ❌ |
| **Scoring** | Coverage %, error detection | Pass/fail + ASR | Configurable scorers | Severity levels |
| **CI/CD** | ❌ Manual | ✅ Native | ⚠️ Manual | ✅ GitHub Actions |
| **Framework mappings** | NIST GenAI | OWASP, NIST RMF, MITRE ATLAS, EU AI Act | OWASP, MITRE ATLAS | Custom A1-A12 (docs only, not enforced in code) |
| **Unique contribution** | Adversarial baseline methodology | Adaptive AI attack generation | Multi-modal orchestration | CodeQL prompt-injection query |

### 3. MCP Security Testing (The Real Comparison)

| MCP Capability | Promptfoo | MCP Sentinel (actual) | Invariant MCP-Scan |
|---------------|-----------|----------------------|-------------------|
| **Tool poisoning detection** | ✅ "Evil MCP server" test pattern | ❌ Not implemented | ✅ Primary capability |
| **Hidden instruction detection** | ✅ Tests user-visible vs. model-visible disconnect | ❌ Not implemented | ✅ |
| **Multi-server composition attacks** | ✅ Multi-server test configs | ❌ Not implemented | ⚠️ Partial |
| **Data exfiltration via tools** | ✅ Side-channel tests | ❌ Not implemented | ✅ |
| **Rug pull detection** | ❌ | ❌ | ✅ |
| **PII leakage through tools** | ✅ Dedicated PII plugin | ❌ | ❌ |
| **SQL injection via tool params** | ✅ SQL injection plugin | ⚠️ Regex pattern only | ❌ |
| **BOLA/BFLA** | ✅ Dedicated plugins | ❌ | ❌ |
| **Approach** | **Dynamic** — live server testing | **Static** — source code patterns | **Protocol** — tool definition analysis |
| **What it requires** | Running MCP server endpoint | Source code / config files | MCP server connection |
| **Compliance mapping** | OWASP LLM Top 10, NIST AI RMF | A1-A12 (aspirational docs only) | Custom |

---

## What NIST's Methodology Adds (Framework-Agnostic Value)

These patterns apply regardless of which scanner you use. None of the tools in this comparison have adopted them.

### 1. Adversarial Baseline Testing (Code Bank Pattern)
NIST tests against known-correct AND known-incorrect implementations. Applied to MCP security:
- `known_safe/` — Vetted MCP server configs that should pass all scans
- `known_vuln_single/` — Servers with exactly one planted vulnerability
- `known_vuln_chain/` — Vulnerabilities that only manifest through tool composition

**Value:** Proves detection rates with evidence rather than assertion. Directly addresses the "95% detection rate" claim that has no backing test corpus.

### 2. Validate-Then-Evaluate Pipeline
NIST's `validate_submission.py` catches format/schema issues before any evaluation. Applied to scanning:
- Validate MCP server manifest schema before protocol scanning
- Validate scan config before running expensive tools
- Reject malformed inputs early

### 3. Dual-Mode Evaluation (Fixed vs. Custom)
NIST evaluates standardized conditions separately from custom tuning. Applied to scanner rules:
- **Fixed rules:** Standard detection patterns (baseline capability)
- **Custom rules:** Organization-specific patterns (tuned capability)
- Score both separately to show out-of-box vs. tuned performance

### 4. Statistical Confidence (via Aegis/active-evaluation)
Confidence intervals on detection rates. No security scanner currently provides this.

---

## The B+C → D Pivot Strategy

### Current State: B+C (Immediate Value — In Progress)

Based on the sustainability assessment, the team is already executing:

**Option B:** Custom Semgrep rules (`.semgrep.yml`) + TruffleHog
- Ports the 7 regex patterns as proper AST-aware Semgrep rules
- ~95% of Sentinel's current findings, better quality
- 2 hours of effort

**Option C:** Invariant MCP-Scan integration for actual protocol scanning
- Covers tool poisoning, rug pulls, cross-origin escalation
- Addresses the MCP-specific gap Sentinel was supposed to fill
- 1 hour setup

**Combined B+C deliverables (shipped):**
- `.semgrep.yml` — 13 custom Semgrep rules covering MCP/AI security patterns (prompt leakage, tool description injection, unsanitized tool output, unsafe prompt concatenation, eval of LLM output), hardcoded secrets in React/Next.js env vars, npm lifecycle script injection, localStorage sensitive data, and YAML unsafe load
- `sentinel-scan.sh` — orchestration script that runs Semgrep (with custom rules) + TruffleHog + npm audit + MCP-Scan with severity counting, JSON output, and exit codes

### Target State: Option D (The Pivot)

Transform from "generic SAST orchestrator branded as MCP tool" to "actual MCP protocol security scanner with NIST-aligned evaluation."

```
MCP Sentinel v3 — Pivoted Architecture
├── Protocol Layer (NEW — the actual MCP gap)
│   ├── Invariant MCP-Scan integration (tool poisoning, rug pulls)
│   ├── Custom protocol checks (inspired by Proximity NOVA rules)
│   ├── Tool description analysis (hidden instruction detection)
│   └── Cross-server composition risk scoring
│
├── Source Layer (B+C — delegate to proven tools)
│   ├── Semgrep with custom .semgrep.yml (ported from Sentinel regex)
│   ├── TruffleHog for verified secret detection
│   └── CodeQL prompt-injection query (the one novel artifact)
│
├── Evaluation Layer (NEW — from NIST analysis)
│   ├── known_safe/ + known_vuln/ test corpus
│   ├── validate_server.py (NIST-style pre-scan validation)
│   ├── evaluate_scanner.py (score against known vulns)
│   └── A1-A12 → OWASP LLM Top 10 mapping table
│
└── Dynamic Layer (FUTURE — integration point)
    ├── Promptfoo as upstream adversarial input generator
    └── PyRIT orchestration for multi-turn protocol testing
```

### What Gets Killed (Phases 3-8 from Original Roadmap)

| Phase | What It Was | Why Kill It |
|-------|-----------|-------------|
| Phase 3 | More SAST adapters | Semgrep already does this better |
| Phase 4 | Compliance engine (PCI/SOC2/HIPAA) | Requires domain expertise; not credible without professional validation |
| Phase 5 | Enterprise dashboard | Premature before protocol scanning works |
| Phase 6 | ML-based detection | No training data; academic exercise |
| Phase 7 | Multi-language expansion | Semgrep already covers this |
| Phase 8 | SaaS platform | Cart before horse |

### What Happens to Existing Code (5,682 lines in `src/sentinel/`)

| Component | Lines | Decision | Rationale |
|-----------|-------|----------|-----------|
| `core/scanner.py` (7 regex patterns) | 622 | **Archive** | Superseded by `.semgrep.yml` custom rules |
| `analyzers/react.py` (3 patterns) | 98 | **Archive** | Superseded by Semgrep React ruleset |
| `analyzers/npm.py` (audit wrapper) | 150 | **Archive** | Superseded by `sentinel-scan.sh` npm audit call |
| `queries/ai-security/prompt-injection.ql` | 209 | **Preserve** | The one novel artifact — promote to top-level |
| FP filtering (4 overlapping systems) | 1,043 | **Delete** | Compensated for weakness of own regex; Semgrep doesn't need it |
| Plugin registry + adapters | ~2,500 | **Archive** | Phase 1-2 restructure is preserved in git history |
| Tests | ~1,060 | **Archive** | Tests for archived code; new tests for D-phase |

**Action:** Move `src/sentinel/` to `archive/sentinel-v2/` and promote `prompt-injection.ql` to `queries/`. The B+C deliverables (`.semgrep.yml` + `sentinel-scan.sh`) replace the Python codebase at the repo root.

### Linear Task Mapping (SAY-49 through SAY-57)

The "kill phases 3-8" table above maps to these Linear issues which should be moved to Cancelled:
- SAY-49 through SAY-53: Original Phase 3-5 tasks (multi-language, compliance, dashboard)
- SAY-54 through SAY-57: Original Phase 6-8 tasks (ML detection, SaaS platform)

New D-phase issues should replace them (D1-D5 from roadmap below).

### What Gets Built (Option D Roadmap)

| Phase | What | Effort | Value |
|-------|------|--------|-------|
| D1 | MCP-Scan integration + `sentinel-scan.sh` + `.semgrep.yml` | Done (B+C) | Immediate coverage |
| D2 | Custom MCP protocol checks: (a) tool description hidden instruction detection via embedding similarity, (b) cross-server permission escalation graph, (c) resource URI validation against allowlists, (d) sampling request boundary enforcement | 1-2 weeks | Unique value — nobody else does this as a standalone scanner |
| D3 | NIST-style test corpus (`known_safe/`, `known_vuln/`) | 1 week | Proves detection rates; differentiator |
| D4 | A1-A12 → OWASP mapping + validate-then-evaluate pipeline | 3 days | Enterprise credibility |
| D5 | Promptfoo integration (adversarial input → protocol scanner) | 2 weeks | Closes dynamic testing gap |

---

## Competitive Positioning (Honest Version)

### What to Stop Claiming
- "95% detection rate" — No test corpus backs this up
- "Multi-layer analysis pipeline with 4 engines" — Aspirational architecture doc, not shipping code
- "Semantic incongruity detection" — Not implemented
- "Orchestration analysis" — Not implemented

### What to Start Claiming (Post-Pivot)
- "Bridges static source analysis and MCP protocol security — the only tool that does both"
- "NIST-aligned evaluation methodology with adversarial baseline testing"
- "Purpose-built for the MCP attack surface defined by Zhao et al. (2025)"
- "Integrates with Promptfoo for dynamic testing and Semgrep/TruffleHog for source scanning"

### The Honest Narrative for SecurityLeader.ai

> "I built a scanner, shipped it, then did the hard thing: I honestly assessed it against the competition and discovered it was a commodity wrapper. So I pivoted. Here's what I learned about the difference between scanning source code and scanning protocols, why NIST's evaluation methodology matters more than detection claims, and how the MCP security landscape actually works."

This story is worth 10x more than "my tool detects 95% of threats" because:
1. It demonstrates the intellectual honesty CISOs respect
2. It shows you understand the problem deeply enough to know what doesn't work
3. It aligns with Byron Wien's principle you follow: "The hard way is always the right way"
4. It's a content piece nobody else in the MCP security space will write

### Positioning vs. Each Competitor

**vs. Promptfoo:** "They do dynamic MCP testing — send adversarial inputs to live servers. We do protocol-level analysis of tool definitions and source-level analysis of server code. Promptfoo asks 'Can I trick your MCP server right now?' We ask 'Is this MCP server trustworthy before you ever connect to it?' Pre-deployment vs. post-deployment security. You need both."

**vs. PyRIT:** "PyRIT is model-focused, not MCP-focused. It's excellent for red teaming LLMs but has no MCP protocol awareness. Different layer of the stack entirely."

**vs. Invariant MCP-Scan:** "We integrate MCP-Scan as our protocol scanning engine and add source-level analysis + NIST-aligned evaluation on top. We're not competing — we're composing."

**vs. NIST:** "NIST provides the evaluation methodology. We provide the security scanner that uses it. They measure quality; we enforce it."

---

## Revised Action Items

### Immediate (This Sprint — Aligns with Claude Code Work)

| # | Action | Status | Owner |
|---|--------|--------|-------|
| 1 | Port Sentinel regex → custom `.semgrep.yml` rules | In Progress (Claude Code) | Dev |
| 2 | Create `sentinel-lite.sh` (Semgrep + TruffleHog + MCP-Scan) | In Progress (Claude Code) | Dev |
| 3 | Push B+C to repo, update README honestly | In Progress (Claude Code) | Dev |
| 4 | Update Linear tasks for Option D roadmap | Pending | Claude Code |

### Next Sprint (Option D Foundation)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 5 | Create `known_safe/` + `known_vuln/` MCP server test corpus | 3 days | Proves detection; NIST alignment |
| 6 | A1-A12 → OWASP LLM Top 10 mapping table (markdown) | 1 day | Enterprise credibility |
| 7 | Custom MCP protocol checks (tool description analysis) | 1 week | Unique value |
| 8 | `validate_server.py` — NIST-style pre-scan validation | 2 days | Quality gate |

### Month 2 (Integration)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 9 | Promptfoo integration as upstream adversarial generator | 2 weeks | Closes dynamic gap |
| 10 | `evaluate_scanner.py` — score against known vuln corpus | 1 week | Statistical backing for claims |
| 11 | SARIF output for GitHub Advanced Security integration | 2 days | Enterprise pipeline |

### Content (Aligned with SAY-64 LinkedIn Series)

| # | Action | Aligns With |
|---|--------|-------------|
| 12 | Revise Post 4 (SAY-68) to tell the pivot story honestly | "From NIST to Your Scanner" |
| 13 | Write "The Honest CISO's Guide to MCP Security Scanning" | New standalone piece |
| 14 | Publish A1-A12 → OWASP mapping as open resource | SAY-69 ecosystem piece |

---

## Appendix: Key Links

**MCP Protocol Scanners:**
- Invariant MCP-Scan: https://github.com/invariantlabs-ai/mcp-scan
- Cisco MCP Scanner: https://github.com/cisco-ai-defense/mcp-scanner
- Proximity: https://github.com/nicholasgriffintn/proximity (MCP server security evaluation)

**AI Red Teaming Tools:**
- Promptfoo: https://www.promptfoo.dev/
- Promptfoo MCP Security Testing: https://www.promptfoo.dev/docs/red-team/mcp-security-testing/
- Promptfoo MCP Plugin: https://www.promptfoo.dev/docs/red-team/plugins/mcp/
- Promptfoo MCP Provider: https://www.promptfoo.dev/docs/providers/mcp/
- PyRIT: https://github.com/Azure/PyRIT
- PyRIT Paper: https://arxiv.org/html/2410.02828v1

**NIST Evaluation:**
- test_code_eval: https://github.com/usnistgov/test_code_eval
- GenAI Code Challenge: https://ai-challenges.nist.gov/code
- CAISI Cyber Evals: https://github.com/usnistgov/caisi-cyber-evals
- Active Evaluation (Aegis): https://github.com/usnistgov/active-evaluation

**Research:**
- Zhao et al. (2025): "When MCP Servers Attack" — arXiv:2509.24272v1
- MCP Specification: https://modelcontextprotocol.io/specification/2025-11-25

**Sentinel (Current):**
- Repo: https://github.com/GeeksikhSecurity/mcp-sentinel-scanner
- Sustainability Assessment: (internal — the document that triggered this revision)
