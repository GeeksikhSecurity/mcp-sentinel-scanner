# Review: Unified AI Security Framework Engineering (Notes)

**Source:** `unified-ai-security-framework-engineering.docx` (Agentic_AI_Notes)  
**Reviewed:** March 2026  
**Context:** mcp-sentinel-scanner repo — this playbook names the Sentinel Scanner as a Phase 2 tool in the NIST/MAESTRO toolchain.

---

## 1. What the Document Is

An **engineering adoption playbook** that:

- **Bridges** NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE) and GenAI Profile 600-1 to **concrete tooling and CI steps**.
- **Maps** each RMF function to:
  - Agent manifest fields (MAESTRO-style YAML: `agent_metadata`, `integrity_definition`, `operational_security`, `risk_mitigation`).
  - Specific checks and tools (manifest validator, MCP config scan, SAST, secrets, agent/skills scan).
- **Provides** a drop-in GitHub Actions workflow, a Python manifest validator script, repo layout, pre-commit hooks, and a 30-minute onboarding checklist.

**Scope:** MCP configs, agent manifest as policy-as-code, app source (multi-language SAST), secrets, and agent skills/plugin supply chain (Cursor, Claude Code, Windsurf).

---

## 2. Strengths

| Aspect | Why it works |
|--------|----------------|
| **No new GRC process** | Tools and CI do the work; NIST is satisfied via annotated pipeline steps and manifest checks. |
| **RMF → manifest → tool** | Clear table: NIST function → outcome → manifest field → implementation note. Good for audits and onboarding. |
| **SARIF-first** | All scanners produce or feed SARIF; one place (GitHub Code Scanning) for results. |
| **Single workflow** | One `ai-security.yml` with GOVERN → MAP → MEASURE → MANAGE ordering; copy-paste plus env tweaks. |
| **Validator is extensible** | `validate_manifest.py` is one function per NIST area; adding a check = adding a block. |
| **Checklist** | 30-min quick-start with GOVERN/MAP/MEASURE/MANAGE items is actionable for new agent projects. |

---

## 3. Gaps and Considerations

| Gap | Suggestion |
|-----|------------|
| **Helixar Sentinel vs MCP Sentinel** | Workflow uses `Helixar-AI/sentinel` (config + probe + container). The doc also names “Sayva Inc. MCP Sentinel Scanner” for Semgrep + TruffleHog. Clarify: use Helixar for full-stack MCP + container, and/or use this repo as the unified SAST/secrets wrapper; document when to use which. |
| **Manifest schema** | Playbook references `manifests/schema/agent-manifest.schema.json` (Sayva internal). This repo doesn’t include it. Either add a minimal schema and validator here, or link to the canonical source. |
| **validate_manifest.py location** | Script is specified as `scripts/validate_manifest.py` in a generic “your-agent-project”. For adoption, either add it to this repo under `scripts/` or publish it as a separate reusable package and reference it from the playbook. |
| **OWASP Agentic Top 10** | Mentioned in the title but not mapped in the table (e.g. which manifest field or check addresses which OWASP Agentic risk). Adding a one-page mapping would strengthen the “MAP” story. |
| **GenAI Profile 2.5 / 4.1 / 1.7** | MEASURE 2.5 (behavioral drift), MANAGE 4.1 (real-time monitoring), GOVERN 1.7 (incident disclosure) are called out but not tied to concrete pipeline steps or manifest fields. Worth one sentence each in the workflow and validator sections. |

---

## 4. Direct Connection to This Repo (mcp-sentinel-scanner)

The playbook explicitly names:

- **“Sayva Inc. MCP Sentinel Scanner (Phase 2): SemgrepAdapter + TruffleHogAdapter + BaseAdapter integration. Validated against 4 public MCP repositories. 95% detection rate. 1,400+ files/second.”**
- **“Use the Sentinel Scanner wrapper in place of raw CLI for unified reporting.”**

So this repo **is** the unified SAST/secrets wrapper in the framework. The table rows for “Semgrep (SemgrepAdapter)” and “TruffleHog (TruffleHogAdapter)” are implemented here.

**Actionable links:**

| Playbook element | In this repo |
|------------------|---------------|
| SemgrepAdapter + TruffleHogAdapter | `src/adapters/semgrep.py`, `src/adapters/trufflehog.py` (and `src/sentinel/adapters/`) |
| SARIF output | `src/reporters/sarif_reporter.py`, CLI `--format sarif` |
| CI usage | Document in README or docs: `sentinel scan --config … --format sarif` and optional `--fail-on` (if supported) |
| validate_manifest.py | Not present; add under `scripts/` or point to external repo |
| ai-security.yml | Not present; add as example in `docs/` or `.github/workflows/` (example) |

---

## 5. Recommendations

1. **Add a “Framework alignment” section** to README or `docs/`: state that this scanner is the NIST/MAESTRO SAST+secrets component from the Unified AI Security Framework playbook; link to the playbook (or a stable URL) and list which RMF functions it supports (MAP + MEASURE + MANAGE in the table’s terms).
2. **Optionally add `scripts/validate_manifest.py`** from the playbook (or a slim variant) so agent projects can clone one repo and get both scanner and manifest validation; keep REQUIRED_TOP / REQUIRED_INTEGRITY / DISALLOWED_PATTERNS in sync with the doc.
3. **Add an example workflow** (e.g. `docs/examples/ai-security.yml` or `.github/workflows/ai-security-example.yml`) that uses this scanner for the “Sentinel Scan” or “SAST + Secrets” steps and shows NIST step comments.
4. **Clarify Helixar vs this scanner** in the playbook or in a short doc: “Use Helixar Sentinel for full MCP config + probe + container scan; use MCP Sentinel Scanner for unified Semgrep + TruffleHog + custom rules and single SARIF report.”

---

## 6. Summary

The document is a **strong engineering playbook**: it turns NIST AI RMF and GenAI Profile into concrete tools, one workflow, one validator, and a checklist. It already positions the MCP Sentinel Scanner as the Phase 2 SAST/secrets engine. Making the connection explicit in this repo (README + optional validator + example workflow) will help adopters run the playbook end-to-end and keep the scanner at the center of the “unified reporting” story.
