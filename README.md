# MCP Sentinel Scanner

Security scanning for MCP server projects. Orchestrates proven tools with custom AI/MCP-specific rules.

## What This Does

Runs four security tools against your codebase with a single command:

| Tool | What It Checks | Installed Via |
|------|---------------|---------------|
| **Semgrep** + custom rules | SAST + MCP/AI-specific patterns | `pip install semgrep` |
| **TruffleHog** | Verified secret detection | `brew install trufflehog` |
| **npm audit** | Dependency vulnerabilities | Comes with Node.js |
| **mcp-scan** | MCP protocol security (tool poisoning, rug pulls) | `pip install mcp-scan` |

The custom `.semgrep.yml` adds 13 rules not in Semgrep's default ruleset:
- MCP prompt leakage, tool description injection, unsanitized tool output
- Unsafe prompt concatenation (Python + JS), eval of LLM output
- Hardcoded secrets in `REACT_APP_` / `NEXT_PUBLIC_` env vars
- npm lifecycle script injection, localStorage sensitive data, YAML unsafe load

## Quick Start

```bash
# Clone
git clone https://github.com/GeeksikhSecurity/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner

# Run against a target directory
./sentinel-scan.sh /path/to/your/mcp-server

# JSON output
./sentinel-scan.sh /path/to/code --json

# With MCP server config for protocol scanning
./sentinel-scan.sh /path/to/code --mcp-config ~/.cursor/mcp.json
```

The script gracefully skips any tool that isn't installed. At minimum, install Semgrep or TruffleHog.

## What's in This Repo

```
.semgrep.yml          # 13 custom Semgrep rules (MCP/AI security)
sentinel-scan.sh      # Orchestration script
queries/              # CodeQL prompt-injection query (novel)
docs/                 # Analysis, architecture, competitive research
tests/                # Test fixtures and regression cases
src/sentinel/         # Original Python scanner (archived — superseded by B+C tools above)
```

### The One Novel Artifact

`queries/ai-security/prompt-injection.ql` — A CodeQL taint-tracking query (209 lines) that detects unsafe data flows from user input to LLM API sinks across OpenAI, Anthropic, HuggingFace, and LangChain. No direct equivalent exists in public CodeQL or Semgrep rule sets.

## Output

Terminal output with severity summary:

```
Sentinel Scan — Tool Check
─────────────────────────────────────
  ✓ semgrep /usr/local/bin/semgrep
  ✓ trufflehog /usr/local/bin/trufflehog
  ✓ npm /usr/local/bin/npm
  ○ mcp-scan — not found (pip install mcp-scan)

[1/4] Semgrep — SAST + MCP/AI custom rules
      Custom rules: .semgrep.yml
      Done: 3 findings → results/semgrep_20260223_143022.json
[2/4] TruffleHog — verified secret detection
      Done: 0 verified secrets
[3/4] npm audit — dependency vulnerabilities
      Done: 2 vulnerabilities → results/npm_audit_20260223_143022.json
[4/4] mcp-scan — MCP protocol security
      Skipped: no MCP server config found

═══════════════════════════════════════
Sentinel Scan Summary
═══════════════════════════════════════
  CRITICAL: 0
  HIGH:     1
  MEDIUM:   2
  LOW:      2
  ─────────
  TOTAL:    5
```

Use `--json` for combined machine-readable output.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean or low/medium findings only |
| 1 | HIGH severity findings |
| 2 | CRITICAL severity findings |

## Honest Assessment

This project started as a custom Python SAST scanner. After honest evaluation against existing tools, it became clear that Semgrep + TruffleHog + MCP-Scan achieve ~95% of the same results with better quality. The pivot:

- **What was killed:** Custom regex engine, FP filtering pipeline, multi-language AST analysis — all commodity capabilities that Semgrep does better
- **What was kept:** CodeQL prompt-injection query (genuinely novel), custom `.semgrep.yml` rules for MCP/AI patterns not in default rulesets
- **What was added:** `sentinel-scan.sh` orchestration, MCP-Scan integration for actual protocol security

See [docs/gap_analysis_revised_honest.md](docs/gap_analysis_revised_honest.md) for the full competitive analysis.

## Research Foundation

Based on "When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation" by Zhao et al. (2025).

## License

MIT License. See [LICENSE](LICENSE) for details.

---

[GitHub](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner) | [Gap Analysis](docs/gap_analysis_revised_honest.md) | [Design Decisions](docs/DESIGN_DECISIONS.md)
