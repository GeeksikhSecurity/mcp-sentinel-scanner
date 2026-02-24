# Project Overview

The MCP Sentinel Scanner delivers proactive security analysis for MCP-aligned services. It focuses on real-world exploitability, reporting severity, probability of success (ASR), and remediation steps that map to the Zhao et al. taxonomy.

## Why It Matters
- MCP servers aggregate sensitive automation tasks and contextual models that attackers target to elevate privileges.
- Traditional SAST tools miss protocol-specific flaws and contextual misuse unique to MCP deployments.
- This project blends lightweight static analysis with protocol-aware heuristics to minimise false negatives without expensive dynamic instrumentation.

## Pillars
- **Coverage**: Pattern library spans injection, deserialization, crypto, and configuration weaknesses commonly observed in MCP reference implementations.
- **Context**: AST and semantic passes reason about dangerous execution flows beyond regex matching.
- **Predictive scoring**: ASR metric estimates likelihood of attacker success using severity weighting informed by the Zhao et al. study.
- **Operational readiness**: CLI, configuration, Docker packaging, and CI workflow support integration into pipelines.

## Metrics Snapshot
- Supported languages: Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, shell, and C-family sources.
- Default ASR bandings: `>=0.8` (Critical), `0.6-0.8` (High), `0.4-0.6` (Medium), `<0.4` (Low).

## Next Steps
1. Expand taint-tracking to understand multi-file data flows.
2. Add language-specific parsing for JavaScript to reduce false positives.
3. Integrate SARIF export for developer tooling alignment.

## References
- Zhao, X., et al. *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation*. 2025. (See `docs/RESEARCH_FOUNDATION.md`)
