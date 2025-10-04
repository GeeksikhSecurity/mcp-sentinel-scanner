# Product Requirements Document: MCP Sentinel

**Document Version:** 1.1  
**Date:** October 2, 2025  
**Author:** MCP Security Team  
**Status:** Draft  
**Stakeholders:** Open Source Community, AI/ML Developers, Corporate Security Teams, MCP Registry Maintainers

---

## 1. Overview & Vision

**Overview:** MCP Sentinel is an open-source security scanner tailored to Model Context Protocol (MCP) servers. Version 1 focuses on robust static analysis that blends rule-based pattern matching, AST inspection, and semantic heuristics to uncover high-impact weaknesses common in MCP tooling and integrations.

**Vision:** Provide a dependable, community-driven scanner that becomes the default trust signal for MCP resources by offering clear guidance, reproducible scoring, and easy CI/CD automation.

## 2. Background & Strategic Fit

The MCP ecosystem is rapidly expanding, but existing scanners miss protocol-specific attack paths highlighted in recent research (e.g., Zhao et al., 2025). Malicious MCP servers can masquerade as helpful tools, introducing prompt injection, hardcoded secrets, or orchestration abuse. MCP Sentinel bridges this gap by operationalising the research taxonomy into a practical scanner that organisations can run locally, integrate into pipelines, and extend through configuration.

## 3. Objectives & Success Metrics

| Objective | Key Result (Success Metric) |
| --- | --- |
| Deliver actionable detection coverage | ≥90% detection on a curated benchmark spanning top MCP weakness patterns. |
| Encourage adoption & trust | 2,000 GitHub stars and 500 forks within 12 months of launch. |
| Streamline developer workflow | Publish CLI + GitHub Actions integration with ≥2,000 cumulative runs within 6 months. |
| Provide intelligible guidance | User feedback indicates ≥85% satisfaction with report clarity and remediation steps. |

## 4. Target Personas & Use Cases

1. **Security Engineer (DevSecOps)**  
   *Use case:* Automatically scan third-party MCP servers during CI/CD. Builds fail when critical issues exceed a configurable severity threshold, and JSON output feeds dashboards.

2. **AI/ML Developer**  
   *Use case:* Run a local scan from the terminal before adopting a community MCP server. Markdown or terminal output summarises risks and remediation guidance.

3. **MCP Registry Maintainer**  
   *Use case:* Periodically audit submitted MCP servers with batch scans. Markdown reports feed review workflows and public "verified" labels.

## 5. Requirements & Features (EARS Syntax)

### User Story 1: CI/CD Integration

*As a Security Engineer, I want MCP Sentinel to plug into pipelines so that MCP servers are evaluated before deployment.*

- **Ubiquitous:** The MCP Sentinel **shall** accept local filesystem paths as scan targets.
- **Event-Driven:** When a scan starts, the MCP Sentinel **shall** apply configurable static rules and AST heuristics to supported file types.
- **Unwanted Behaviour:** If any finding meets or exceeds the configured severity threshold, then the MCP Sentinel **shall** exit with a non-zero status code.
- **Event-Driven:** When a scan completes, the MCP Sentinel **shall** be capable of emitting machine-readable (JSON) and human-readable (Markdown, terminal) reports.

### User Story 2: Developer Workstation Scans

*As an AI/ML developer, I want fast insights from the CLI so that I can decide whether to trust a server.*

- **Ubiquitous:** The MCP Sentinel **shall** provide colourised terminal output summarising findings when run interactively.
- **Event-Driven:** When the scanner processes files, it **shall** highlight vulnerable code snippets with remediation advice and CWE references.
- **Optional Feature:** Where Markdown output is requested, the MCP Sentinel **should** generate a report suitable for sharing in issue trackers.

### User Story 3: Advanced Heuristics

*As a user, I want additional context beyond simple pattern hits so that complex issues are easier to triage.*

- **Event-Driven:** When the AST layer detects always-true conditions in access checks, the MCP Sentinel **shall** classify them as authentication bypass risks.
- **Event-Driven:** When cryptographic primitives from weak families are used, the MCP Sentinel **shall** flag crypto misuse with severity guidance.
- **Event-Driven:** When complexity metrics exceed defined thresholds, the MCP Sentinel **shall** emit an advisory finding to aid maintainability review.

## 6. User Interaction & Design

- **Interface:** Command-line utility (`scripts/sentinel_cli.py`) with arguments for target path, output format, severity filtering, and parallelism.
- **Output:**
  - Terminal: Colour-coded summary with tabular view of findings.  
  - JSON: Structured payload for pipeline consumption.  
  - Markdown: Shareable reports for audit trails.
- **Configuration:** Defaults in `configs/default_config.json` cover exclusion paths and severity settings; users can provide custom JSON configs.

## 7. Scope Boundaries (V1)

- ✅ Included: Static pattern rules, Python AST analysis, entropy-based secret detection, advanced heuristics (auth bypass, crypto misuse, complexity scoring), CLI tooling, Docker packaging, GitHub Actions workflow, documentation.
- 🚫 Deferred: Remote Git cloning, dynamic sandbox execution, LLM-assisted semantic audits, real-time progress updates, SARIF export, VS Code extension.

## 8. Assumptions

- Users have Python 3.9+ environments; optional Docker image provides containerised execution.
- The Zhao et al. taxonomy remains a relevant threat baseline.
- Community contributions will follow the MIT licence to maximise adoption.
- Scans are primarily offline/local; networked enrichments can be introduced later as opt-in features.

## 9. Open Questions

1. What format/versioning strategy best supports rule-pack updates without breaking CI pipelines?
2. How should we balance false positives vs. missed detections for high-entropy secret heuristics?
3. Which additional languages should receive AST-like analysis next (e.g., TypeScript via tree-sitter)?

## 10. Release Plan

- **Alpha (complete):** Core CLI, static + AST layers, advanced heuristics, Markdown/JSON reporting, documentation set.
- **Beta:** Introduce optional SARIF export, configurable severity weighting, and richer CI recipes.
- **V1.0 GA:** Harden rule packs, extend language coverage, publish PyPI package, add contribution governance playbook.
- **Post-V1 Roadmap:** Explore remote repository scanning, sandbox execution, LLM-assisted semantic checks, editor extensions.

## 11. References

- Zhao, X., Ortega, L., Chen, Q., & Musa, R. (2025). *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation*. arXiv:2509.24272.
- Mitra, S., Dong, Y., & Fox, K. (2024). *Context-Aware Static Analysis for AI Orchestration Pipelines*.
- Hsu, P., & Dani, A. (2023). *Lightweight Taint Analysis for Serverless Functions*.
