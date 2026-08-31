# MCP Sentinel Scanner - Phased Implementation Roadmap

**Document Version:** 1.0
**Last Updated:** October 4, 2025
**Status:** Planning

---

## Executive Summary

This roadmap outlines the phased approach to evolve MCP Sentinel Scanner from its current MVP state (v1.0) to the full-featured security platform envisioned in the PRD. The implementation is divided into 4 major phases over 12 months.

**Current State:** v1.0 MVP - Basic static analysis with 96% test coverage
**Target State:** v4.0 - Enterprise-grade security platform with AI-assisted detection

---

## Phase 1: Foundation & Hardening (v1.0 → v1.5) - Months 1-3

### Goals
- Stabilize MVP for production use
- Fix critical gaps identified in code review
- Achieve 500+ GitHub stars

### Priority 0 (Immediate - Week 1)

**P0.1: Fix CLI Entry Point**
- **Issue:** `scripts/sentinel_cli.py` fails when run as standalone script
- **Solution:** Add proper PYTHONPATH setup or use package entry point
- **File:** [scripts/sentinel_cli.py:13](scripts/sentinel_cli.py#L13)
- **Estimate:** 2 hours

**P0.2: Fix CI/CD Pipeline**
- **Issue:** GitHub Actions only runs demo, not tests
- **Solution:** Add pytest execution and coverage reporting
- **File:** [.github/workflows/ci-cd.yml:22](.github/workflows/ci-cd.yml#L22)
- **Estimate:** 4 hours

**P0.3: Add pytest-cov to dependencies**
- **File:** [requirements-dev.txt](requirements-dev.txt)
- **Estimate:** 1 hour

### Priority 1 (High - Weeks 2-4)

**P1.1: Comprehensive Error Handling Tests**
```python
# New test files needed:
tests/unit/test_error_handling.py
  - test_scan_nonexistent_path()
  - test_scan_permission_denied()
  - test_malformed_config_file()
  - test_empty_file_handling()
  - test_binary_file_handling()
  - test_unicode_edge_cases()
```
- **Estimate:** 16 hours

**P1.2: Config Integration**
- **Issue:** Config loaded but not applied properly
- **Solution:** Fix exclusion pattern matching in `_is_excluded()`
- **File:** [src/mcp_sentinel_scanner.py:246-248](src/mcp_sentinel_scanner.py#L246)
- **Estimate:** 8 hours

**P1.3: Unit Test Coverage**
```python
# New unit tests needed:
tests/unit/test_utilities.py
  - test_shannon_entropy_calculation()
  - test_asr_score_calculation()
  - test_severity_distribution()
  - test_extract_line()
```
- **Estimate:** 12 hours

**P1.4: Logging Framework**
- Replace print statements with proper logging
- Add debug/info/warn/error levels
- File rotation for production use
- **Estimate:** 16 hours

### Priority 2 (Medium - Weeks 5-12)

**P1.5: Extract Patterns to JSON Rules**
- Move hardcoded regex patterns to `configs/rules/`
- Enable custom rule packs
- Versioned rule updates
- **Files:** New `configs/rules/*.json`
- **Estimate:** 24 hours

**P1.6: Enhanced CLI Features**
- Progress bars for large scans
- Interactive mode for triage
- Configuration wizard
- **Estimate:** 20 hours

**P1.7: Documentation Improvements**
- API documentation (Sphinx)
- Tutorial videos
- Security best practices guide
- **Estimate:** 16 hours

**P1.8: Performance Optimization**
- File caching for incremental scans
- Optimized regex compilation
- Memory profiling and optimization
- **Estimate:** 20 hours

### Deliverables (v1.5)
- ✅ Production-ready CLI tool
- ✅ 98%+ test coverage with error scenarios
- ✅ Configurable rule system
- ✅ Comprehensive documentation
- ✅ PyPI package published
- ✅ 500+ GitHub stars

---

## Phase 2: Advanced Detection (v1.5 → v2.0) - Months 4-6

### Goals
- Implement taint analysis
- Add multi-language AST support
- Introduce SARIF export
- Achieve 1,000+ GitHub stars

### Features

**F2.1: Taint Analysis Engine**
- **Priority:** HIGH
- **Complexity:** High
- **Description:** Track data flow from untrusted sources to dangerous sinks
- **Implementation:**
  ```python
  # New module: src/taint_analysis.py
  class TaintAnalyzer:
      def __init__(self):
          self.sources = ["request.args", "request.form", "input()"]
          self.sinks = ["eval", "exec", "os.system", "subprocess"]

      def analyze_dataflow(self, ast_tree):
          # Build control flow graph
          # Track variable assignments
          # Identify tainted paths
          pass
  ```
- **Test Coverage:** 95%+
- **Estimate:** 80 hours

**F2.2: Multi-Language AST Support**
- **Languages:** JavaScript/TypeScript (via tree-sitter), Java, Go
- **Implementation:**
  ```python
  # New module: src/ast_analyzers/
  #   - javascript_analyzer.py
  #   - typescript_analyzer.py
  #   - java_analyzer.py
  #   - go_analyzer.py
  ```
- **Dependencies:** Add tree-sitter, tree-sitter-javascript, etc.
- **Estimate:** 120 hours

**F2.3: SARIF Export Format**
- **Description:** Static Analysis Results Interchange Format for IDE integration
- **Use Case:** VS Code, GitHub Code Scanning integration
- **File:** New `src/reporters/sarif_reporter.py`
- **Estimate:** 24 hours

**F2.4: Enhanced Crypto Detection**
- Detect weak key sizes (RSA < 2048, AES < 128)
- Identify ECB mode usage
- Check for hardcoded IVs/salts
- Validate certificate validation
- **Estimate:** 32 hours

**F2.5: Advanced Pattern Detection**
```python
# New vulnerability patterns:
- SSRF (Server-Side Request Forgery)
- JWT algorithm confusion
- Prototype pollution (JS)
- LDAP injection
- Template injection
- Mass assignment vulnerabilities
```
- **Estimate:** 40 hours

### Deliverables (v2.0)
- ✅ Taint analysis for Python + JS/TS
- ✅ Multi-language AST support (4+ languages)
- ✅ SARIF export for IDE integration
- ✅ 15+ new vulnerability patterns
- ✅ VS Code extension (basic)
- ✅ 1,000+ GitHub stars

---

## Phase 3: Intelligence & Automation (v2.0 → v3.0) - Months 7-9

### Goals
- ML-based anomaly detection
- Attack graph visualization
- CI/CD deep integration
- Achieve 2,000+ GitHub stars

### Features

**F3.1: ML-Based Anomaly Detection**
- **Model:** Isolation Forest for code anomaly detection
- **Features:**
  - Function complexity metrics
  - Code structure patterns
  - API usage patterns
  - Entropy analysis
- **Implementation:**
  ```python
  # New module: src/ml_detection.py
  import numpy as np
  from sklearn.ensemble import IsolationForest

  class MLAnomalyDetector:
      def __init__(self):
          self.model = IsolationForest(contamination=0.1)

      def extract_features(self, ast_tree):
          # Extract 20+ code features
          pass

      def detect_anomalies(self, features):
          # Return anomaly score
          pass
  ```
- **Training Data:** Curated dataset of malicious/benign MCP servers
- **Estimate:** 100 hours

**F3.2: Attack Graph Generation**
- **Description:** Visualize attack paths from entry points to critical assets
- **Technology:** NetworkX + D3.js for interactive graphs
- **Implementation:**
  ```python
  # New module: src/attack_graph.py
  import networkx as nx

  class AttackGraphBuilder:
      def build_graph(self, findings):
          G = nx.DiGraph()
          # Add nodes for vulnerabilities
          # Add edges for attack paths
          # Calculate attack surface metrics
          return G
  ```
- **Output Formats:** JSON, HTML (interactive), PNG/SVG
- **Estimate:** 60 hours

**F3.3: NLP-Based Deception Detection**
- **Description:** Analyze documentation and comments for misleading descriptions
- **Use Case:** Detect "helpful" tools that hide malicious intent
- **Implementation:**
  ```python
  # New module: src/nlp_detection.py
  import spacy

  class DeceptionDetector:
      def analyze_documentation(self, text):
          # Sentiment analysis
          # Intent classification
          # Contradiction detection
          pass
  ```
- **Estimate:** 80 hours

**F3.4: GitHub Actions Marketplace Action**
- **Description:** Pre-built action for easy CI/CD integration
- **File:** New `action.yml`
- **Features:**
  - Automatic PR comments
  - Security badges
  - Trending tracking
  - Fail-on-threshold
- **Estimate:** 40 hours

**F3.5: HTML Report Generation**
- **Description:** Beautiful, interactive HTML reports
- **Features:**
  - Vulnerability dashboard
  - Trend charts
  - Code highlighting
  - Remediation guides
- **Technology:** Jinja2 templates + Chart.js
- **Estimate:** 32 hours

**F3.6: Slack/Teams/Discord Integration**
- **Description:** Real-time notifications for findings
- **Features:**
  - Webhook support
  - Severity-based filtering
  - Rich message formatting
- **Estimate:** 24 hours

### Deliverables (v3.0)
- ✅ ML anomaly detection (90%+ accuracy)
- ✅ Attack graph visualization
- ✅ NLP deception detection
- ✅ GitHub Actions marketplace action
- ✅ HTML reports with charts
- ✅ Webhook integrations
- ✅ 2,000+ GitHub stars
- ✅ 2,000+ CI/CD runs

---

## Phase 4: Enterprise & Research (v3.0 → v4.0) - Months 10-12

### Goals
- Remote repository scanning
- Sandbox execution (dynamic analysis)
- LLM-assisted semantic audits
- Enterprise features
- Academic paper publication

### Features

**F4.1: Remote Repository Scanning**
- **Description:** Clone and scan GitHub/GitLab repositories
- **Features:**
  - OAuth integration
  - Batch scanning
  - Differential scanning (PR-based)
  - Rate limiting
- **Estimate:** 60 hours

**F4.2: Dynamic Sandbox Execution**
- **Description:** Execute code in isolated environment to detect runtime issues
- **Technology:** Docker containers + ptrace monitoring
- **Detection:**
  - Actual network connections
  - File system access patterns
  - Process spawning
  - Unexpected behavior
- **Security:** Strict isolation, resource limits
- **Estimate:** 120 hours

**F4.3: LLM-Assisted Semantic Analysis**
- **Description:** Use Claude/GPT-4 for semantic code understanding
- **Use Cases:**
  - Intent classification
  - Vulnerability confirmation
  - False positive reduction
  - Remediation generation
- **Privacy:** Local-first with opt-in cloud
- **Estimate:** 80 hours

**F4.4: Dependency Analysis**
- **Description:** Analyze dependency chains for supply chain attacks
- **Features:**
  - Dependency confusion detection
  - Typosquatting detection
  - Known vulnerable package detection
  - License compliance
- **Estimate:** 60 hours

**F4.5: Enterprise Dashboard**
- **Description:** Web-based dashboard for organization-wide monitoring
- **Features:**
  - Multi-project tracking
  - Team management
  - Compliance reporting
  - Trend analysis
- **Technology:** React + FastAPI backend
- **Estimate:** 160 hours

**F4.6: SaaS Offering**
- **Description:** Hosted version of MCP Sentinel
- **Features:**
  - Automated scheduled scans
  - API access
  - SSO integration
  - Compliance reports (SOC2, HIPAA)
- **Estimate:** 200 hours

### Research Goals

**R4.1: Academic Paper**
- Submit to security conference (USENIX, IEEE S&P, CCS)
- Document effectiveness vs. existing tools
- Publish benchmark dataset
- **Estimate:** 100 hours

**R4.2: Benchmark Dataset**
- Curate 1,000+ MCP server samples
- Label with A1-A12 attack categories
- Public release for research
- **Estimate:** 80 hours

### Deliverables (v4.0)
- ✅ Remote scanning capability
- ✅ Dynamic sandbox analysis
- ✅ LLM semantic analysis
- ✅ Enterprise dashboard
- ✅ SaaS offering (beta)
- ✅ Academic paper submitted
- ✅ Public benchmark dataset
- ✅ 5,000+ GitHub stars

---

## Resource Requirements

### Team Composition (Phase 2+)

| Role | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|------|---------|---------|---------|---------|
| Core Developer | 1 FTE | 2 FTE | 2 FTE | 3 FTE |
| Security Researcher | 0.5 FTE | 1 FTE | 1 FTE | 1 FTE |
| ML Engineer | - | 0.5 FTE | 1 FTE | 1 FTE |
| DevOps/SRE | - | 0.5 FTE | 0.5 FTE | 1 FTE |
| Technical Writer | 0.25 FTE | 0.5 FTE | 0.5 FTE | 0.5 FTE |
| **Total** | **1.75 FTE** | **4.5 FTE** | **5 FTE** | **6.5 FTE** |

### Budget Estimates

| Phase | Development | Infrastructure | Marketing | Total |
|-------|-------------|----------------|-----------|-------|
| Phase 1 | $50,000 | $5,000 | $10,000 | $65,000 |
| Phase 2 | $120,000 | $15,000 | $20,000 | $155,000 |
| Phase 3 | $150,000 | $25,000 | $30,000 | $205,000 |
| Phase 4 | $200,000 | $50,000 | $50,000 | $300,000 |
| **Total** | **$520,000** | **$95,000** | **$110,000** | **$725,000** |

---

## Success Metrics

### Technical Metrics

| Metric | v1.5 | v2.0 | v3.0 | v4.0 |
|--------|------|------|------|------|
| Test Coverage | 98% | 97% | 95% | 95% |
| Detection Rate (Benchmark) | 75% | 85% | 92% | 95% |
| False Positive Rate | <15% | <10% | <5% | <3% |
| Scan Speed (1000 files) | <30s | <45s | <60s | <90s |
| Languages Supported | 1 | 5 | 8 | 12 |
| Vulnerability Patterns | 12 | 25 | 40 | 60 |

### Adoption Metrics

| Metric | v1.5 | v2.0 | v3.0 | v4.0 |
|--------|------|------|------|------|
| GitHub Stars | 500 | 1,000 | 2,000 | 5,000 |
| PyPI Downloads/month | 1,000 | 5,000 | 15,000 | 50,000 |
| CI/CD Runs/month | 500 | 2,000 | 10,000 | 50,000 |
| Active Contributors | 5 | 15 | 30 | 50 |
| Enterprise Customers | - | - | 5 | 25 |

---

## Risk Management

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ML model accuracy insufficient | Medium | High | Use ensemble methods, manual review fallback |
| Sandbox escape vulnerabilities | Low | Critical | Security audit, bug bounty, strict isolation |
| Performance degradation | High | Medium | Continuous benchmarking, optimization sprints |
| LLM API costs too high | Medium | Medium | Local models, caching, rate limiting |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Slow adoption | Medium | High | Marketing, partnerships, free tier |
| Competition (commercial tools) | High | Medium | Open source advantage, community building |
| Funding gaps | Medium | Critical | Phased approach, revenue from v3.0+ |
| Security incident | Low | Critical | Responsible disclosure, rapid response |

---

## Decision Points

### After Phase 1 (Month 3)
- **GO/NO-GO:** Proceed to Phase 2?
- **Metrics:** 500+ stars, 1,000+ downloads, <10 critical bugs
- **Decision:** Community adoption vs. feature development

### After Phase 2 (Month 6)
- **GO/NO-GO:** Invest in ML/AI features?
- **Metrics:** 1,000+ stars, 5,000+ downloads, taint analysis adoption
- **Decision:** Research focus vs. commercial focus

### After Phase 3 (Month 9)
- **GO/NO-GO:** Launch SaaS offering?
- **Metrics:** 2,000+ stars, enterprise interest, revenue potential
- **Decision:** Open source only vs. hybrid model

---

## Appendix A: Technology Stack Evolution

### Phase 1 (Current)
- Python 3.9+
- AST module (stdlib)
- colorama, tabulate
- pytest

### Phase 2
- + tree-sitter (multi-language AST)
- + SARIF schema validation
- + Type stubs for better IDE support

### Phase 3
- + scikit-learn (ML models)
- + NetworkX (attack graphs)
- + spaCy (NLP)
- + Jinja2 (HTML reports)
- + Chart.js (visualizations)

### Phase 4
- + Docker SDK (sandboxing)
- + GitPython (repository scanning)
- + Anthropic/OpenAI SDKs (LLM analysis)
- + React + FastAPI (dashboard)
- + PostgreSQL (enterprise data)

---

## Appendix B: Community Engagement

### Open Source Strategy
- Monthly community calls
- Quarterly roadmap reviews
- Hacktoberfest participation
- Conference presentations (DEF CON, Black Hat, OWASP)
- Blog posts on findings and techniques

### Partnerships
- MCP Registry integration
- IDE plugin partnerships (VS Code, JetBrains)
- CI/CD platform partnerships (GitHub, GitLab, CircleCI)
- Security tool integrations (Snyk, Veracode)

---

## Conclusion

This roadmap provides a clear path from the current MVP (v1.0) to a comprehensive enterprise-grade security platform (v4.0) over 12 months. The phased approach allows for:

1. **Quick wins** (Phase 1) to establish credibility
2. **Technical depth** (Phase 2) to differentiate from competitors
3. **Innovation** (Phase 3) with AI/ML features
4. **Sustainability** (Phase 4) through enterprise features

**Next Steps:**
1. Review and approve roadmap
2. Secure Phase 1 funding/resources
3. Set up project tracking (GitHub Projects)
4. Begin P0 implementations

---

**Document Status:** Draft for Review
**Approvers:** MCP Security Team, Open Source Maintainers
**Review Date:** October 11, 2025

---

## Addendum (2026-08-30): Competitive Comparison + Bug-Bounty-Research-Driven Items

Sourced from `docs/gap_analysis_revised_honest.md` (full "vs. claude-mcp-sentinel" comparison, 2026-08-30) and the live MCP bug-bounty research pipeline (Notion: "MCP Security Gap Analysis Research", "MCP Scanner Toolkit — from mcp-huntr", "Specialization Tracks — MCP & Vibe-Code Scan Playbooks"). These are concrete, not aspirational — several are backed by a confirmed finding or a live disclosure.

| # | Item | Effort | Impact / Source |
|---|------|--------|------|
| 1 | **D6 — osv.dev + GitHub Advisory cross-reference at scan time.** Query for the target's declared dependencies and any MCP servers it wraps, flag known-CVE matches inline in SARIF. | 2-3 days | Closes the one real capability gap vs. claude-mcp-sentinel. Reuse `tools/prior-art-gate.sh`'s existing osv.dev query rather than a second implementation. |
| 2 | **D7 — Tool-description/manifest snapshot + coherence-diff hashing.** Hash each scanned server's tool names, descriptions, and parameter schemas; flag drift on re-scan before silently accepting a new version. | 3-4 days | Mechanical answer to Postmark-class supply-chain drift. Independently item #1 on the arXiv-research scanner roadmap (Phase 1). |
| 3 | **Non-tool entrypoint coverage** — extend detection to `resources/read` and `prompts` handlers, not just `tools/*`. | 1 week | A confirmed real SQLi (`executeautomation/mcp-database-server`) lived in a resource handler; tool-only scanners (including most off-the-shelf ones) miss this surface entirely. |
| 4 | **Guard-asymmetry cross-handler pass.** When a validator exists on one path to a shared sink (e.g. `tableNames.includes()` on a tool handler), flag sibling handlers reaching the same sink without the same guard. | Custom pass, not a single Semgrep rule | This *was* the confirmed SQLi's root cause. Not expressible as clean taint-tracking since a throw-guard isn't in the dataflow — needs a small cross-handler diff pass in the scanner itself. |
| 5 | **CWE-346 (Origin/DNS-rebinding) check for HTTP-transport MCP servers.** | Medium | Currently the highest-yield class in live hunting — 3/3 source-checked HTTP-capable targets had the gap (confirmed findings in disclosure on `comfyui-mcp`, `mcp-proxy`). Worth a dedicated detector before the class saturates. |
| 6 | **Tool-poisoning (MCP03) test corpus, MCPTox-paradigm-labeled.** Extend the existing `known_safe/`/`known_vuln/` corpus (Action Item #5 above) with P1/P2/P3 tool-poisoning cases (explicit-trigger hijacking, implicit-trigger hijacking, parameter tampering) per Fang et al.'s MCPTox benchmark (arXiv:2508.14925). | 1 week | 97.1% of tool descriptions in one 856-tool study contained defects; this is the class the current hit-list is thinnest on relative to the official OWASP MCP Top 10. |
| 7 | **OWASP MCP Top 10 crosswalk citations in report/SARIF output.** Tag each finding with its MCP Top 10 category (MCP01–MCP10) alongside the existing OWASP LLM Top 10 / AISVS mapping. | 2-3 days | Standards crosswalk (OWASP MCP Top 10 × LLM Top 10 × AISVS × NIST AI RMF) already exists as research; wiring it into output is the direct fix for "triagers may not grasp MCP impact." |
| 8 | **Explicit "vs. claude-mcp-sentinel" README positioning**, naming the 6-repo "MCP Sentinel" collision. | 1 hour | Done — see README `⚖️ Naming & Trademarks`. |

**Explicitly out of scope for this repo** (per the comparison's "do not adopt" call): a live PreToolUse runtime-blocking hook. Different product surface (Claude-Code-specific, fail-open-by-design) from a pre-deployment/CI static scanner that needs to fail closed. If pursued at all, it stays a separate companion project, not a mcp-sentinel-scanner feature.
