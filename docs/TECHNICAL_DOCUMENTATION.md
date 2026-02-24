# Technical Documentation

## 1. Architecture
The scanner implements the four-layer stack discussed in Zhao et al. (2025):

1. **Static Pattern Layer**: Regex-driven heuristics flag known vulnerability idioms.
2. **AST Layer**: Python AST inspection surfaces dangerous function usage and always-true conditions.
3. **Semantic Layer**: The advanced engine calculates metrics (complexity, crypto misuse) and detects protocol edge cases. This layer is intended to be opt-in for deep scans.
4. **Orchestration Layer**: Results are consolidated with ASR weighting, reporting utilities, and CLI interaction. Optional external tools are used when installed and enabled.

## 2. Components
- `src/mcp_sentinel_scanner.py`: Core engine performing file collection, rule execution, entropy checks, and reporting.
- `src/advanced_detection.py`: Additional analyses providing depth on authentication, crypto, and complexity (opt-in).
- `src/unified_scanner.py`: Orchestrates optional external tools and analyzers in parallel.
- `src/adapters/`: Optional tool adapters (Semgrep, TruffleHog).
- `scripts/sentinel_cli.py`: CLI for pipeline integration with JSON and Markdown output.

## 3. Detection Catalogue
| Category | Description | CWE |
| --- | --- | --- |
| sql_injection | String concatenation in SQL queries | CWE-89 |
| command_injection | Shell execution with `shell=True` | CWE-78 |
| path_traversal | Use of `../` in path construction | CWE-22 |
| weak_crypto | Weak hashing (MD5/SHA1) | CWE-327 |
| xxe | XML entity resolution enabled | CWE-611 |
| insecure_deserialization | Uses of `pickle.loads` or unsafe YAML loaders | CWE-502 |
| dangerous_function | `eval`, `exec`, `compile`, `os.system`, `subprocess.*` | CWE-95 |
| hardcoded_secret | High-entropy literals matching secret keywords | CWE-798 |

## 4. ASR Scoring
Severity weights originate from the empirical mapping in Zhao et al. (2025):
- Critical: 1.00
- High: 0.75
- Medium: 0.50
- Low: 0.25

Scores average across findings and are capped at `1.0`. Teams treat bandings as:
- `>=0.8`: Critical, immediate triage.
- `0.6-0.8`: High, remediate within 48 hours.
- `0.4-0.6`: Medium, schedule and monitor.
- `<0.4`: Low, backlog with monitoring.

## 5. Extensibility
Add new patterns by editing `_load_default_patterns()` inside `MCPSentinelScanner`. Extend advanced analyses by enhancing `AdvancedDetectionEngine._run_semantic_checks` with additional visitors. Always accompany new heuristics with regression tests inside `tests/`.

## 6. CLI Usage
```
python scripts/sentinel_cli.py <target> --format json --output report.json
python scripts/sentinel_cli.py <target> --deep-scan --severity HIGH
```

Notes:
- `--deep-scan` enables advanced semantic checks.
- `--unified` aggregates optional tools and analyzers when installed and enabled.

## 7. Limitations
- The AST layer is currently Python-only.
- No interprocedural taint tracking; flows across modules require manual review.
- False positives are possible for intentionally constructed code samples.

## 8. References
Zhao, X., Ortega, L., Chen, Q., & Musa, R. (2025). *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation*. Proceedings of the Secure Context Protocols Workshop.
