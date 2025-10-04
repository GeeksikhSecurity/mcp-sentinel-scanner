# Research Foundation

## Source Paper
- Zhao, X., Ortega, L., Chen, Q., & Musa, R. (2025). *When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation*. arXiv preprint arXiv:2509.24272.

## Key Insights
1. **Attack Taxonomy (A1–A12)**: Comprehensive listing of MCP attack surfaces from prompt injection to context hijacking.
2. **Success Predictors**: Severity correlates strongly with exploit simplicity and session persistence, motivating the ASR weighting strategy.
3. **Mitigation Portfolio**: Paper advocates layered defences mixing validation, anomaly detection, and continuous scanning.

## How the Scanner Maps to the Paper
| Paper Concept | Implementation |
| --- | --- |
| A1 (Prompt Injection) | Pattern search for string concatenation with untrusted input. |
| A3 (Secret Leakage) | Entropy-based hardcoded secret detection. |
| A7 (State Corruption) | Complexity metrics flag brittle control flow. |
| A11 (Auth Bypass) | AST analysis for always-true branch conditions. |

## Quantitative References
- The authors report a 95% detection rate for blended prompt/file attacks using four-layer analysis. The scanner adopts the same layered approach to approach this benchmark.
- Severity weighting mirrors the empirical ASR mapping from Table 3 of the paper.

## Additional Reading
- Mitra, S., Dong, Y., & Fox, K. (2024). *Context-Aware Static Analysis for AI Orchestration Pipelines*.
- Hsu, P., & Dani, A. (2023). *Lightweight Taint Analysis for Serverless Functions*.
