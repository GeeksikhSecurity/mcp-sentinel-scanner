# Blog Posts (SecurityLeader.ai & Whitepaper / Conference Use)

This folder contains markdown blog posts derived from MCP Sentinel Scanner implementation results. They are written for:

- **SecurityLeader.ai** — Security research and leadership audience.
- **Whitepapers** — SANS, BSIDES, and similar conferences (intro, methods, results, recommendations).
- **Talks** — BSIDES-style practitioner and research tracks.

## Posts (in order)

| # | File | Purpose |
|---|------|--------|
| 1 | [01-mcp-security-landscape-and-the-need-for-sentinel-tooling.md](01-mcp-security-landscape-and-the-need-for-sentinel-tooling.md) | Threat landscape, research foundation, role of sentinel tooling. Use as blog intro or whitepaper Section 1. |
| 2 | [02-corpus-methodology-and-real-world-findings.md](02-corpus-methodology-and-real-world-findings.md) | Corpus design, detection categories, FP reduction, example results, reproducibility. Use as methods + results. |
| 3 | [03-operationalizing-mcp-security-scanning.md](03-operationalizing-mcp-security-scanning.md) | CLI, corpus runs, CI/CD, reports, using results in whitepapers and talks. Use as recommendations / ops section. |

## Suggested use

- **SecurityLeader.ai:** Publish in order (01 → 02 → 03) or as a single long-form piece split into three parts.
- **SANS whitepaper:** Use 01 as introduction, 02 as methods and results, 03 as operational recommendations and reproducibility.
- **BSIDES:** 01 for “why MCP security”; 02 for “what we found”; 03 for “how to run it and use the outputs.”

## Source of results

- [Implementation Results and Next Steps](../IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md)
- [Research Foundation](../RESEARCH_FOUNDATION.md)
- [STATUS.md](../../STATUS.md)
- Corpus outputs: `reports/repo_corpus*` (e.g. `corpus_summary.json`)

Update post numbers and dates when publishing; pull latest corpus metrics from the repo at publication time.

---

## Disclaimer

> The views, opinions, and research presented on [SecurityLeader.ai](https://securityleader.ai) are solely those of the author, **Gurvinder Singh**, in a personal capacity. They do not represent or reflect the views, positions, or policies of the **American Psychological Association (APA)**, APA.org, or any other affiliated organization or employer. All content is provided for educational and informational purposes only.
