# MCP Sentinel Scanner

The MCP Sentinel Scanner is a research-inspired security analysis tool designed to protect Model Context Protocol (MCP) infrastructures. It combines heuristic, AST, and lightweight semantic analysis to highlight risky patterns, rank attack success probability, and provide actionable remediation guidance.

## Key Features
- **Four-layer analysis**: static pattern matching, AST inspection, semantics-powered heuristics, and orchestration intelligence.
- **Attack Success Rate (ASR)** scoring that quantifies exploit feasibility on a 0–1 scale.
- **Extensible rule set** powered by JSON configuration and modular detectors.
- **Advanced modules** for authentication bypass discovery, cryptographic misuse detection, and complexity profiling.
- **Multiple report formats** including terminal, JSON, and Markdown.

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/sentinel_cli.py tests --deep-scan
```

## Configuration
Default configuration values live in `configs/default_config.json`. Provide a custom configuration on the command line with `--config path/to/config.json` to tailor exclusions, thresholds, and output preferences.

## Documentation
- Technical reference: `docs/TECHNICAL_DOCUMENTATION.md`
- Architecture diagrams: `docs/ARCHITECTURE_DIAGRAMS.md`
- Research mapping: `docs/RESEARCH_FOUNDATION.md`
- Executive overview: `PROJECT_OVERVIEW.md`

## Inspiration
The design references concepts discussed in *"When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation"* by Zhao et al. (2025). See `docs/RESEARCH_FOUNDATION.md` for a structured summary.

## Contributing
See `CONTRIBUTING.md` for guidelines on branching, testing, and submitting patches.

## License
This project is distributed under the MIT License. See `LICENSE` for details.
