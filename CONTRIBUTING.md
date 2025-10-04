# Contributing Guide

Thanks for your interest in strengthening the MCP Sentinel Scanner. This guide summarises expectations for contributions.

## Development Workflow
1. Fork the repository and create a feature branch: `git checkout -b feature/<topic>`.
2. Install dependencies via `pip install -r requirements.txt` (preferably inside a virtual environment).
3. Run the demo scan to ensure baseline behaviour: `python demo.py`.
4. Add or update unit tests under `tests/` when modifying detection logic.
5. Submit a pull request describing the change, risk, and mitigation validation.

## Coding Standards
- Python 3.9+ with `ruff` or `flake8`-style linting in mind.
- Prefer descriptive class and function names over extensive inline comments.
- Keep the scanner responsive; new checks should stay linear in file size.

## Commit Messages
Follow the conventional commits style (e.g., `feat: add taint analysis for HTTP handlers`).

## Security Reporting
If you uncover a vulnerability in the scanner itself, email `security@mcp-sentinel.example` with details. We aim to respond within 48 hours.
