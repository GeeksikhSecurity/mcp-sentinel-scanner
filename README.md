# MCP Sentinel Scanner

[![CI](https://github.com/mcp-security/mcp-sentinel-scanner/workflows/CI/badge.svg)](https://github.com/mcp-security/mcp-sentinel-scanner/actions)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](https://github.com/mcp-security/mcp-sentinel-scanner)
[![Version](https://img.shields.io/badge/version-1.5-blue)](https://github.com/mcp-security/mcp-sentinel-scanner/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

The MCP Sentinel Scanner is a research-inspired security analysis tool designed to protect Model Context Protocol (MCP) infrastructures. It combines static analysis, AST inspection, taint analysis, and semantic heuristics to detect vulnerabilities with high accuracy.

## ✨ Key Features

- 🔍 **Multi-Layer Analysis** - Static patterns, AST inspection, taint analysis, semantic heuristics
- 📊 **Attack Success Rate (ASR)** - Quantifies exploit feasibility on a 0–1 scale
- 🎯 **High Accuracy** - 96% test coverage, comprehensive vulnerability detection
- 🚀 **Fast Scanning** - 57 files/second with parallel processing
- 📄 **5 Output Formats** - Terminal, JSON, Markdown, SARIF, HTML
- 🐳 **Docker Ready** - Pre-built images for easy deployment
- 🔄 **CI/CD Integration** - GitHub Actions, Jenkins, Bitbucket pipelines
- 🛡️ **Advanced Detection** - Taint analysis, auth bypass, crypto misuse

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Pull and run
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# Generate HTML report
docker run --rm -v $(pwd):/scan -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format html -o /reports/report.html
```

### pip Install

```bash
pip install mcp-sentinel-scanner
mcp-scan /path/to/code
```

### From Source

```bash
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner
pip install -r requirements.txt
python -m scripts.sentinel_cli /path/to/code
```

**👉 See [QUICK_START.md](QUICK_START.md) for more options**

## 📊 Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **Terminal** | Interactive use | `--format terminal` (default) |
| **HTML** | Reports, dashboards | `--format html -o report.html` |
| **JSON** | API integration | `--format json -o results.json` |
| **SARIF** | IDE, GitHub Security | `--format sarif -o results.sarif` |
| **Markdown** | Documentation | `--format markdown -o report.md` |

## 🐳 Docker Usage

```bash
# Basic scan
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# With exclusions
docker run --rm -v $(pwd):/scan \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --exclude "node_modules" "*.d.ts" "dist"

# Multiple formats
docker run --rm -v $(pwd):/scan -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format html -o /reports/report.html

# Using docker-compose
docker-compose up scanner
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/scan \
      ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
      /scan --format sarif -o results.sarif

- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'docker run --rm -v ${WORKSPACE}:/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan'
    }
}
```

**👉 Full guides: [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)**

## ⚙️ Configuration

Create `config.json`:

```json
{
  "exclude": ["node_modules", "*.d.ts", "dist", ".git"],
  "severity_threshold": "HIGH",
  "parallel_workers": 4
}
```

Use it:
```bash
mcp-scan /path --config config.json
```

## 📚 Documentation

### Getting Started
- 📖 [Quick Start Guide](QUICK_START.md) - Get scanning in 60 seconds
- 🚀 [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) - Docker, CI/CD, local setup
- ⚙️ [Configuration Guide](configs/default_config.json) - Customize the scanner

### Architecture & Development
- 🏗️ [Architecture Diagrams](docs/ARCHITECTURE_DIAGRAMS.md) - System design
- 🔬 [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) - Deep dive
- 🗺️ [Roadmap](ROADMAP.md) - Future features and timeline
- 📊 [Implementation Summary](IMPLEMENTATION_SUMMARY.md) - What's implemented

### Reports & Analysis
- 🔒 [Security Scan Report](SECURITY_SCAN_REPORT.md) - Real-world scan results
- 📈 [Scan Comparison](SCAN_COMPARISON_REPORT.md) - v1.0 vs v1.5 analysis
- 📊 [Project Status](STATUS.md) - Current state and metrics

### Research & Foundation
- 📄 [Research Foundation](docs/RESEARCH_FOUNDATION.md) - Academic basis
- 📝 [PRD](PRD%20open%20source%20mcp%20scanner-%20MCP%20Sentinel.md) - Product requirements
- 📋 [Project Overview](PROJECT_OVERVIEW.md) - Executive summary

## 🎯 Features

### Core Detection
- ✅ SQL Injection (CWE-89)
- ✅ Command Injection (CWE-78)
- ✅ Path Traversal (CWE-22)
- ✅ XSS (CWE-79)
- ✅ Weak Cryptography (CWE-327)
- ✅ Hardcoded Secrets (CWE-798)
- ✅ Insecure Deserialization (CWE-502)
- ✅ XXE (CWE-611)
- ✅ Dangerous Functions (eval, exec)

### Advanced Analysis (v1.5)
- ✅ **Taint Analysis** - Data flow tracking from sources to sinks
- ✅ **Authentication Bypass** - Always-true condition detection
- ✅ **Crypto Misuse** - Weak algorithms and random number generators
- ✅ **Complexity Metrics** - Cyclomatic complexity analysis

### Output & Integration
- ✅ **SARIF Export** - For VS Code and GitHub Code Scanning
- ✅ **HTML Reports** - Interactive dashboards with charts
- ✅ **JSON/Markdown** - Machine-readable and human-friendly
- ✅ **CI/CD Ready** - GitHub Actions, Jenkins, Bitbucket

## 📈 Performance

| Metric | Value |
|--------|-------|
| **Scan Speed** | 57 files/second |
| **Test Coverage** | 96% (core modules) |
| **Test Cases** | 52 comprehensive tests |
| **Languages** | Python (JS/TS coming in v2.0) |
| **Parallel Processing** | 4-8 workers |

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v --cov=src

# Make changes and submit PR
```

## 🔬 Research Foundation

Based on *"When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation"* by Zhao et al. (2025).

See [docs/RESEARCH_FOUNDATION.md](docs/RESEARCH_FOUNDATION.md) for details.

## 📊 Project Status

- ✅ **Phase 1 Complete** - Foundation & hardening
- ⚡ **Phase 2 Partial** - Taint analysis, SARIF export
- ⚡ **Phase 3 Partial** - HTML reports
- 📋 **Phase 4 Planned** - ML detection, enterprise features

See [STATUS.md](STATUS.md) for detailed progress.

## 📝 License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **Zhao et al. (2025)** - Research foundation
- **Open Source Community** - Contributions and feedback
- **Security Researchers** - Vulnerability taxonomies and best practices

---

**🌟 Star us on GitHub!** | **🐛 Report Issues** | **💬 Join Discussions**

[GitHub](https://github.com/mcp-security/mcp-sentinel-scanner) • [Documentation](docs/) • [Roadmap](ROADMAP.md)
