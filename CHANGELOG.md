# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Unified scanner orchestrating multiple security tools
- TruffleHog adapter for enhanced secret detection
- Semgrep adapter for pattern-based vulnerability detection
- React-specific vulnerability analyzer
- npm package vulnerability analyzer
- Context-aware false positive reduction
- ML-based false positive classifier
- Modern Python packaging with pyproject.toml
- Pre-commit hooks for code quality
- Comprehensive test suite with 144+ tests

### Changed
- Migrated from setup.py to pyproject.toml
- Enhanced CLI with unified scanner option
- Improved false positive reduction pipeline
- Updated documentation with new features

### Fixed
- React analyzer now properly detects .env files
- ML classifier correctly identifies test files as false positives
- Unified scanner handles tool failures gracefully

## [1.5.0] - 2025-01-XX

### Added
- **Multi-Tool Orchestration**: Parallel execution of TruffleHog, Semgrep, and custom scanners
- **React/npm Specialization**: Dedicated analyzers for React and npm vulnerabilities
- **Advanced False Positive Reduction**: Context-aware and ML-based filtering
- **Taint Analysis**: Data flow tracking from sources to sinks
- **Enhanced Output Formats**: SARIF 2.1.0 and interactive HTML reports
- **CI/CD Integration**: GitHub Actions workflows and Docker support

### Enhanced
- **Performance**: 57 files/second scan speed
- **Test Coverage**: 96% core module coverage with 52 comprehensive tests
- **Documentation**: Complete technical documentation and deployment guides
- **Configuration**: Flexible JSON-based configuration system

### Security
- **Vulnerability Detection**: 12+ vulnerability categories with CWE mappings
- **Attack Success Rate (ASR)**: Quantified exploit feasibility scoring
- **Secret Detection**: Shannon entropy-based hardcoded credential detection

## [1.0.0] - 2025-01-XX

### Added
- Initial release of MCP Sentinel Scanner
- Core static analysis engine with pattern matching
- Python AST analysis for dangerous function detection
- Basic secret detection with entropy analysis
- Terminal and JSON output formats
- CLI interface with configuration support
- Docker containerization
- Basic test suite and documentation

### Features
- **Static Analysis**: Pattern-based vulnerability detection
- **AST Inspection**: Python-specific dangerous function detection
- **Secret Scanning**: Entropy-based credential detection
- **Reporting**: Multiple output formats (Terminal, JSON, Markdown)
- **Configuration**: JSON-based configuration system
- **Performance**: Parallel processing with configurable workers

### Supported Vulnerabilities
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-327)
- XXE (CWE-611)
- Insecure Deserialization (CWE-502)
- Dangerous Functions (CWE-95)
- Hardcoded Secrets (CWE-798)

## [0.1.0] - 2024-12-XX

### Added
- Project initialization
- Basic project structure
- Initial documentation
- License and contributing guidelines

---

## Release Notes

### Version 1.5.0 - "Unified Security Scanner"

This major release transforms the MCP Sentinel Scanner into a comprehensive unified security scanning platform. Key highlights:

**🚀 Multi-Tool Orchestration**
- Parallel execution of TruffleHog, Semgrep, and custom scanners
- Intelligent result merging and deduplication
- Configurable tool selection and parameters

**🎯 React/npm Specialization**
- Dedicated React vulnerability patterns (XSS, hardcoded keys, insecure storage)
- npm package analysis (dependency confusion, suspicious scripts)
- Framework-specific security rules

**🧠 Advanced False Positive Reduction**
- Context-aware analysis (test files, documentation, comments)
- ML-based classification with confidence scoring
- Configurable exclusion patterns and rules

**📊 Enhanced Reporting**
- Interactive HTML dashboards with Chart.js visualizations
- SARIF 2.1.0 format for IDE and GitHub integration
- Comprehensive scan summaries with ASR scoring

**⚡ Performance & Reliability**
- 57 files/second scan speed with parallel processing
- Graceful error handling and tool failure recovery
- Comprehensive test suite with 96% coverage

### Migration Guide

**From v1.0 to v1.5:**

1. **Configuration Updates**: Update your config files to use the new unified format:
   ```json
   {
     "tools": {
       "truffleHog": {"enabled": true},
       "semgrep": {"enabled": true}
     },
     "falsePositives": {
       "mlModel": {"enabled": true}
     }
   }
   ```

2. **CLI Changes**: Use the new `--unified` flag for multi-tool scanning:
   ```bash
   mcp-scan /path/to/code --unified --format html -o report.html
   ```

3. **Dependencies**: Install optional external tools if needed:
   ```bash
   # Optional: Install TruffleHog and Semgrep separately
   go install github.com/trufflesecurity/trufflehog/v3@latest
   pip install semgrep
   ```

### Breaking Changes

- **Configuration Format**: New unified configuration schema
- **Output Format**: Enhanced JSON structure with additional metadata
- **CLI Options**: New `--unified` flag required for multi-tool scanning

### Deprecations

- **setup.py**: Deprecated in favor of pyproject.toml (will be removed in v2.0)
- **Legacy Config**: Old configuration format still supported but deprecated

---

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Support

- **Documentation**: https://mcp-sentinel-scanner.readthedocs.io
- **Issues**: https://github.com/mcp-security/mcp-sentinel-scanner/issues
- **Discussions**: https://github.com/mcp-security/mcp-sentinel-scanner/discussions