# Security Policy

## Supported Versions

We actively support the following versions of MCP Sentinel Scanner with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in MCP Sentinel Scanner, please report it responsibly.

### Where to Report

**For security vulnerabilities, please DO NOT create a public GitHub issue.**

Instead, please report security issues through one of the following methods:

1. **GitHub Security Advisories (Preferred)**
   - Navigate to the [Security tab](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the private vulnerability report form
   - Our security team will respond within 48 hours

2. **Email**
   - Send details to: security@sayvainc.com
   - Use PGP key: [Available on request]
   - Include "MCP Sentinel Scanner Security" in the subject line

3. **Pull Request (For non-critical issues)**
   - Fork the repository
   - Create a branch: `security/fix-description`
   - Make your changes
   - Submit a PR with tag `security`

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker achieve?
- **Reproduction**: Step-by-step instructions to reproduce
- **Affected Versions**: Which versions are impacted?
- **Proof of Concept**: Code or screenshots demonstrating the issue
- **Suggested Fix**: If you have ideas for remediation

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 5 business days
- **Status Updates**: Every 7 days until resolved
- **Fix Release**: Critical issues within 14 days, High within 30 days

### Security Update Process

1. **Acknowledgment**: We confirm receipt and begin investigation
2. **Assessment**: We evaluate severity using CVSS 3.1 scoring
3. **Development**: We develop and test a fix
4. **Disclosure**: We coordinate disclosure with the reporter
5. **Release**: We release a patched version
6. **Advisory**: We publish a security advisory (if applicable)

## Security Best Practices

### For Users

When using MCP Sentinel Scanner:

- ✅ **Keep Updated**: Always use the latest version
- ✅ **Scan Before Deploy**: Run scans before production deployments
- ✅ **Review Findings**: Don't ignore CRITICAL and HIGH severity findings
- ✅ **Use CI/CD Integration**: Automate security scanning in pipelines
- ✅ **Exclude Sensitive Data**: Don't scan files containing real secrets
- ✅ **Verify SARIF**: Review uploaded security findings in GitHub Security tab

### For Contributors

When contributing code:

- ✅ **No Secrets**: Never commit API keys, tokens, or credentials
- ✅ **Input Validation**: Sanitize all user inputs
- ✅ **Least Privilege**: Request minimum permissions needed
- ✅ **Dependency Updates**: Keep dependencies up to date
- ✅ **Test Coverage**: Maintain >95% test coverage for security modules
- ✅ **Code Review**: All PRs require security review for core modules

## Known Limitations

The scanner is designed for **defensive security** purposes only. We explicitly:

- ❌ Do not assist with offensive security tools
- ❌ Do not help with credential harvesting or bulk secret extraction
- ❌ Do not support malware development or distribution
- ✅ Support security analysis, detection rules, and defensive tools
- ✅ Support vulnerability explanations and remediation guidance

## Security Features

MCP Sentinel Scanner includes:

- **Multi-Layer Detection**: Pattern matching, AST analysis, taint tracking
- **Attack Success Rate (ASR)**: Quantifies exploit feasibility (0.0-1.0)
- **SARIF 2.1.0 Support**: GitHub Security integration
- **CWE Mappings**: Industry-standard vulnerability categorization
- **Configurable Thresholds**: Block builds on CRITICAL/HIGH findings
- **False Positive Filtering**: Reduce noise with custom exclusions

## Vulnerability Disclosure Policy

We follow **Coordinated Vulnerability Disclosure** principles:

1. **Private Reporting**: Report vulnerabilities privately first
2. **90-Day Window**: We aim to fix within 90 days of report
3. **Early Disclosure**: We may disclose earlier if exploit is public
4. **Credit**: We credit reporters in security advisories (unless anonymous)
5. **CVE Assignment**: We request CVEs for qualifying vulnerabilities

### Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Security researchers will be listed here -->
_No vulnerabilities reported yet. Be the first!_

## Security Scanning of MCP Sentinel Scanner

We practice what we preach! This project is continuously scanned with:

- **Self-Scanning**: MCP Sentinel Scanner scans its own codebase
- **GitHub CodeQL**: Advanced semantic analysis
- **Dependency Scanning**: Dependabot alerts for vulnerable dependencies
- **SARIF Integration**: Results visible in GitHub Security tab

Current Security Status: [![Security Scan](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/workflows/Security%20Scan/badge.svg)](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/actions)

## Contact

- **Security Team**: security@sayvainc.com
- **General Issues**: [GitHub Issues](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GeeksikhSecurity/mcp-sentinel-scanner/discussions)

## License

This security policy is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

**Last Updated**: October 4, 2025
**Policy Version**: 1.0
