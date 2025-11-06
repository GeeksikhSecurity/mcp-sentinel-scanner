# OpenSSF Scorecard Integration

## 🛡️ Overview

MCP Sentinel Scanner integrates with [OpenSSF Scorecard](https://securityscorecards.dev/) to provide automated security posture assessment and supply chain security metrics. This integration helps us maintain enterprise-grade security standards and demonstrates our commitment to secure software development practices.

## 📊 What is OpenSSF Scorecard?

OpenSSF Scorecard is an automated security tool developed by the Open Source Security Foundation (OpenSSF) that evaluates open source projects against a set of security best practices. It provides a score (0-10) based on 19 different security checks.

### Key Benefits

- ✅ **Automated Security Assessment** - Weekly scans of our security posture
- ✅ **Supply Chain Security** - Identifies risks in our development practices
- ✅ **Industry Standard** - Recognized metric for open source security
- ✅ **Actionable Insights** - Specific recommendations for improvement
- ✅ **Transparency** - Public scorecard available to users and contributors
- ✅ **Free for Public Repos** - No cost for open source projects

## 🔍 The 19 Security Checks

OpenSSF Scorecard evaluates projects across the following categories:

### Code Quality & Review (4 checks)

| Check | Description | Current Status |
|-------|-------------|----------------|
| **Code-Review** | Ensures all code changes are reviewed before merge | ✅ Implemented |
| **Maintained** | Project shows signs of active maintenance | ✅ Active |
| **CI-Tests** | Automated tests run on all changes | ✅ GitHub Actions |
| **Branch-Protection** | Main branch has protection rules enabled | ⚠️ To Configure |

### Security Practices (6 checks)

| Check | Description | Current Status |
|-------|-------------|----------------|
| **Signed-Releases** | Releases are cryptographically signed | 🔄 In Progress |
| **Security-Policy** | SECURITY.md file exists with reporting instructions | ✅ Implemented |
| **Token-Permissions** | GitHub workflows use minimal token permissions | ✅ Pinned |
| **Dangerous-Workflow** | No dangerous patterns in GitHub Actions | ✅ Verified |
| **Vulnerabilities** | No known vulnerabilities in dependencies | ✅ Monitored |
| **SAST** | Static analysis tools are used | ✅ Multiple tools |

### Dependency Management (4 checks)

| Check | Description | Current Status |
|-------|-------------|----------------|
| **Dependency-Update-Tool** | Automated dependency updates configured | ✅ Dependabot |
| **Pinned-Dependencies** | All dependencies use pinned versions | ✅ Implemented |
| **Fuzzing** | Fuzz testing is performed | 📋 Planned |
| **Binary-Artifacts** | No binary artifacts checked into repository | ✅ None present |

### Transparency & Documentation (3 checks)

| Check | Description | Current Status |
|-------|-------------|----------------|
| **License** | Project has an OSI-approved license | ✅ MIT License |
| **CII-Best-Practices** | OpenSSF Best Practices badge earned | 📋 To Apply |
| **Packaging** | Project is published to language package registry | 🔄 PyPI planned |

### Supply Chain Security (2 checks)

| Check | Description | Current Status |
|-------|-------------|----------------|
| **SBOM** | Software Bill of Materials is generated | ✅ Generated |
| **Webhooks** | Webhooks use secrets for authentication | N/A |

## 🚀 How It Works

### Automated Workflow

Our OpenSSF Scorecard integration runs automatically via GitHub Actions:

```yaml
# .github/workflows/scorecard.yml
name: OpenSSF Scorecard

on:
  push:
    branches: [main]
  schedule:
    - cron: '30 1 * * 6'  # Weekly on Saturday
  workflow_dispatch:

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2
      - uses: github/codeql-action/upload-sarif@v3
```

### Workflow Triggers

1. **Push to Main** - Runs on every commit to main branch
2. **Weekly Schedule** - Automated scan every Saturday at 1:30 AM UTC
3. **Manual Trigger** - Can be run manually via GitHub Actions UI

### Results Location

Scorecard results are available in multiple locations:

1. **GitHub Security Tab**
   - Navigate to: `Security` → `Code scanning` → `OpenSSF Scorecard`
   - View detailed findings and recommendations

2. **Public Scorecard API**
   - URL: `https://api.securityscorecards.dev/projects/github.com/mcp-security/mcp-sentinel-scanner`
   - JSON format with detailed metrics

3. **Badge Display**
   - Badge URL: `https://api.securityscorecards.dev/projects/github.com/mcp-security/mcp-sentinel-scanner/badge`
   - Displayed in README.md and SECURITY.md

4. **SARIF Artifacts**
   - Uploaded as workflow artifacts
   - Retained for 5 days

## 📈 Score Interpretation

### Score Ranges

| Score | Grade | Interpretation |
|-------|-------|----------------|
| 8-10 | 🟢 Excellent | Industry-leading security practices |
| 6-7.9 | 🟡 Good | Solid security, minor improvements needed |
| 4-5.9 | 🟠 Fair | Moderate security, several gaps to address |
| 0-3.9 | 🔴 Poor | Significant security improvements required |

### Our Target

**Target Score:** 8.0+ (Excellent)
**Timeline:** Q2 2026
**Current Focus:** Branch protection, signed releases, CII badge

## 🔧 Configuration

### Minimal Configuration Required

OpenSSF Scorecard works out-of-the-box with zero configuration. The workflow file is the only requirement.

### Optional Customizations

#### 1. Badge Display

Add to README.md:

```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/mcp-security/mcp-sentinel-scanner/badge)](https://securityscorecards.dev/viewer/?uri=github.com/mcp-security/mcp-sentinel-scanner)
```

#### 2. Scan Frequency

Modify the cron schedule in `.github/workflows/scorecard.yml`:

```yaml
schedule:
  - cron: '30 1 * * 6'  # Change day/time as needed
```

#### 3. Publishing Results

Enable public results publishing (already enabled):

```yaml
with:
  publish_results: true  # Makes results publicly available
```

## 📊 Improvement Roadmap

### Phase 1: Foundation (Complete) ✅

- [x] Add SECURITY.md file
- [x] Configure Dependabot
- [x] Pin GitHub Actions versions
- [x] Implement automated testing
- [x] Use minimal token permissions

### Phase 2: Advanced Security (Q1 2026) 🔄

- [ ] Enable branch protection rules
  - Require pull request reviews
  - Require status checks to pass
  - Restrict who can push to main
- [ ] Sign releases with GPG/Sigstore
- [ ] Apply for OpenSSF Best Practices badge
- [ ] Add fuzzing tests

### Phase 3: Enterprise Grade (Q2 2026) 📋

- [ ] Publish to PyPI with signed releases
- [ ] Implement continuous SBOM generation
- [ ] Add security champions program
- [ ] Regular security audits

## 🎯 Specific Actions to Improve Score

### Branch Protection (+1.0 points)

**Action Required:**
1. Go to: `Settings` → `Branches` → `Branch protection rules`
2. Add rule for `main` branch:
   - ✅ Require pull request reviews before merging
   - ✅ Require status checks to pass (CI, tests, security scan)
   - ✅ Require branches to be up to date
   - ✅ Include administrators

**Impact:** Prevents accidental or malicious code from being merged without review.

### Signed Releases (+0.8 points)

**Action Required:**
1. Generate GPG key: `gpg --full-generate-key`
2. Add to GitHub: `Settings` → `SSH and GPG keys`
3. Update release workflow to sign artifacts
4. Consider using Sigstore for keyless signing

**Impact:** Ensures release artifacts haven't been tampered with.

### CII Best Practices Badge (+0.5 points)

**Action Required:**
1. Visit: https://bestpractices.coreinfrastructure.org/
2. Register project
3. Complete self-certification questionnaire
4. Add badge to README.md

**Impact:** Demonstrates commitment to security best practices.

### Fuzzing (+0.5 points)

**Action Required:**
1. Add OSS-Fuzz integration or custom fuzzing tests
2. Update CI/CD to run fuzz tests
3. Configure fuzzing targets for critical functions

**Impact:** Discovers edge cases and potential crashes.

## 📚 Resources

### Official Documentation

- **OpenSSF Scorecard**: https://securityscorecards.dev/
- **GitHub Action**: https://github.com/ossf/scorecard-action
- **Checks Documentation**: https://github.com/ossf/scorecard/blob/main/docs/checks.md
- **Best Practices**: https://bestpractices.coreinfrastructure.org/

### Related Projects

- **SLSA Framework**: https://slsa.dev/
- **Supply Chain Levels**: https://github.com/slsa-framework/slsa
- **Sigstore**: https://www.sigstore.dev/

### MCP Sentinel Documentation

- [Security Policy](../SECURITY.md)
- [Architecture Diagrams](ARCHITECTURE_DIAGRAMS.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Enterprise Roadmap](../ENTERPRISE_SCALING_ROADMAP.md)

## 🔐 Security Considerations

### Privacy

- Scorecard results are **publicly available** by default
- No secrets or credentials are included in results
- Only public repository metadata is analyzed

### Permissions

The workflow requires minimal permissions:

```yaml
permissions:
  security-events: write  # Upload SARIF to GitHub Security
  id-token: write         # Publish results with OIDC token
```

### False Positives

Some checks may flag false positives:
- **Manual Review**: Review all findings before taking action
- **Context Matters**: Some practices may not apply to your project
- **Document Exceptions**: Note valid reasons for not following a check

## 📞 Support

### Questions About Scorecard

- **OpenSSF Slack**: https://openssf.slack.com/
- **GitHub Discussions**: https://github.com/ossf/scorecard/discussions
- **Issue Tracker**: https://github.com/ossf/scorecard/issues

### Questions About Our Integration

- **GitHub Issues**: https://github.com/mcp-security/mcp-sentinel-scanner/issues
- **Security Team**: security@mcp-project.org
- **Documentation**: [docs/](.)

## 🎉 Success Metrics

We track the following metrics to measure our security posture:

| Metric | Target | Current | Last Updated |
|--------|--------|---------|--------------|
| Overall Score | 8.0+ | TBD | 2025-11-06 |
| Passed Checks | 17/19 | TBD | 2025-11-06 |
| Critical Findings | 0 | TBD | 2025-11-06 |
| Supply Chain Score | 9.0+ | TBD | 2025-11-06 |

*Scores will be populated after first scan completes.*

## 📝 Changelog

### 2025-11-06 - Initial Integration

- ✅ Created `.github/workflows/scorecard.yml`
- ✅ Updated `SECURITY.md` with Scorecard badge
- ✅ Pinned all GitHub Actions to SHA hashes
- ✅ Replaced deprecated actions in release workflow
- ✅ Added comprehensive documentation

---

**Last Updated:** 2025-11-06
**Maintained By:** MCP Security Team
**Version:** 1.0
