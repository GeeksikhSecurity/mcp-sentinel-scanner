# GitHub Teams Security Configuration Guide

Complete guide for configuring code scanning and security features after migrating to GitHub Teams.

## Overview

GitHub Teams provides enhanced security features beyond the free tier, including:
- **Code scanning** with CodeQL analysis
- **Secret scanning** for detecting exposed credentials
- **Dependency review** for pull requests
- **Security overview** dashboard
- **Organization-wide security policies**
- **Advanced security features** for private repositories

This guide covers setting up these features to complement your existing OpenSSF Scorecard implementation.

## GitHub Teams vs Free Tier

| Feature | GitHub Free | GitHub Teams |
|---------|-------------|--------------|
| Code scanning (public repos) | ✅ | ✅ |
| Code scanning (private repos) | ❌ | ✅ |
| Secret scanning (public repos) | ✅ (limited) | ✅ |
| Secret scanning (private repos) | ❌ | ✅ |
| Dependency review | ❌ | ✅ |
| Security overview | ❌ | ✅ |
| Custom retention periods | ❌ | ✅ |
| Protected branches (advanced) | ❌ | ✅ |

## Part 1: Default Setup for Code Scanning

GitHub offers two approaches to code scanning:
1. **Default setup** - Simplified, automatic configuration (recommended for most projects)
2. **Advanced setup** - Custom workflows (like our OpenSSF Scorecard)

### What is Default Setup?

Default setup automatically:
- Detects languages in your repository
- Configures CodeQL analysis
- Runs scans on relevant events (push, pull request, schedule)
- Uploads results to Security tab
- No workflow file required

**Supported Languages:**
- C/C++
- C#
- Go
- Java/Kotlin
- JavaScript/TypeScript
- Python
- Ruby
- Swift

### Enabling Default Setup (Repository Level)

#### Step 1: Navigate to Settings

1. Go to your repository
2. Click **Settings** tab
3. Select **Code security and analysis** (left sidebar)

#### Step 2: Enable Code Scanning

In the "Code scanning" section:

1. Click **Set up** → **Default**
2. Review the configuration:
   - **Languages**: Verify detected languages are correct
   - **Query suite**: Choose analysis depth
     - **Default** - Balanced security and performance (recommended)
     - **Extended** - More checks, longer runtime
     - **Security and quality** - Most comprehensive
   - **Events**: Configure when scans run
     - ✅ **On push** - Scan on commits to default branch
     - ✅ **On pull request** - Scan PRs before merge
     - ✅ **On schedule** - Weekly scans (recommended)

3. Click **Enable CodeQL**

#### Step 3: Verify Setup

After enabling:
- GitHub creates a configuration automatically
- First scan runs immediately
- Results appear in **Security** → **Code scanning** within 5-10 minutes

### Enabling Default Setup (Organization Level)

For organizations, enable default setup across all repositories:

#### Step 1: Organization Security Settings

1. Go to organization **Settings**
2. Select **Code security and analysis**
3. Scroll to **Code scanning**

#### Step 2: Configure Default Policy

1. Click **Configure default setup**
2. Select repositories:
   - **All repositories** - Apply to existing and future repos
   - **All repositories and future** - Automatic enrollment
   - **Select repositories** - Choose specific repos

3. Configure policy:
   ```yaml
   Languages: Auto-detect
   Query suite: Default
   Events:
     - Push to default branch
     - Pull requests
     - Weekly schedule
   ```

4. Click **Apply to X repositories**

#### Step 3: Monitor Rollout

- View progress in **Security** → **Overview**
- Check individual repositories for successful enablement
- Review any repositories that failed to enable (may need manual configuration)

### Default Setup vs Advanced Setup

You can use **both** approaches simultaneously:

| Setup Type | Use Case | Our Implementation |
|------------|----------|-------------------|
| **Default** | Automatic CodeQL for code quality | Enable for all repos |
| **Advanced** | Custom security tools | OpenSSF Scorecard (existing) |

**Recommendation**: Enable default setup for CodeQL analysis while keeping the OpenSSF Scorecard advanced workflow.

## Part 2: Secret Scanning Configuration

### Enable Secret Scanning (Repository)

1. Go to **Settings** → **Code security and analysis**
2. Find **Secret scanning** section
3. Click **Enable**
4. Configure options:
   - ✅ **Push protection** - Prevent secrets from being committed
   - ✅ **Validity checks** - Verify if exposed secrets are active
   - ✅ **Non-provider patterns** - Detect generic secrets

### Enable Secret Scanning (Organization)

1. Organization **Settings** → **Code security and analysis**
2. **Secret scanning** section
3. Click **Enable all** or configure per-repository
4. Set up **push protection** org-wide:
   - Prevents developers from pushing secrets
   - Shows alert before push completes
   - Requires bypass permission for exceptions

### Custom Secret Patterns (Optional)

Add organization-specific secret patterns:

1. Organization **Settings** → **Code security and analysis**
2. Scroll to **Custom patterns**
3. Click **New pattern**
4. Configure:
   - **Pattern name**: e.g., "Internal API Key"
   - **Secret format**: Regex pattern
   - **Test string**: Validate pattern
   - **Before pattern**: Context before secret (optional)
   - **After pattern**: Context after secret (optional)

Example pattern for custom API keys:
```regex
Pattern: [A-Z]{3}_[a-f0-9]{32}
Before: api_key\s*=\s*['"]?
After: ['"]?
```

## Part 3: Dependency Review

Enabled automatically with GitHub Teams for pull requests.

### How It Works

1. **Automatic**: Enabled on all PRs
2. **Analysis**: Compares dependencies between base and head
3. **Alerts**: Shows new vulnerabilities, license issues
4. **Blocking**: Optionally block PRs with critical issues

### Configure Dependency Review

Create `.github/dependency-review-config.yml`:

```yaml
# Dependency Review Configuration
fail-on-severity: moderate

# License restrictions
fail-on-licenses:
  - GPL-3.0
  - AGPL-3.0

# Package allow/deny lists
allow-dependencies-licenses:
  - MIT
  - Apache-2.0
  - BSD-3-Clause
  - ISC

# Vulnerability threshold
fail-on-scopes:
  - runtime
  - development

# Additional checks
check-licenses: true
check-vulnerabilities: true
```

### Add Dependency Review Workflow

Create `.github/workflows/dependency-review.yml`:

```yaml
name: Dependency Review

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
          fail-on-scopes: runtime
          comment-summary-in-pr: always
```

## Part 4: Security Overview Dashboard

Organization-level security visibility.

### Access Security Overview

1. Go to organization page
2. Click **Security** tab
3. View dashboard with:
   - **Overview**: Summary of security alerts across all repos
   - **Risk**: Repositories ranked by security issues
   - **Coverage**: Security feature adoption
   - **Alert trends**: Historical data

### Configure Security Policies

Create organization-wide security policy:

1. Create a `.github` repository in your organization
2. Add `SECURITY.md`:

```markdown
# Security Policy

## Reporting Security Issues

Please report security vulnerabilities to: security@yourorg.com

**Do not** open public issues for security vulnerabilities.

## Response Timeline

- Initial response: Within 24 hours
- Status update: Within 72 hours
- Resolution timeline: Varies by severity

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

This organization uses:
- Code scanning (CodeQL + OpenSSF Scorecard)
- Secret scanning with push protection
- Dependency review
- Dependabot security updates
```

3. This policy applies to all organization repositories

## Part 5: Integration with Existing OpenSSF Scorecard

Your existing Scorecard workflow complements GitHub Teams features:

### Current Security Stack

```
┌─────────────────────────────────────────┐
│     GitHub Teams Security Features      │
├─────────────────────────────────────────┤
│                                         │
│  ┌──────────────┐  ┌─────────────────┐ │
│  │   CodeQL     │  │  Secret Scan    │ │
│  │  (Default)   │  │  (Push Protect) │ │
│  └──────────────┘  └─────────────────┘ │
│                                         │
│  ┌──────────────┐  ┌─────────────────┐ │
│  │ Dependency   │  │   Dependabot    │ │
│  │   Review     │  │    Updates      │ │
│  └──────────────┘  └─────────────────┘ │
│                                         │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│       Custom Advanced Workflows         │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────────────────────┐   │
│  │    OpenSSF Scorecard            │   │
│  │  (Supply Chain Security)        │   │
│  │  ✅ Already Implemented         │   │
│  └─────────────────────────────────┘   │
│                                         │
└─────────────────────────────────────────┘
```

### Recommended Configuration

1. **Enable CodeQL default setup** - Automated code quality scanning
2. **Keep OpenSSF Scorecard** - Supply chain security assessment
3. **Enable secret scanning** - Prevent credential leaks
4. **Enable dependency review** - Catch vulnerable dependencies in PRs
5. **Keep Dependabot** - Automated dependency updates (already enabled)

### No Conflicts

These tools work together:
- **CodeQL**: Finds code vulnerabilities (SQL injection, XSS, etc.)
- **Scorecard**: Assesses security practices (branch protection, code review, etc.)
- **Secret scanning**: Detects exposed credentials
- **Dependency review**: Identifies vulnerable dependencies

All upload SARIF results to the same Security tab with different categories.

## Part 6: Branch Protection for Security

Enhance branch protection with security requirements:

### Configure Protected Branches

1. **Settings** → **Branches** → **Add rule**
2. Branch name pattern: `main`
3. Enable protections:

```yaml
Required status checks:
  ✅ Require status checks to pass before merging
  ✅ Require branches to be up to date
  Required checks:
    - CodeQL (if using default setup)
    - Scorecard analysis
    - Dependency Review
    - CI tests

Required reviews:
  ✅ Require pull request reviews before merging
  Required approving reviews: 1
  ✅ Dismiss stale reviews when new commits are pushed
  ✅ Require review from Code Owners

Additional protections:
  ✅ Require signed commits
  ✅ Require linear history
  ✅ Include administrators

  ❌ Allow force pushes
  ❌ Allow deletions
```

### Create CODEOWNERS

Define security review requirements in `.github/CODEOWNERS`:

```
# Security-related files require security team review
/SECURITY.md                @yourorg/security-team
/.github/workflows/*        @yourorg/security-team
/docs/security/*            @yourorg/security-team

# Dependency files require review
/package.json               @yourorg/security-team
/requirements.txt           @yourorg/security-team
/go.mod                     @yourorg/security-team

# All files default reviewers
*                           @yourorg/engineering
```

## Part 7: Complete Configuration Checklist

### Repository-Level Setup

- [ ] **Code scanning default setup enabled**
  - [ ] Languages detected correctly
  - [ ] Query suite selected (Default/Extended/Security)
  - [ ] Events configured (push, PR, schedule)
  - [ ] First scan completed successfully

- [ ] **Secret scanning enabled**
  - [ ] Push protection active
  - [ ] Validity checks enabled
  - [ ] Custom patterns added (if needed)

- [ ] **Dependabot configured**
  - [ ] Security updates enabled
  - [ ] Version updates configured
  - [ ] `.github/dependabot.yml` exists

- [ ] **OpenSSF Scorecard running**
  - [ ] Workflow permissions correct
  - [ ] Scheduled runs working
  - [ ] Results in Security tab

- [ ] **Branch protection configured**
  - [ ] Status checks required
  - [ ] Reviews required
  - [ ] Security checks enforced

### Organization-Level Setup

- [ ] **Default setup policy created**
  - [ ] Applied to all repositories
  - [ ] Auto-enrollment for new repos
  - [ ] Monitoring rollout status

- [ ] **Secret scanning org-wide**
  - [ ] Enabled for all repos
  - [ ] Push protection enforced
  - [ ] Custom patterns configured

- [ ] **Security policy published**
  - [ ] `.github` repo created
  - [ ] `SECURITY.md` added
  - [ ] Contact information current

- [ ] **Security overview configured**
  - [ ] Dashboard reviewed
  - [ ] Risk assessment completed
  - [ ] Coverage gaps identified

- [ ] **Team permissions reviewed**
  - [ ] Security team has appropriate access
  - [ ] Bypass permissions limited
  - [ ] Audit logs reviewed

## Part 8: Workflows to Add

### Recommended Additional Workflows

#### 1. CodeQL Advanced (if default setup insufficient)

`.github/workflows/codeql-analysis.yml`:

```yaml
name: CodeQL Advanced

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Monday 6 AM

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: ['python', 'javascript']

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended,security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

#### 2. Security Audit Workflow

`.github/workflows/security-audit.yml`:

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sundays
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Run npm audit
        if: hashFiles('package.json') != ''
        run: |
          npm audit --production --audit-level=moderate
        continue-on-error: true

      - name: Run pip safety check
        if: hashFiles('requirements.txt') != ''
        run: |
          pip install safety
          safety check --json
        continue-on-error: true

      - name: Generate report
        run: |
          echo "### 🔒 Security Audit Complete" >> $GITHUB_STEP_SUMMARY
          echo "Review findings in job logs" >> $GITHUB_STEP_SUMMARY
```

## Part 9: Monitoring and Maintenance

### Weekly Tasks

- [ ] Review Security Overview dashboard
- [ ] Check new CodeQL alerts
- [ ] Review secret scanning findings
- [ ] Verify all security workflows running

### Monthly Tasks

- [ ] Audit security feature coverage
- [ ] Review and update security policies
- [ ] Update custom secret patterns if needed
- [ ] Review branch protection effectiveness

### Quarterly Tasks

- [ ] Security posture assessment
- [ ] Review organization-wide trends
- [ ] Update security documentation
- [ ] Team security training review

## Part 10: Troubleshooting

### CodeQL Default Setup Not Available

**Issue**: "Default setup" option not showing

**Causes**:
1. Repository language not supported
2. GitHub Teams license not active
3. Organization settings restricting feature

**Solution**:
1. Verify supported languages in repo
2. Check organization billing status
3. Contact GitHub support if issue persists

### Secret Scanning Alerts Not Appearing

**Issue**: No alerts despite having secrets

**Causes**:
1. Secrets in patterns not recognized by GitHub
2. File excluded (e.g., in `.git`, `node_modules`)
3. Secret added before feature enabled (historical scan needed)

**Solution**:
1. Review supported secret patterns
2. Check file locations
3. Trigger historical scan in settings

### Dependency Review Not Blocking PRs

**Issue**: PRs merge despite vulnerable dependencies

**Causes**:
1. Workflow not configured
2. Branch protection not requiring check
3. Threshold set too high

**Solution**:
1. Add dependency-review workflow
2. Add to required checks in branch protection
3. Lower `fail-on-severity` threshold

## Part 11: Cost Optimization

### GitHub Teams Limits

- **Code scanning minutes**: Included in Teams plan
- **Storage**: SARIF results retention (configurable)
- **API rate limits**: Higher than free tier

### Optimization Tips

1. **Reduce scan frequency** for less active repos
   - Change schedule from daily to weekly
   - Disable on push for low-risk branches

2. **Optimize query suites**
   - Use "Default" instead of "Extended" for faster scans
   - Use "Security-only" for speed-critical scenarios

3. **Configure retention**
   - Reduce SARIF artifact retention to 5-7 days
   - Clean up old alerts regularly

## Resources

- **GitHub Docs**: https://docs.github.com/en/code-security
- **CodeQL**: https://codeql.github.com/
- **Secret Scanning**: https://docs.github.com/en/code-security/secret-scanning
- **Dependency Review**: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review
- **OpenSSF Scorecard**: See `SCORECARD_SETUP.md` in this repo
- **Security Best Practices**: https://docs.github.com/en/code-security/getting-started

## Support

For issues specific to:
- **OpenSSF Scorecard**: See `SCORECARD_SETUP.md` troubleshooting section
- **GitHub Teams features**: Contact GitHub Support
- **Organization setup**: Contact your GitHub organization admin

---

**Last Updated**: 2025-11-08
**GitHub Teams Plan**: Required for private repository features
**Complements**: Existing OpenSSF Scorecard implementation
