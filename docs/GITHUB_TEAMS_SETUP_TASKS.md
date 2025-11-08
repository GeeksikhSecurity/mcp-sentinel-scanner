# GitHub Teams Security Setup - Quick Tasks

Fast-track checklist for configuring GitHub Teams security features after migration.

## Quick Start (30 minutes)

Complete these tasks to activate all GitHub Teams security features.

---

## Phase 1: Enable Default Code Scanning (10 minutes)

### Repository-Level Setup

- [ ] **Navigate to repository Settings**
  - Click **Settings** tab
  - Select **Code security and analysis**

- [ ] **Enable Code Scanning - Default Setup**
  - Find "Code scanning" section
  - Click **Set up** → **Default**
  - Configure:
    - Languages: ✅ Auto-detected (verify Python, JavaScript, etc.)
    - Query suite: ✅ **Default** (recommended)
    - Events:
      - ✅ On push to default branch
      - ✅ On pull request
      - ✅ Weekly schedule
  - Click **Enable CodeQL**

- [ ] **Verify first scan**
  - Wait 5-10 minutes for initial scan
  - Go to **Security** → **Code scanning**
  - Confirm CodeQL results appear
  - Review any alerts

### Organization-Level Setup (If applicable)

- [ ] **Go to Organization Settings**
  - Organization page → **Settings**
  - Select **Code security and analysis**

- [ ] **Configure Default Setup Policy**
  - Scroll to "Code scanning"
  - Click **Configure default setup**
  - Select scope:
    - ✅ **All repositories** (recommended)
    - ✅ **Enable for future repositories**
  - Click **Apply to X repositories**

- [ ] **Monitor rollout**
  - Check **Security** → **Overview**
  - Verify success across repositories
  - Note any failures for manual review

---

## Phase 2: Enable Secret Scanning (5 minutes)

### Repository Level

- [ ] **Navigate to Security Settings**
  - **Settings** → **Code security and analysis**

- [ ] **Enable Secret Scanning**
  - Find "Secret scanning" section
  - Click **Enable**
  - Configure options:
    - ✅ **Push protection** (prevents secret commits)
    - ✅ **Validity checks** (verifies if secrets are active)
    - ✅ **Non-provider patterns** (generic secrets)

- [ ] **Review any detected secrets**
  - Go to **Security** → **Secret scanning**
  - Address any findings immediately
  - Revoke exposed credentials

### Organization Level

- [ ] **Enable for all repositories**
  - Organization **Settings** → **Code security and analysis**
  - Secret scanning section
  - Click **Enable all**

- [ ] **Configure push protection**
  - ✅ Enable **Push protection**
  - Set bypass permissions (admin only)
  - Document bypass procedures

- [ ] **Add custom secret patterns** (optional)
  - Scroll to "Custom patterns"
  - Click **New pattern**
  - Add organization-specific patterns
  - Test and save

---

## Phase 3: Configure Dependency Review (10 minutes)

### Create Configuration File

- [ ] **Create config file**
  - Path: `.github/dependency-review-config.yml`
  - Content:
```yaml
# Dependency Review Configuration
fail-on-severity: moderate

# License restrictions
fail-on-licenses:
  - GPL-3.0
  - AGPL-3.0

# Allowed licenses
allow-dependencies-licenses:
  - MIT
  - Apache-2.0
  - BSD-3-Clause
  - ISC

# Vulnerability checking
fail-on-scopes:
  - runtime
  - development

check-licenses: true
check-vulnerabilities: true
```

### Create Dependency Review Workflow

- [ ] **Create workflow file**
  - Path: `.github/workflows/dependency-review.yml`
  - Content:
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

- [ ] **Commit and push workflow**
```bash
git add .github/dependency-review-config.yml
git add .github/workflows/dependency-review.yml
git commit -m "feat: Add dependency review for PR security checks"
git push origin main
```

- [ ] **Test with a PR**
  - Create test PR with dependency change
  - Verify dependency review runs
  - Check PR comments for review summary

---

## Phase 4: Update Branch Protection (5 minutes)

### Configure Protected Branches

- [ ] **Navigate to Branch Settings**
  - **Settings** → **Branches**
  - Click **Add rule** (or edit existing)
  - Branch name pattern: `main`

- [ ] **Enable required status checks**
  - ✅ Require status checks to pass before merging
  - ✅ Require branches to be up to date before merging
  - Add required checks:
    - ✅ CodeQL (if using default setup)
    - ✅ Scorecard analysis
    - ✅ Dependency Review
    - ✅ CI/CD tests

- [ ] **Enable review requirements**
  - ✅ Require pull request reviews before merging
  - Required approving reviews: **1** (minimum)
  - ✅ Dismiss stale reviews when new commits are pushed
  - ✅ Require review from Code Owners

- [ ] **Additional protections**
  - ✅ Require signed commits
  - ✅ Require linear history
  - ✅ Include administrators
  - ❌ Allow force pushes (disabled)
  - ❌ Allow deletions (disabled)

- [ ] **Save protection rule**

### Create CODEOWNERS File (Optional)

- [ ] **Create CODEOWNERS**
  - Path: `.github/CODEOWNERS`
  - Content:
```
# Security-related files require security team review
/SECURITY.md                @yourorg/security-team
/.github/workflows/*        @yourorg/security-team
/docs/security/*            @yourorg/security-team

# Dependency files require review
/package.json               @yourorg/security-team
/requirements.txt           @yourorg/security-team
/go.mod                     @yourorg/security-team

# Default reviewers
*                           @yourorg/engineering
```

- [ ] **Commit CODEOWNERS**
```bash
git add .github/CODEOWNERS
git commit -m "chore: Add CODEOWNERS for security-sensitive files"
git push origin main
```

---

## Phase 5: Verify Integration with OpenSSF Scorecard

### Confirm No Conflicts

- [ ] **Check existing Scorecard workflow**
  - Path: `.github/workflows/scorecard.yml`
  - Verify permissions are correct:
```yaml
permissions:
  security-events: write
  id-token: write
  contents: read
  actions: read
```

- [ ] **Verify all tools upload SARIF correctly**
  - Go to **Security** → **Code scanning**
  - Confirm you see:
    - ✅ CodeQL results (category: codeql)
    - ✅ Scorecard results (category: ossf-scorecard)
    - ✅ Any other security tools

- [ ] **Check SARIF categories don't conflict**
  - Each tool should have unique category
  - No duplicate uploads
  - All results visible in Security tab

### Security Stack Overview

Your complete security stack should now include:

```
GitHub Teams Features (Default):
├── CodeQL (code vulnerabilities)
├── Secret Scanning (credential exposure)
├── Dependency Review (vulnerable dependencies)
└── Dependabot (automated updates)

Advanced Workflows (Custom):
└── OpenSSF Scorecard (supply chain security)
```

- [ ] **Confirm all features active**

---

## Phase 6: Create Organization Security Policy

### Create .github Repository (Organization)

- [ ] **Create special `.github` repository**
  - Organization level repository
  - Name exactly: `.github`
  - Public or internal visibility

- [ ] **Add SECURITY.md**
  - Path: `SECURITY.md`
  - Content:
```markdown
# Security Policy

## Reporting Security Issues

Please report security vulnerabilities to: security@yourorganization.com

**Do not** open public issues for security vulnerabilities.

### Response Timeline

- Initial response: Within 24 hours
- Status update: Within 72 hours
- Resolution timeline: Varies by severity (High: 7 days, Medium: 30 days)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | ✅                |
| < 1.0   | ❌                |

## Security Features

This organization uses:
- ✅ Code scanning (CodeQL)
- ✅ Secret scanning with push protection
- ✅ Dependency review
- ✅ Dependabot security updates
- ✅ OpenSSF Scorecard analysis
- ✅ Branch protection rules
```

- [ ] **This policy now applies to all org repositories**

---

## Verification Checklist

### Test Each Feature

- [ ] **CodeQL Default Setup**
  - Trigger: Push to main or create PR
  - Expected: Scan runs, results in Security tab
  - Location: **Security** → **Code scanning** → Filter by "CodeQL"

- [ ] **Secret Scanning**
  - Test: Try to commit a test secret (AWS key format)
  - Expected: Push blocked with alert
  - Verify: Alert appears in **Security** → **Secret scanning**

- [ ] **Dependency Review**
  - Test: Create PR adding dependency with known CVE
  - Expected: PR shows warning, review comments added
  - Location: PR checks and comments

- [ ] **OpenSSF Scorecard**
  - Test: Trigger workflow manually or wait for schedule
  - Expected: Workflow completes, results uploaded
  - Location: **Security** → **Code scanning** → Filter by "ossf-scorecard"

- [ ] **Branch Protection**
  - Test: Try to push directly to main
  - Expected: Push rejected (if you don't have bypass permission)
  - Test: Create PR without required checks passing
  - Expected: Merge blocked until checks pass

---

## Dashboard Review

### Security Overview (Organization)

- [ ] **Access Security Overview**
  - Organization page → **Security** tab
  - Review dashboard sections

- [ ] **Check Coverage**
  - **Overview**: Security alerts summary
  - **Risk**: High-risk repositories
  - **Coverage**: Feature adoption percentage
  - **Alert trends**: Historical security data

- [ ] **Identify Gaps**
  - List repositories without code scanning
  - List repositories without secret scanning
  - Prioritize enabling features

### Repository Security Tab

- [ ] **Review Security Tab**
  - Repository → **Security** tab
  - Check sections:
    - ✅ Security policy (links to SECURITY.md)
    - ✅ Security advisories (if any)
    - ✅ Dependabot alerts
    - ✅ Code scanning alerts
    - ✅ Secret scanning alerts

---

## Post-Setup Maintenance

### Daily (Automated)

- [ ] **Set up notifications**
  - **Settings** → **Notifications** → **Security alerts**
  - ✅ Email notifications for:
    - New vulnerabilities
    - Secret scanning alerts
    - Failed security workflows

### Weekly Review

- [ ] **Review new alerts**
  - CodeQL findings
  - Secret scanning detections
  - Dependabot updates
  - Scorecard score changes

- [ ] **Check workflow status**
  - All security workflows running successfully
  - No failed scans
  - Scheduled jobs executing

### Monthly Review

- [ ] **Audit security posture**
  - Review Security Overview dashboard
  - Check coverage across all repositories
  - Update security policies if needed

- [ ] **Review and update**
  - Custom secret patterns
  - Dependency review configuration
  - Branch protection rules
  - CODEOWNERS assignments

### Quarterly Assessment

- [ ] **Security posture report**
  - Overall score trends
  - Alert resolution time
  - Coverage improvement
  - Team compliance

- [ ] **Policy updates**
  - Review SECURITY.md
  - Update supported versions
  - Refresh contact information
  - Document new procedures

---

## Troubleshooting Quick Reference

### Issue: "Default setup not available"

**Quick Fix:**
- Verify GitHub Teams license is active
- Check if repo language is supported (Python, JS, Java, Go, C++, C#, Ruby, Swift)
- Try using Advanced setup instead

### Issue: "Secret scanning not detecting secrets"

**Quick Fix:**
- Check if file is in excluded path (`.git/`, `node_modules/`)
- Verify secret matches GitHub's patterns
- Run historical scan: **Settings** → **Code security** → **Secret scanning** → **Run historical scan**

### Issue: "Dependency Review not blocking PRs"

**Quick Fix:**
- Verify workflow file exists: `.github/workflows/dependency-review.yml`
- Check branch protection requires this check
- Ensure `fail-on-severity` threshold is appropriate

### Issue: "Multiple SARIF uploads conflicting"

**Quick Fix:**
- Check each workflow uses unique `category`:
  - CodeQL: `category: codeql`
  - Scorecard: `category: ossf-scorecard`
  - Custom tools: `category: custom-tool-name`

---

## Success Criteria

You've successfully configured GitHub Teams security when:

✅ **Code scanning default setup enabled** and running on schedule
✅ **Secret scanning active** with push protection enforcing
✅ **Dependency review** commenting on PRs
✅ **Branch protection** enforcing security checks
✅ **OpenSSF Scorecard** still running (no conflicts)
✅ **Security Overview** dashboard shows full coverage
✅ **SECURITY.md** published org-wide
✅ **Team notified** of new security features
✅ **All workflows** green in Actions tab

---

## Resources

- **Full Guide**: See `GITHUB_TEAMS_SECURITY_SETUP.md`
- **Scorecard Setup**: See `SCORECARD_SETUP.md`
- **GitHub Docs**: https://docs.github.com/en/code-security
- **Support**: https://support.github.com/

---

**Estimated Time**: 30-45 minutes for full setup
**Skill Level**: Intermediate
**GitHub Plan Required**: GitHub Teams or higher
**Maintains Compatibility**: With existing OpenSSF Scorecard

Last Updated: 2025-11-08
