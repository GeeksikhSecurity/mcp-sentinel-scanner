# OpenSSF Scorecard Implementation Tasks

Quick reference checklist for implementing OpenSSF Scorecard based on successful deployment in mcp-sentinel-scanner.

## Pre-Implementation (5 minutes)

- [ ] **Verify GitHub Actions is enabled** in repository settings
- [ ] **Check permissions** - You need admin or write access
- [ ] **Decide visibility** - Will scorecard results be public or private?
- [ ] **Review current security posture** - Note areas for improvement

## Core Implementation (15 minutes)

### Task 1: Create Workflow Directory
```bash
mkdir -p .github/workflows
```

### Task 2: Create Scorecard Workflow File

**File**: `.github/workflows/scorecard.yml`

```yaml
name: OpenSSF Scorecard

on:
  push:
    branches: [main]
  schedule:
    - cron: '30 1 * * 6'  # Weekly on Saturdays
  workflow_dispatch:

permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read      # ⚠️ CRITICAL: Do NOT comment out
      actions: read       # ⚠️ CRITICAL: Do NOT comment out

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run analysis
        uses: ossf/scorecard-action@62b2cac7ed8198b15735ed49ab1e5cf35480ba46
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true  # Set to false for private repos

      - name: Upload SARIF results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ossf-scorecard

      - name: Upload SARIF results as artifact
        uses: actions/upload-artifact@v4
        with:
          name: SARIF file
          path: results.sarif
          retention-days: 5

      - name: Generate summary
        if: always()
        run: |
          echo "### 🛡️ OpenSSF Scorecard Analysis Complete" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "The security scorecard has been generated and uploaded to:" >> $GITHUB_STEP_SUMMARY
          echo "- **Security** tab → **Code scanning** → **OpenSSF Scorecard**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "📊 View detailed results: https://api.securityscorecards.dev/projects/github.com/${{ github.repository }}" >> $GITHUB_STEP_SUMMARY
```

- [ ] **File created** at `.github/workflows/scorecard.yml`
- [ ] **Permissions verified** - `contents: read` and `actions: read` are NOT commented
- [ ] **publish_results configured** - Set appropriately for repo visibility

### Task 3: Enable Code Scanning

- [ ] Navigate to **Settings** → **Code security and analysis**
- [ ] Click **Enable** for **Code scanning** (if not already enabled)
- [ ] Confirm setup is complete

### Task 4: Commit and Push

```bash
git add .github/workflows/scorecard.yml
git commit -m "feat: Add OpenSSF Scorecard security analysis"
git push origin main
```

- [ ] **Changes committed**
- [ ] **Changes pushed** to main branch

## Verification (10 minutes)

### Task 5: Manual Test Run

- [ ] Go to repository **Actions** tab
- [ ] Select **OpenSSF Scorecard** workflow
- [ ] Click **Run workflow** → **Run workflow**
- [ ] Wait for completion (typically 2-5 minutes)
- [ ] Verify workflow completes with green checkmark

### Task 6: Verify Results

- [ ] Navigate to **Security** → **Code scanning**
- [ ] Confirm **OpenSSF Scorecard** alerts are visible
- [ ] Click on alerts to view details
- [ ] Review recommendations

### Task 7: Check Public Scorecard (Public Repos Only)

- [ ] Visit `https://api.securityscorecards.dev/projects/github.com/YOUR_ORG/YOUR_REPO`
- [ ] Verify scorecard is accessible
- [ ] Note overall score and individual check scores
- [ ] Bookmark for future reference

## Troubleshooting Checklist

If workflow fails, check these in order:

### Error: "repository not found" or Git exit code 128

- [ ] **Verify** `contents: read` is set and NOT commented out
- [ ] **Verify** `actions: read` is set and NOT commented out
- [ ] **Check** workflow permissions section looks like this:
```yaml
permissions:
  security-events: write
  id-token: write
  contents: read      # ✅ Must be uncommented
  actions: read       # ✅ Must be uncommented
```

### Error: "Resource not accessible by integration"

- [ ] **Verify** `security-events: write` permission is set
- [ ] **Check** Code Scanning is enabled in Settings
- [ ] **Confirm** GitHub Actions has necessary permissions

### No Results in Security Tab

- [ ] **Verify** SARIF upload step completed successfully
- [ ] **Check** Code Scanning is enabled in repository settings
- [ ] **Review** workflow logs for errors in upload-sarif step
- [ ] **Wait** 5-10 minutes for results to appear

### Badge Not Showing (Public Repos)

- [ ] **Confirm** `publish_results: true` is set
- [ ] **Verify** workflow completed successfully
- [ ] **Wait** 24 hours for public scorecard to update
- [ ] **Check** scorecard API endpoint is accessible

## Post-Implementation (Ongoing)

### Week 1: Initial Review
- [ ] **Review all scorecard findings**
- [ ] **Prioritize** security improvements
- [ ] **Create issues** for actionable items
- [ ] **Document** baseline score

### Month 1: First Improvements
- [ ] **Address** high-priority recommendations
- [ ] **Implement** quick wins (e.g., add SECURITY.md, LICENSE)
- [ ] **Enable** additional security features (Dependabot, branch protection)
- [ ] **Re-run** scorecard and compare scores

### Quarterly: Ongoing Monitoring
- [ ] **Review** weekly scorecard results
- [ ] **Track** score trends over time
- [ ] **Update** security policies as needed
- [ ] **Celebrate** improvements with team

## Optional Enhancements

### Add Branch Protection Requirement
- [ ] Go to **Settings** → **Branches**
- [ ] Edit protection rules for `main`
- [ ] Enable "Require status checks to pass"
- [ ] Add **Scorecard analysis** to required checks

### Add Badge to README (Public Repos)
```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/YOUR_ORG/YOUR_REPO/badge)](https://api.securityscorecards.dev/projects/github.com/YOUR_ORG/YOUR_REPO)
```
- [ ] **Badge added** to README.md
- [ ] **Badge verified** displays correctly

### Customize Schedule
- [ ] **Decide** on run frequency
- [ ] **Update** cron expression in workflow
- [ ] **Test** new schedule

### Integration with CI/CD
- [ ] **Add** scorecard check to pull request workflow
- [ ] **Set** minimum score requirements
- [ ] **Block** merges below threshold (optional)

## Success Metrics

Track these metrics to measure success:

| Metric | Target | Current | Date |
|--------|--------|---------|------|
| Overall Score | ≥ 7.0 | ___ | ___ |
| Critical Checks Passing | 100% | ___ | ___ |
| High Priority Issues | 0 | ___ | ___ |
| Workflow Success Rate | 100% | ___ | ___ |
| Time to Remediate | < 7 days | ___ | ___ |

## Quick Reference: Common Commands

```bash
# View workflow runs
gh run list --workflow=scorecard.yml

# Trigger manual run
gh workflow run scorecard.yml

# View latest run logs
gh run view --log

# Download SARIF results
gh run download <run-id> --name "SARIF file"

# Check workflow status
gh run watch
```

## Critical Permissions Summary

**DO NOT FORGET THESE PERMISSIONS:**

```yaml
permissions:
  security-events: write  # Upload to Security tab
  id-token: write         # Publish results & badge
  contents: read          # ⚠️ ALWAYS REQUIRED - access repo contents
  actions: read           # ⚠️ ALWAYS REQUIRED - analyze workflows
```

The `contents: read` and `actions: read` permissions are required for **both public AND private repositories**. This is the most common mistake that causes "repository not found" errors.

## Support Resources

- **Full Documentation**: See `SCORECARD_SETUP.md` for detailed guide
- **Scorecard Docs**: https://scorecard.dev/
- **GitHub Actions**: https://docs.github.com/en/actions
- **SARIF Format**: https://sarifweb.azurewebsites.net/
- **Security Best Practices**: https://openssf.org/

## Issue Resolution

Encountered a problem not listed here?

1. **Check workflow logs** in Actions tab
2. **Review permissions** carefully
3. **Consult** `SCORECARD_SETUP.md` troubleshooting section
4. **Search** GitHub issues: https://github.com/ossf/scorecard-action/issues
5. **Report** new issues to project maintainers

---

**Quick Start Time**: ~30 minutes
**Skill Level**: Beginner-friendly
**Based On**: Successful implementation in mcp-sentinel-scanner
**Last Updated**: 2025-11-08
