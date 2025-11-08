# OpenSSF Scorecard Implementation Guide

This guide provides step-by-step instructions for implementing OpenSSF Scorecard in your GitHub repository, based on successful deployment in mcp-sentinel-scanner.

## Overview

OpenSSF Scorecard is an automated tool that assesses open source projects for security risks. It provides a score for various security practices and helps identify areas for improvement.

## Prerequisites

- GitHub repository (public or private)
- GitHub Actions enabled
- Admin or write access to repository settings

## Implementation Tasks

### 1. Create the Scorecard Workflow

**File**: `.github/workflows/scorecard.yml`

Create a new workflow file with the following structure:

```yaml
name: OpenSSF Scorecard

on:
  # Run on pushes to main branch
  push:
    branches: [main]
  # Run weekly on Saturdays at 1:30 AM UTC
  schedule:
    - cron: '30 1 * * 6'
  # Allow manual trigger
  workflow_dispatch:

# Declare default permissions as read only
permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    permissions:
      # Needed to upload the results to code-scanning dashboard
      security-events: write
      # Needed to publish results and get a badge
      id-token: write
      # CRITICAL: Required for both public AND private repositories
      contents: read
      actions: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run analysis
        uses: ossf/scorecard-action@62b2cac7ed8198b15735ed49ab1e5cf35480ba46 # v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          # Set to true for public repositories
          publish_results: true

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
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "🔗 Scorecard documentation: https://scorecard.dev/" >> $GITHUB_STEP_SUMMARY
```

### 2. Critical Configuration Points

#### ⚠️ COMMON PITFALL: Missing Permissions

**Problem**: The workflow fails with errors like:
- `repository 'https://github.com/org/repo/' not found`
- `The process '/usr/bin/git' failed with exit code 128`

**Solution**: Ensure these permissions are **NOT commented out**:

```yaml
permissions:
  security-events: write  # For uploading to Security tab
  id-token: write         # For publishing results
  contents: read          # ✅ REQUIRED - Do not comment out
  actions: read           # ✅ REQUIRED - Do not comment out
```

The `contents: read` and `actions: read` permissions are required for **both public and private repositories**, contrary to what some documentation suggests.

#### Private Repository Considerations

For private repositories:
1. **DO NOT** set `publish_results: true` (set to `false` or remove)
2. Results will only be visible in your Security tab
3. No public scorecard badge will be generated

### 3. Enable Code Scanning (First-Time Setup)

If this is your first code scanning workflow:

1. Go to repository **Settings** → **Code security and analysis**
2. Enable **Code scanning**
3. The Scorecard workflow will automatically upload results once enabled

### 4. Verify Installation

#### Manual Trigger
1. Go to **Actions** tab
2. Select **OpenSSF Scorecard** workflow
3. Click **Run workflow** → **Run workflow**

#### Check Results
After the workflow completes:
1. Navigate to **Security** → **Code scanning**
2. Look for alerts categorized as **ossf-scorecard**
3. View detailed analysis and recommendations

#### Public Scorecard (Public Repos Only)
- Visit: `https://api.securityscorecards.dev/projects/github.com/YOUR_ORG/YOUR_REPO`
- View comprehensive security score breakdown

### 5. Customize Schedule (Optional)

Default schedule runs weekly on Saturdays at 1:30 AM UTC:
```yaml
schedule:
  - cron: '30 1 * * 6'
```

Modify the cron expression as needed:
- Daily at midnight: `'0 0 * * *'`
- Bi-weekly: `'0 0 1,15 * *'`
- Monthly: `'0 0 1 * *'`

### 6. Integration with Branch Protection

Add Scorecard as a required check:
1. Go to **Settings** → **Branches**
2. Edit branch protection rules for `main`
3. Enable "Require status checks to pass before merging"
4. Add **Scorecard analysis** to required checks

## Troubleshooting

### Error: "repository not found"

**Cause**: Missing `contents: read` or `actions: read` permissions

**Fix**: Uncomment these permissions in the workflow file:
```yaml
permissions:
  contents: read
  actions: read
```

### Error: "Resource not accessible by integration"

**Cause**: Missing `security-events: write` permission

**Fix**: Ensure permission is set:
```yaml
permissions:
  security-events: write
```

### No Results in Security Tab

**Causes**:
1. Code scanning not enabled in repository settings
2. SARIF upload failed
3. Workflow permissions insufficient

**Fix**:
1. Check **Settings** → **Code security and analysis**
2. Review workflow logs for upload errors
3. Verify all permissions are correctly set

### Badge Not Showing (Public Repos)

**Cause**: `publish_results` is set to `false` or workflow hasn't run successfully

**Fix**:
1. Set `publish_results: true` in workflow
2. Ensure workflow completes successfully
3. Wait 24 hours for badge to appear

## Best Practices

### Security
- ✅ Use pinned action versions with SHA hashes
- ✅ Set `persist-credentials: false` in checkout step
- ✅ Use minimal required permissions
- ✅ Review scorecard recommendations regularly

### Maintenance
- 📅 Schedule weekly runs to track security posture over time
- 🔄 Update scorecard-action to latest versions
- 📊 Monitor trends in your security score
- 🎯 Set goals for improving specific checks

### Workflow Integration
- Combine with Dependabot for dependency updates
- Integrate with security scanning tools (CodeQL, Trivy)
- Add to CI/CD pipeline for continuous monitoring
- Use branch protection to enforce minimum scores

## Scorecard Checks Overview

The Scorecard evaluates projects on:

| Check | Description |
|-------|-------------|
| **Binary-Artifacts** | No checked-in binaries |
| **Branch-Protection** | Branch protection rules enabled |
| **CI-Tests** | Runs tests in CI |
| **CII-Best-Practices** | Has CII Best Practices badge |
| **Code-Review** | Code review before merge |
| **Contributors** | Multiple contributors |
| **Dangerous-Workflow** | No dangerous workflow patterns |
| **Dependency-Update-Tool** | Uses dependency update tools |
| **Fuzzing** | Implements fuzzing |
| **License** | Has license file |
| **Maintained** | Active maintenance |
| **Packaging** | Published as package |
| **Pinned-Dependencies** | Dependencies pinned |
| **SAST** | Uses SAST tools |
| **Security-Policy** | Has SECURITY.md |
| **Signed-Releases** | Releases are signed |
| **Token-Permissions** | Minimal token permissions |
| **Vulnerabilities** | No known vulnerabilities |
| **Webhooks** | Secure webhook configuration |

## Resources

- **Official Documentation**: https://scorecard.dev/
- **Action Repository**: https://github.com/ossf/scorecard-action
- **Scorecard Checks**: https://github.com/ossf/scorecard/blob/main/docs/checks.md
- **SARIF Specification**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- **OpenSSF Project**: https://openssf.org/

## Example Implementations

### Minimal Configuration (Quick Start)
```yaml
name: Scorecard
on:
  workflow_dispatch:
permissions: read-all

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Advanced Configuration (With Notifications)
```yaml
name: Scorecard
on:
  push:
    branches: [main]
  schedule:
    - cron: '30 1 * * 6'

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
      actions: read

    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Scorecard
        uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload to Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload Artifact
        uses: actions/upload-artifact@v4
        with:
          name: scorecard-results
          path: results.sarif

      - name: Notify on Failure
        if: failure()
        run: |
          echo "::error::Scorecard analysis failed"
```

## Checklist for New Implementation

- [ ] Create `.github/workflows/scorecard.yml`
- [ ] Set all required permissions (especially `contents: read` and `actions: read`)
- [ ] Configure `publish_results` based on repository visibility
- [ ] Enable Code Scanning in repository settings
- [ ] Run workflow manually to verify setup
- [ ] Check results in Security tab
- [ ] Review and address scorecard recommendations
- [ ] Set up scheduled runs (weekly recommended)
- [ ] Document scorecard score goals for your project
- [ ] Integrate with branch protection (optional)
- [ ] Add scorecard badge to README (public repos only)

## Success Criteria

✅ Workflow runs without errors
✅ SARIF results uploaded to Security tab
✅ Scorecard alerts visible in Code Scanning
✅ Public scorecard accessible (if public repo)
✅ Regular scheduled runs completing successfully
✅ Team reviewing and acting on recommendations

## Lessons Learned from mcp-sentinel-scanner

1. **Always enable `contents: read` and `actions: read`** - Even if documentation says they're only for private repos
2. **Test with manual trigger first** - Don't wait for scheduled run or push to main
3. **Check permissions carefully** - Most failures are permission-related
4. **Review logs thoroughly** - Error messages clearly indicate permission issues
5. **Enable Code Scanning early** - Do this before first workflow run

---

**Last Updated**: Based on successful implementation in mcp-sentinel-scanner (2025-11-08)
**Scorecard Action Version**: v2.4.0
**Tested On**: GitHub-hosted runners (ubuntu-latest)
