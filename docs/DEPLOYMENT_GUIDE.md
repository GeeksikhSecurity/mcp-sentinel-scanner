# MCP Sentinel Scanner - Deployment Guide

**Version:** 1.5
**Last Updated:** October 4, 2025

This guide covers deploying MCP Sentinel Scanner in various environments:
- 🐳 Docker (local and production)
- 🔄 GitHub Actions
- 🔨 Jenkins
- 🌊 Bitbucket Pipelines
- 💻 Local development

📊 **[View Interactive Infographic](INFOGRAPHIC.html)** for visual deployment workflows and architecture diagrams.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [GitHub Actions](#github-actions)
4. [Jenkins Integration](#jenkins-integration)
5. [Bitbucket Pipelines](#bitbucket-pipelines)
6. [Local Development](#local-development)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

- Python 3.9+ (for local/manual deployment)
- Docker (for containerized deployment)
- Git

### Fastest Way to Scan

```bash
# Using Docker (recommended)
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest
docker run -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# Using pip
pip install mcp-sentinel-scanner
mcp-scan /path/to/code

# From source
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner
pip install -r requirements.txt
python -m scripts.sentinel_cli /path/to/code
```

---

## Docker Deployment

### Option 1: Pre-built Image (Recommended)

```bash
# Pull latest image
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest

# Basic scan
docker run --rm -v $(pwd):/scan \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan

# Scan with HTML report
docker run --rm -v $(pwd):/scan \
  -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format html -o /reports/security-report.html

# Scan with SARIF for GitHub
docker run --rm -v $(pwd):/scan \
  -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format sarif -o /reports/results.sarif
```

### Option 2: Build Your Own Image

```bash
# Clone repository
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner

# Build image
docker build -t mcp-sentinel-scanner:local .

# Run scan
docker run --rm -v $(pwd):/scan mcp-sentinel-scanner:local /scan
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mcp-scanner:
    image: ghcr.io/mcp-security/mcp-sentinel-scanner:latest
    volumes:
      - ./:/scan:ro
      - ./reports:/reports
    command: >
      /scan
      --format html
      -o /reports/security-report.html
      --severity HIGH
    environment:
      - PYTHONUNBUFFERED=1
```

Run with:
```bash
docker-compose up
```

### Advanced Docker Usage

**Scan specific directory with exclusions:**
```bash
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan/src \
  --exclude "*.d.ts" "node_modules" "dist" \
  --format json \
  -o /reports/scan-results.json
```

**Scan with custom config:**
```bash
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/config.json:/config/config.json:ro \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan \
  --config /config/config.json
```

**Multi-format output:**
```bash
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  bash -c "
    mcp-scan /scan --format json -o /reports/scan.json && \
    mcp-scan /scan --format html -o /reports/scan.html && \
    mcp-scan /scan --format sarif -o /reports/scan.sarif
  "
```

---

## GitHub Actions

### Option 1: Using GitHub Action (Recommended)

Create `.github/workflows/security-scan.yml`:

```yaml
name: MCP Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  security-scan:
    name: MCP Sentinel Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run MCP Sentinel Scanner
        uses: mcp-security/mcp-sentinel-scanner-action@v1
        with:
          path: '.'
          format: 'sarif'
          severity: 'HIGH'
          fail-on-critical: true

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload HTML Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-report.html
```

### Option 2: Using Docker in GitHub Actions

```yaml
name: MCP Security Scan (Docker)

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run security scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
            /scan \
            --format sarif \
            -o /reports/results.sarif \
            --severity HIGH

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: reports/results.sarif

      - name: Generate HTML report
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
            /scan \
            --format html \
            -o /reports/security-report.html

      - name: Upload HTML Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: reports/security-report.html
```

### Option 3: Manual Setup with Python

```yaml
name: MCP Security Scan (Python)

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install MCP Sentinel Scanner
        run: |
          pip install mcp-sentinel-scanner

      - name: Run scan
        run: |
          mcp-scan . \
            --format sarif \
            -o results.sarif \
            --severity HIGH

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### Advanced GitHub Actions Examples

**Fail build on critical vulnerabilities:**
```yaml
- name: Run scan and fail on critical
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/scan \
      ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
      /scan \
      --severity CRITICAL \
      --format json \
      -o /scan/results.json

    # Parse results and fail if critical found
    CRITICAL_COUNT=$(jq '.scan_summary.severity_distribution.CRITICAL // 0' results.json)
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
      echo "❌ Found $CRITICAL_COUNT critical vulnerabilities!"
      exit 1
    fi
```

**Post results as PR comment:**
```yaml
- name: Generate report and comment on PR
  if: github.event_name == 'pull_request'
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/scan \
      ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
      /scan \
      --format markdown \
      -o /scan/report.md

    gh pr comment ${{ github.event.pull_request.number }} \
      --body-file report.md
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Jenkins Integration

### Jenkinsfile (Declarative)

```groovy
pipeline {
    agent any

    environment {
        SCANNER_IMAGE = 'ghcr.io/mcp-security/mcp-sentinel-scanner:latest'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    docker.image(env.SCANNER_IMAGE).inside('-v ${WORKSPACE}:/scan') {
                        sh '''
                            python -m scripts.sentinel_cli /scan \
                                --format json \
                                -o /scan/reports/security-scan.json \
                                --format html \
                                -o /scan/reports/security-scan.html
                        '''
                    }
                }
            }
        }

        stage('Publish Reports') {
            steps {
                publishHTML([
                    reportDir: 'reports',
                    reportFiles: 'security-scan.html',
                    reportName: 'MCP Security Report'
                ])

                archiveArtifacts artifacts: 'reports/**', fingerprint: true
            }
        }

        stage('Check Vulnerabilities') {
            steps {
                script {
                    def scanResults = readJSON file: 'reports/security-scan.json'
                    def criticalCount = scanResults.scan_summary.severity_distribution.CRITICAL ?: 0

                    if (criticalCount > 0) {
                        error("Found ${criticalCount} critical vulnerabilities!")
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
```

### Jenkinsfile (Scripted)

```groovy
node {
    def scannerImage = 'ghcr.io/mcp-security/mcp-sentinel-scanner:latest'

    try {
        stage('Checkout') {
            checkout scm
        }

        stage('Run Security Scan') {
            docker.image(scannerImage).inside('-v ${WORKSPACE}:/scan') {
                sh '''
                    mcp-scan /scan \
                        --format json -o /scan/scan-results.json \
                        --format html -o /scan/scan-report.html \
                        --format sarif -o /scan/scan-results.sarif
                '''
            }
        }

        stage('Analyze Results') {
            def results = readJSON file: 'scan-results.json'
            def vulnCount = results.scan_summary.vulnerabilities_found

            echo "Total vulnerabilities found: ${vulnCount}"

            // Fail if critical vulnerabilities found
            if (results.scan_summary.severity_distribution.CRITICAL > 0) {
                currentBuild.result = 'FAILURE'
                error('Critical vulnerabilities detected!')
            }
        }

        stage('Publish Reports') {
            publishHTML([
                reportDir: '.',
                reportFiles: 'scan-report.html',
                reportName: 'Security Scan Report'
            ])

            archiveArtifacts artifacts: '*.json,*.html,*.sarif'
        }

    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        throw e
    } finally {
        cleanWs()
    }
}
```

### Jenkins Freestyle Project

1. **Source Code Management:** Configure your Git repository
2. **Build Environment:** Enable "Build inside a Docker container"
   - Docker image: `ghcr.io/mcp-security/mcp-sentinel-scanner:latest`
3. **Build Steps:** Add "Execute shell"
   ```bash
   mcp-scan ${WORKSPACE} \
     --format json -o scan-results.json \
     --format html -o scan-report.html
   ```
4. **Post-build Actions:**
   - Publish HTML reports
   - Archive artifacts: `*.json, *.html`
   - Conditional step: Fail build if critical vulnerabilities found

---

## Bitbucket Pipelines

### bitbucket-pipelines.yml

```yaml
image: python:3.11

pipelines:
  default:
    - step:
        name: MCP Security Scan
        caches:
          - pip
        script:
          - pip install mcp-sentinel-scanner
          - mcp-scan . --format json -o scan-results.json
          - mcp-scan . --format html -o scan-report.html
        artifacts:
          - scan-results.json
          - scan-report.html

  branches:
    main:
      - step:
          name: Production Security Scan
          deployment: production
          script:
            - pip install mcp-sentinel-scanner
            - mcp-scan . --format sarif -o results.sarif --severity HIGH
            - |
              # Fail if critical vulnerabilities found
              CRITICAL=$(jq '.scan_summary.severity_distribution.CRITICAL // 0' scan-results.json)
              if [ "$CRITICAL" -gt 0 ]; then
                echo "Critical vulnerabilities found!"
                exit 1
              fi
          artifacts:
            - results.sarif
            - scan-report.html

  pull-requests:
    '**':
      - step:
          name: PR Security Check
          script:
            - pipe: docker://ghcr.io/mcp-security/mcp-sentinel-scanner:latest
              variables:
                SCAN_PATH: '.'
                OUTPUT_FORMAT: 'json'
            - |
              # Post results as PR comment
              curl -X POST \
                -H "Authorization: Bearer $BITBUCKET_TOKEN" \
                "https://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_OWNER/$BITBUCKET_REPO_SLUG/pullrequests/$BITBUCKET_PR_ID/comments" \
                -d "@scan-results.json"
```

### Using Docker in Bitbucket

```yaml
image: atlassian/default-image:3

pipelines:
  default:
    - step:
        name: Security Scan with Docker
        services:
          - docker
        script:
          - docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest
          - docker run --rm
              -v $(pwd):/scan
              -v $(pwd)/reports:/reports
              ghcr.io/mcp-security/mcp-sentinel-scanner:latest
              /scan
              --format html
              -o /reports/security-report.html
        artifacts:
          - reports/**

definitions:
  services:
    docker:
      memory: 2048
```

---

## Local Development

### Option 1: Direct Python Installation

```bash
# Clone repository
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run scanner
python -m scripts.sentinel_cli /path/to/code

# Run tests
pytest tests/ -v --cov=src
```

### Option 2: Install from PyPI

```bash
# Install globally
pip install mcp-sentinel-scanner

# Or in virtual environment
python3 -m venv scanner-env
source scanner-env/bin/activate
pip install mcp-sentinel-scanner

# Run scanner
mcp-scan /path/to/code
```

### Option 3: Docker for Local Scans

```bash
# Pull image
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest

# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# Alias for convenience
alias mcp-scan='docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest'

# Use alias
mcp-scan /scan --format html -o report.html
```

### Development Workflow

```bash
# Clone and setup
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Make changes
# ... edit files ...

# Run tests
pytest tests/ -v

# Run linting
black src/ tests/
flake8 src/ tests/

# Test scanner
python -m scripts.sentinel_cli tests/vulnerable_test.py

# Build Docker image
docker build -t mcp-scanner:dev .

# Test Docker image
docker run --rm -v $(pwd):/scan mcp-scanner:dev /scan/tests
```

---

## Configuration

### Configuration File

Create `config.json`:

```json
{
  "exclude": [
    "node_modules",
    "*.d.ts",
    "*.min.js",
    "dist",
    "build",
    ".git",
    "__pycache__",
    "*.pyc",
    "venv",
    ".venv"
  ],
  "severity_threshold": "LOW",
  "secret_entropy_threshold": 4.5,
  "parallel_workers": 4,
  "report_formats": ["terminal", "json", "html"]
}
```

### Using Configuration

```bash
# CLI
mcp-scan /path/to/code --config config.json

# Docker
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/config.json:/config.json:ro \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --config /config.json
```

### Environment Variables

```bash
# Set environment variables
export MCP_SCANNER_CONFIG=/path/to/config.json
export MCP_SCANNER_PARALLEL_WORKERS=8
export MCP_SCANNER_SEVERITY=HIGH

# Run scanner (uses environment variables)
mcp-scan /path/to/code
```

---

## Troubleshooting

### Common Issues

**Issue: Permission denied errors**
```bash
# Fix: Run with proper user mapping in Docker
docker run --rm \
  -u $(id -u):$(id -g) \
  -v $(pwd):/scan \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan
```

**Issue: Out of memory**
```bash
# Fix: Reduce parallel workers
mcp-scan /path/to/code --parallel 2

# Or increase Docker memory
docker run --rm --memory=4g \
  -v $(pwd):/scan \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan
```

**Issue: Slow scans**
```bash
# Fix: Increase parallel workers and exclude unnecessary files
mcp-scan /path/to/code \
  --parallel 8 \
  --exclude "node_modules" "*.d.ts" "dist"
```

**Issue: False positives**
```bash
# Fix: Use exclusions and adjust entropy threshold
mcp-scan /path/to/code \
  --exclude "*.d.ts" "*.min.js" \
  --config config.json  # With higher entropy_threshold
```

### Getting Help

- **Documentation:** [docs/](../docs/)
- **Issues:** https://github.com/mcp-security/mcp-sentinel-scanner/issues
- **Discussions:** https://github.com/mcp-security/mcp-sentinel-scanner/discussions

---

## Best Practices

### 1. CI/CD Integration

- ✅ Run scans on every PR
- ✅ Upload SARIF to GitHub Security
- ✅ Fail builds on critical vulnerabilities
- ✅ Generate HTML reports for review
- ✅ Archive scan results

### 2. Configuration

- ✅ Use `.mcp-scanner.json` in repository root
- ✅ Exclude third-party code and dependencies
- ✅ Adjust thresholds for your project
- ✅ Version control your configuration

### 3. Performance

- ✅ Use Docker for consistent environments
- ✅ Adjust `--parallel` based on available CPU
- ✅ Exclude large generated files
- ✅ Cache Docker images in CI/CD

### 4. Results Management

- ✅ Archive scan results for trend analysis
- ✅ Track ASR score over time
- ✅ Review and triage findings regularly
- ✅ Update exclusions as needed

---

## Example: Complete CI/CD Setup

### Full GitHub Actions Workflow

```yaml
name: Complete Security Workflow

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * 1'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run MCP Sentinel Scanner
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
            /scan \
            --exclude "node_modules" "*.d.ts" "dist" \
            --format json -o /reports/scan.json \
            --format html -o /reports/scan.html \
            --format sarif -o /reports/scan.sarif \
            --severity HIGH

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: reports/scan.sarif

      - name: Upload HTML Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: reports/scan.html

      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL=$(jq '.scan_summary.severity_distribution.CRITICAL // 0' reports/scan.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical vulnerabilities"
            exit 1
          fi

      - name: Post PR Comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const scan = JSON.parse(fs.readFileSync('reports/scan.json'));
            const summary = scan.scan_summary;

            const comment = `## 🛡️ MCP Security Scan Results

            - **Files Scanned:** ${summary.files_scanned}
            - **Vulnerabilities:** ${summary.vulnerabilities_found}
            - **ASR Score:** ${(summary.asr_score * 100).toFixed(1)}%

            ### Severity Distribution
            ${Object.entries(summary.severity_distribution)
              .map(([sev, count]) => `- **${sev}:** ${count}`)
              .join('\n')}

            [📄 View Full Report](../actions/runs/${{ github.run_id }})`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

**For more examples and updates, visit:** https://github.com/mcp-security/mcp-sentinel-scanner
