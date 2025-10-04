# MCP Sentinel Scanner - Quick Start Guide

Get scanning in 60 seconds! 🚀

---

## 🐳 Docker (Recommended)

```bash
# Pull and run
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# Generate HTML report
docker run --rm -v $(pwd):/scan -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format html -o /reports/security-report.html

# Open report
open reports/security-report.html  # macOS
xdg-open reports/security-report.html  # Linux
```

---

## 📦 pip Install

```bash
# Install
pip install mcp-sentinel-scanner

# Scan
mcp-scan /path/to/code

# With HTML report
mcp-scan /path/to/code --format html -o report.html
```

---

## 🔧 From Source

```bash
# Clone and setup
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner
pip install -r requirements.txt

# Scan
python -m scripts.sentinel_cli /path/to/code

# With exclusions
python -m scripts.sentinel_cli /path/to/code \
  --exclude "node_modules" "*.d.ts" "dist" \
  --format html -o report.html
```

---

## 🔄 CI/CD Integration

### GitHub Actions

Add `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          docker run --rm -v ${{ github.workspace }}:/scan \
            ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
            /scan --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'docker run --rm -v ${WORKSPACE}:/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan'
            }
        }
    }
}
```

---

## 📊 Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **Terminal** | Quick check | `--format terminal` (default) |
| **HTML** | Reports | `--format html -o report.html` |
| **JSON** | Automation | `--format json -o results.json` |
| **SARIF** | IDE/GitHub | `--format sarif -o results.sarif` |
| **Markdown** | Docs | `--format markdown -o report.md` |

---

## ⚙️ Common Options

```bash
# Exclude files/directories
mcp-scan /path --exclude "*.d.ts" "node_modules" "dist"

# Filter by severity
mcp-scan /path --severity HIGH

# Parallel workers (faster)
mcp-scan /path --parallel 8

# Custom config
mcp-scan /path --config config.json
```

---

## 🎯 Example Config

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

---

## 📚 Next Steps

- 📖 [Full Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- 🏗️ [Architecture](docs/ARCHITECTURE_DIAGRAMS.md)
- 🗺️ [Roadmap](ROADMAP.md)
- 🐛 [Report Issues](https://github.com/mcp-security/mcp-sentinel-scanner/issues)

---

## 💡 Pro Tips

**Tip 1: Create an alias**
```bash
alias mcp-scan='docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest'
mcp-scan /scan
```

**Tip 2: Scan only your code**
```bash
mcp-scan src/ --exclude "*.test.js" "*.spec.ts"
```

**Tip 3: Fail CI on critical**
```bash
mcp-scan /path --format json -o results.json
CRITICAL=$(jq '.scan_summary.severity_distribution.CRITICAL // 0' results.json)
[ "$CRITICAL" -eq 0 ] || exit 1
```

---

**Full documentation:** https://github.com/mcp-security/mcp-sentinel-scanner
