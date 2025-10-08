# MCP Sentinel Scanner Installation Guide

## Quick Start (60 seconds)

```bash
# Option 1: pip install (recommended)
pip install mcp-sentinel-scanner
mcp-scan /path/to/code --unified

# Option 2: Docker (no dependencies)
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan --unified

# Option 3: Development setup
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner && pip install -e ".[dev]"
python -m scripts.sentinel_cli /path/to/code --unified
```

## Installation Methods

### 1. pip Install (Recommended)

#### System Requirements
- **Python**: 3.8+ (3.11+ recommended)
- **OS**: macOS, Linux, Windows
- **Memory**: 2GB+ available RAM
- **Disk**: 500MB free space

#### Installation
```bash
# Install latest stable version
pip install mcp-sentinel-scanner

# Install with all optional dependencies
pip install mcp-sentinel-scanner[all]

# Install specific version
pip install mcp-sentinel-scanner==1.5.0

# Upgrade existing installation
pip install --upgrade mcp-sentinel-scanner
```

#### Verify Installation
```bash
mcp-scan --version
# Expected: MCP Sentinel Scanner v1.5.0

mcp-scan --help
# Shows all available commands and options
```

### 2. Docker Installation

#### Pull Image
```bash
# Latest stable
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest

# Specific version
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:v1.5.0

# Development version
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:dev
```

#### Basic Usage
```bash
# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/mcp-security/mcp-sentinel-scanner:latest /scan

# Generate HTML report
docker run --rm -v $(pwd):/scan -v $(pwd)/reports:/reports \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --format html -o /reports/security-report.html

# With custom config
docker run --rm -v $(pwd):/scan -v $(pwd)/config.json:/config.json \
  ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
  /scan --config /config.json
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  mcp-scanner:
    image: ghcr.io/mcp-security/mcp-sentinel-scanner:latest
    volumes:
      - ./:/scan
      - ./reports:/reports
    command: ["/scan", "--unified", "--format", "html", "-o", "/reports/report.html"]
    environment:
      - SCAN_PARALLEL_WORKERS=4
      - SCAN_SEVERITY_THRESHOLD=HIGH
```

### 3. Development Installation

#### Clone Repository
```bash
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner
```

#### Setup Development Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
make test
```

#### Development Dependencies
```bash
# Core dependencies
pip install -e .

# Development dependencies
pip install -e ".[dev]"

# Testing dependencies
pip install -e ".[test]"

# Documentation dependencies
pip install -e ".[docs]"

# All dependencies
pip install -e ".[all]"
```

### 4. Package Manager Installation

#### Homebrew (macOS/Linux)
```bash
# Add tap
brew tap mcp-security/tap

# Install scanner
brew install mcp-sentinel-scanner

# Upgrade
brew upgrade mcp-sentinel-scanner
```

#### Chocolatey (Windows)
```powershell
# Install Chocolatey package
choco install mcp-sentinel-scanner

# Upgrade
choco upgrade mcp-sentinel-scanner
```

#### Snap (Linux)
```bash
# Install snap package
sudo snap install mcp-sentinel-scanner

# Upgrade
sudo snap refresh mcp-sentinel-scanner
```

## Configuration

### 1. Basic Configuration

#### Create config.json
```json
{
  "exclude": [
    "node_modules",
    "*.d.ts",
    "dist",
    ".git",
    "__pycache__",
    "*.pyc"
  ],
  "severity_threshold": "HIGH",
  "parallel_workers": 4,
  "output_format": "terminal",
  "enable_taint_analysis": true,
  "enable_ml_classification": true
}
```

#### Environment Variables
```bash
# Scanner configuration
export MCP_SCAN_WORKERS=8
export MCP_SCAN_THRESHOLD=MEDIUM
export MCP_SCAN_FORMAT=json
export MCP_SCAN_OUTPUT=/tmp/scan-results.json

# External tool configuration
export TRUFFLEHOG_PATH=/usr/local/bin/trufflehog
export SEMGREP_PATH=/usr/local/bin/semgrep
export SEMGREP_TIMEOUT=300

# Performance tuning
export MCP_SCAN_MEMORY_LIMIT=4096
export MCP_SCAN_TIMEOUT=1800
```

### 2. Advanced Configuration

#### Custom Rules
```json
{
  "custom_patterns": {
    "mcp_auth_bypass": {
      "pattern": "if\\s+1\\s*==\\s*1:",
      "severity": "CRITICAL",
      "description": "Always-true authentication bypass"
    },
    "mcp_hardcoded_key": {
      "pattern": "sk-[a-zA-Z0-9]{48}",
      "severity": "HIGH",
      "description": "OpenAI API key detected"
    }
  },
  "false_positive_filters": {
    "test_files": true,
    "import_statements": true,
    "placeholder_values": true,
    "documentation": true
  }
}
```

#### Tool-Specific Settings
```json
{
  "tools": {
    "trufflehog": {
      "enabled": true,
      "timeout": 300,
      "args": ["--no-verification", "--json"]
    },
    "semgrep": {
      "enabled": true,
      "timeout": 600,
      "rules": ["p/security-audit", "p/owasp-top-ten"]
    },
    "custom_analyzer": {
      "enabled": true,
      "taint_analysis": true,
      "complexity_threshold": 10
    }
  }
}
```

### 3. CI/CD Configuration

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Install MCP Scanner
        run: pip install mcp-sentinel-scanner
        
      - name: Run Security Scan
        run: |
          mcp-scan . --unified --format sarif -o results.sarif
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ghcr.io/mcp-security/mcp-sentinel-scanner:latest').inside {
                        sh 'mcp-scan /workspace --unified --format json -o security-results.json'
                    }
                }
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-results.json',
                    reportName: 'Security Scan Report'
                ])
            }
        }
    }
}
```

## IDE Integration

### 1. VS Code Extension

#### Installation
```bash
# Install from marketplace
code --install-extension mcp-security.mcp-sentinel-scanner

# Or search "MCP Sentinel Scanner" in Extensions panel
```

#### Configuration
```json
// .vscode/settings.json
{
  "mcp-scanner.enableRealTimeScanning": true,
  "mcp-scanner.severityThreshold": "HIGH",
  "mcp-scanner.excludePatterns": ["node_modules", "dist"],
  "mcp-scanner.showInlineWarnings": true,
  "mcp-scanner.autoScanOnSave": true
}
```

### 2. JetBrains IDEs

#### Plugin Installation
1. Open **Settings** → **Plugins**
2. Search "MCP Sentinel Scanner"
3. Install and restart IDE

#### Configuration
```xml
<!-- .idea/mcp-scanner.xml -->
<component name="MCPScannerSettings">
  <option name="enableRealTimeScanning" value="true" />
  <option name="severityThreshold" value="HIGH" />
  <option name="parallelWorkers" value="4" />
</component>
```

### 3. Vim/Neovim Integration

#### ALE Plugin
```vim
" .vimrc or init.vim
let g:ale_linters = {
\   'python': ['mcp-scanner'],
\   'javascript': ['mcp-scanner'],
\   'typescript': ['mcp-scanner']
\}

let g:ale_python_mcp_scanner_options = '--unified --format json'
```

## Performance Optimization

### 1. System Tuning

#### Memory Optimization
```bash
# Increase available memory
export MCP_SCAN_MEMORY_LIMIT=8192  # 8GB

# Enable memory-mapped files
export MCP_SCAN_USE_MMAP=true

# Garbage collection tuning
export PYTHONHASHSEED=0
export PYTHONOPTIMIZE=1
```

#### CPU Optimization
```bash
# Set worker count to CPU cores
export MCP_SCAN_WORKERS=$(nproc)

# Enable parallel processing
export MCP_SCAN_PARALLEL=true

# CPU affinity (Linux)
taskset -c 0-7 mcp-scan /path/to/code
```

### 2. Scan Optimization

#### Exclude Patterns
```json
{
  "exclude": [
    "node_modules/**",
    "venv/**",
    "*.min.js",
    "*.bundle.js",
    "dist/**",
    "build/**",
    ".git/**",
    "*.log",
    "*.tmp"
  ]
}
```

#### Incremental Scanning
```bash
# Scan only changed files
mcp-scan . --incremental --since HEAD~1

# Scan specific file types
mcp-scan . --include "*.py" "*.js" "*.ts"

# Fast scan (pattern matching only)
mcp-scan . --fast --no-taint-analysis
```

## Troubleshooting

### 1. Common Issues

#### Installation Problems

**Issue**: `pip install` fails with permission error
```bash
# Solution: Use user install
pip install --user mcp-sentinel-scanner

# Or use virtual environment
python -m venv venv && source venv/bin/activate
pip install mcp-sentinel-scanner
```

**Issue**: Docker image pull fails
```bash
# Solution: Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
docker pull ghcr.io/mcp-security/mcp-sentinel-scanner:latest
```

#### Runtime Issues

**Issue**: Scanner runs out of memory
```bash
# Solution: Reduce parallel workers
mcp-scan . --workers 2

# Or increase memory limit
export MCP_SCAN_MEMORY_LIMIT=4096
```

**Issue**: External tools not found
```bash
# Solution: Install missing tools
pip install trufflehog semgrep

# Or disable external tools
mcp-scan . --no-external-tools
```

### 2. Performance Issues

#### Slow Scanning
```bash
# Check system resources
htop  # Monitor CPU/memory usage

# Profile scanner performance
mcp-scan . --profile --verbose

# Use fast mode for quick checks
mcp-scan . --fast
```

#### High Memory Usage
```bash
# Monitor memory usage
mcp-scan . --memory-profile

# Reduce memory footprint
mcp-scan . --workers 1 --no-cache
```

### 3. Output Issues

#### Missing Results
```bash
# Increase verbosity
mcp-scan . --verbose --debug

# Check excluded files
mcp-scan . --list-excluded

# Verify file permissions
ls -la /path/to/scan
```

#### Format Problems
```bash
# Validate output format
mcp-scan . --format json --validate

# Use alternative format
mcp-scan . --format terminal  # Always works
```

### 4. Debug Mode

#### Enable Debug Logging
```bash
# Full debug output
mcp-scan . --debug --log-level DEBUG

# Save debug log
mcp-scan . --debug --log-file debug.log

# Trace execution
mcp-scan . --trace
```

#### Debug Configuration
```json
{
  "debug": {
    "enabled": true,
    "log_level": "DEBUG",
    "log_file": "mcp-scanner-debug.log",
    "profile_performance": true,
    "trace_execution": true
  }
}
```

## Support and Resources

### Documentation
- **Quick Start**: [QUICK_START.md](QUICK_START.md)
- **Configuration**: [configs/default_config.json](configs/default_config.json)
- **API Reference**: [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- **Architecture**: [docs/ARCHITECTURE_DIAGRAMS.md](docs/ARCHITECTURE_DIAGRAMS.md)

### Community
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/mcp-security/mcp-sentinel-scanner/issues)
- **Discussions**: [Community forum](https://github.com/mcp-security/mcp-sentinel-scanner/discussions)
- **Discord**: [Real-time chat support](https://discord.gg/mcp-security)

### Professional Support
- **Enterprise Support**: enterprise@mcp-security.com
- **Training**: [Security scanning workshops](https://mcp-security.com/training)
- **Consulting**: [Custom security solutions](https://mcp-security.com/consulting)

---

**Next Steps**: Choose your installation method and run your first scan in under 60 seconds!