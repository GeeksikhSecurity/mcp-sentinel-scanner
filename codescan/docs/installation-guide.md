# CodeQL Installation & Setup Guide

## Prerequisites

### System Requirements
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: 10GB free space for CodeQL CLI and databases
- **Node.js**: Version 14+ for JavaScript/TypeScript analysis

### Required Tools
- Git
- Node.js & npm/yarn
- Docker (optional, for containerized scanning)

## CodeQL CLI Installation

### macOS Installation
```bash
# Download CodeQL CLI
curl -L https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-osx64.zip -o codeql.zip

# Extract and setup
unzip codeql.zip
sudo mv codeql /usr/local/bin/
export PATH=$PATH:/usr/local/bin/codeql

# Verify installation
codeql version
```

### Linux Installation
```bash
# Download CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip

# Extract and setup
unzip codeql-linux64.zip
sudo mv codeql /usr/local/bin/
export PATH=$PATH:/usr/local/bin/codeql

# Add to shell profile
echo 'export PATH=$PATH:/usr/local/bin/codeql' >> ~/.bashrc
source ~/.bashrc
```

### Windows Installation
```powershell
# Download CodeQL CLI
Invoke-WebRequest -Uri "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip" -OutFile "codeql.zip"

# Extract
Expand-Archive -Path "codeql.zip" -DestinationPath "C:\codeql"

# Add to PATH
$env:PATH += ";C:\codeql\codeql"
[Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::User)
```

## Project Setup

### 1. Clone the MCP Sentinel Scanner
```bash
git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
cd mcp-sentinel-scanner/codescan
```

### 2. Install Dependencies
```bash
# Install Node.js dependencies for the scanner
npm install

# Or using yarn
yarn install
```

### 3. Configure CodeQL
```bash
# Make scripts executable (macOS/Linux)
chmod +x scripts/*.sh

# Verify configuration
codeql resolve queries queries/security/
```

## Database Creation

### For Your Node.js/Angular Project
```bash
# Navigate to your project directory
cd /path/to/your/nodejs-angular-project

# Initialize CodeQL database
/path/to/mcp-sentinel-scanner/codescan/scripts/init-codeql.sh $(pwd)
```

### Manual Database Creation
```bash
# Create database manually
codeql database create my-nodejs-db \
    --language=javascript \
    --source-root=/path/to/your/project \
    --command="npm run build"
```

## Running Scans

### Quick Security Scan
```bash
# Run security-focused scan
codeql database analyze my-nodejs-db \
    --format=sarif-latest \
    --output=security-results.sarif \
    queries/security/
```

### Comprehensive Scan
```bash
# Run all query categories
./scripts/run-comprehensive-scan.sh
```

### Specific Category Scans
```bash
# PCI DSS Compliance
codeql database analyze my-nodejs-db \
    --format=json \
    --output=pci-results.json \
    queries/pci-compliance/

# Performance Analysis
codeql database analyze my-nodejs-db \
    --format=csv \
    --output=performance-results.csv \
    queries/performance/

# AI Security
codeql database analyze my-nodejs-db \
    --format=sarif-latest \
    --output=ai-security-results.sarif \
    queries/ai-security/
```

## Integration Setup

### GitHub Actions Integration
Create `.github/workflows/codeql-analysis.yml`:
```yaml
name: "CodeQL Analysis"

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
    - name: Checkout repository
      uses: actions/checkout@v3

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: javascript
        config-file: ./.github/codeql/codeql-config.yml

    - name: Autobuild
      uses: github/codeql-action/autobuild@v2

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      with:
        category: "/language:javascript"
```

### VS Code Integration
```bash
# Install CodeQL extension
code --install-extension ms-vscode.codeql

# Open workspace with CodeQL support
code --add .
```

### Jenkins Integration
```groovy
pipeline {
    agent any
    
    stages {
        stage('CodeQL Analysis') {
            steps {
                script {
                    sh '''
                        # Create CodeQL database
                        codeql database create nodejs-db \
                            --language=javascript \
                            --source-root=. \
                            --command="npm run build"
                        
                        # Run analysis
                        codeql database analyze nodejs-db \
                            --format=sarif-latest \
                            --output=results.sarif \
                            /path/to/queries/
                    '''
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*.sarif', fingerprint: true
        }
    }
}
```

## Configuration Customization

### Custom Query Configuration
Edit `configs/codeql-config.yml`:
```yaml
name: "Custom Security Scan"
queries:
  - name: high-severity-only
    uses: ./queries/security/
    filters:
      - include:
          severity: error
      - exclude:
          tags: experimental

paths:
  - "src/**"
  - "lib/**"

paths-ignore:
  - "node_modules/**"
  - "test/**"
  - "*.test.js"
```

### Environment-Specific Configurations
```bash
# Development environment
cp configs/codeql-config.yml configs/dev-config.yml

# Production environment
cp configs/codeql-config.yml configs/prod-config.yml

# Use specific config
codeql database analyze my-db \
    --sarif-category=production \
    --config=configs/prod-config.yml \
    queries/
```

## Troubleshooting

### Common Issues

#### Database Creation Fails
```bash
# Check build command
npm run build

# Use alternative build command
codeql database create my-db \
    --language=javascript \
    --source-root=. \
    --command="yarn build || npm run compile || echo 'No build command'"
```

#### Out of Memory Errors
```bash
# Increase memory allocation
codeql database analyze my-db \
    --ram=8192 \
    --threads=4 \
    queries/
```

#### Query Compilation Errors
```bash
# Check query syntax
codeql query compile queries/security/hardcoded-secrets.ql

# Resolve dependencies
codeql resolve queries queries/security/
```

### Performance Optimization
```bash
# Use fewer threads for limited resources
codeql database analyze my-db \
    --threads=2 \
    --ram=4096 \
    queries/

# Analyze specific paths only
codeql database analyze my-db \
    --additional-packs=/path/to/custom/packs \
    queries/security/
```

## Verification

### Test Installation
```bash
# Verify CodeQL CLI
codeql version

# Test query compilation
codeql query compile queries/security/hardcoded-secrets.ql

# Test database creation on sample project
mkdir test-project
cd test-project
npm init -y
echo 'console.log("Hello World");' > index.js
codeql database create test-db --language=javascript --source-root=. --command="echo 'No build needed'"
```

### Validate Results
```bash
# Check SARIF format
codeql database analyze test-db \
    --format=sarif-latest \
    --output=test-results.sarif \
    codeql/javascript-queries

# Validate SARIF file
python -m json.tool test-results.sarif > /dev/null && echo "Valid SARIF"
```

## Next Steps

1. **Run Initial Scan**: Execute comprehensive scan on your project
2. **Review Results**: Analyze findings in generated reports
3. **Configure CI/CD**: Set up automated scanning in your pipeline
4. **Customize Queries**: Adapt queries for your specific requirements
5. **Monitor Progress**: Track security improvements over time

For advanced configuration and custom query development, see:
- [Query Development Guide](query-development.md)
- [Custom Rules Creation](custom-rules.md)
- [Performance Tuning](performance-tuning.md)