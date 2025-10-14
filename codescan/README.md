# CodeQL Code Scanning for Node.js & Angular Applications

## Overview
Advanced CodeQL configuration for comprehensive security, performance, and compliance scanning of Node.js & Angular applications with focus on PCI DSS compliance, AI integration security, and container optimization.

## Features
- **Security & PCI Compliance**: Deep dependency scanning, authentication flaws, data exposure risks
- **Performance & Scalability**: Memory leak detection, bundle analysis, database optimization
- **Architecture Analysis**: Service mesh compatibility, API patterns, data flow mapping
- **AI Integration Security**: Model vulnerabilities, data pipeline integrity, inference optimization
- **Container Security**: Multi-stage build analysis, runtime security, orchestration validation
- **Code Quality**: Technical debt quantification, Angular/Node.js specific optimizations

## Installation & Setup

### Prerequisites
```bash
# Install CodeQL CLI
curl -L https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-osx64.zip -o codeql.zip
unzip codeql.zip
export PATH=$PATH:$(pwd)/codeql
```

### Quick Start
```bash
# Initialize CodeQL database
./scripts/init-codeql.sh /path/to/your/project

# Run comprehensive scan
./scripts/run-comprehensive-scan.sh

# Generate reports
./scripts/generate-reports.sh
```

## Configuration Files

### Core Configuration
- `codeql-config.yml` - Main CodeQL configuration
- `queries/` - Custom security and performance queries
- `scripts/` - Automation scripts for scanning
- `reports/` - Output templates and formatters

### Specialized Configurations
- `pci-compliance/` - PCI DSS specific queries and rules
- `ai-security/` - AI/ML integration security patterns
- `container-security/` - Docker and Kubernetes security security analysis
- `performance/` - Node.js and Angular performance optimization

## Usage Examples

### Security Scan
```bash
codeql database analyze nodejs-db \
  --format=sarif-latest \
  --output=security-results.sarif \
  queries/security/
```

### Performance Analysis
```bash
codeql database analyze nodejs-db \
  --format=csv \
  --output=performance-results.csv \
  queries/performance/
```

### PCI Compliance Check
```bash
codeql database analyze nodejs-db \
  --format=json \
  --output=pci-compliance.json \
  queries/pci-compliance/
```