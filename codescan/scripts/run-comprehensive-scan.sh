#!/bin/bash
# Comprehensive CodeQL Security Scan for Node.js & Angular Applications

set -e

# Configuration
DB_NAME="nodejs-angular-db"
OUTPUT_DIR="./reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONFIG_FILE="./configs/codeql-config.yml"

echo "🛡️ Starting Comprehensive CodeQL Security Scan"
echo "Database: $DB_NAME"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo "=" * 70

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if database exists
if [ ! -d "$DB_NAME" ]; then
    echo "❌ CodeQL database not found. Please run ./scripts/init-codeql.sh first"
    exit 1
fi

echo "🔍 Running Security Analysis..."

# 1. Security Queries
echo "📊 1/8 Security vulnerabilities..."
codeql database analyze "$DB_NAME" \
    --format=sarif-latest \
    --output="$OUTPUT_DIR/security-results-$TIMESTAMP.sarif" \
    --sarif-category=security \
    queries/security/ \
    --threads=4 \
    --ram=4096

# 2. PCI Compliance
echo "💳 2/8 PCI DSS compliance..."
codeql database analyze "$DB_NAME" \
    --format=json \
    --output="$OUTPUT_DIR/pci-compliance-$TIMESTAMP.json" \
    queries/pci-compliance/ \
    --threads=4

# 3. Performance Analysis
echo "⚡ 3/8 Performance issues..."
codeql database analyze "$DB_NAME" \
    --format=csv \
    --output="$OUTPUT_DIR/performance-$TIMESTAMP.csv" \
    queries/performance/ \
    --threads=4

# 4. AI Security
echo "🤖 4/8 AI/ML security..."
codeql database analyze "$DB_NAME" \
    --format=sarif-latest \
    --output="$OUTPUT_DIR/ai-security-$TIMESTAMP.sarif" \
    --sarif-category=ai-security \
    queries/ai-security/ \
    --threads=4

# 5. Container Security
echo "🐳 5/8 Container security..."
codeql database analyze "$DB_NAME" \
    --format=json \
    --output="$OUTPUT_DIR/container-security-$TIMESTAMP.json" \
    queries/container-security/ \
    --threads=4

# 6. Architecture Analysis
echo "🏗️ 6/8 Architecture patterns..."
codeql database analyze "$DB_NAME" \
    --format=csv \
    --output="$OUTPUT_DIR/architecture-$TIMESTAMP.csv" \
    queries/architecture/ \
    --threads=4

# 7. Code Quality
echo "✨ 7/8 Code quality..."
codeql database analyze "$DB_NAME" \
    --format=json \
    --output="$OUTPUT_DIR/quality-$TIMESTAMP.json" \
    queries/quality/ \
    --threads=4

# 8. Comprehensive Analysis (All queries)
echo "🎯 8/8 Comprehensive analysis..."
codeql database analyze "$DB_NAME" \
    --format=sarif-latest \
    --output="$OUTPUT_DIR/comprehensive-$TIMESTAMP.sarif" \
    --sarif-category=comprehensive \
    queries/ \
    --threads=4 \
    --ram=6144

echo "📈 Generating Summary Report..."

# Generate summary report
cat > "$OUTPUT_DIR/scan-summary-$TIMESTAMP.md" << EOF
# CodeQL Comprehensive Scan Report

**Scan Date**: $(date)
**Database**: $DB_NAME
**Total Queries**: $(find queries/ -name "*.ql" | wc -l)

## Scan Results

### Security Analysis
- **File**: security-results-$TIMESTAMP.sarif
- **Format**: SARIF 2.1.0 (GitHub Security compatible)
- **Categories**: Hardcoded secrets, SQL injection, XSS, Command injection

### PCI DSS Compliance
- **File**: pci-compliance-$TIMESTAMP.json
- **Focus**: Cardholder data exposure, Payment flow security
- **Standards**: PCI DSS v3.2.1

### Performance Analysis
- **File**: performance-$TIMESTAMP.csv
- **Focus**: Memory leaks, Bundle optimization, Database queries
- **Targets**: Node.js processes, Angular applications

### AI/ML Security
- **File**: ai-security-$TIMESTAMP.sarif
- **Focus**: Prompt injection, Model vulnerabilities, Data pipeline security
- **Integrations**: OpenAI, Anthropic, Hugging Face, LangChain

### Container Security
- **File**: container-security-$TIMESTAMP.json
- **Focus**: Dockerfile security, Kubernetes configurations, Docker Compose
- **Standards**: CIS Docker Benchmark, Kubernetes security best practices

### Architecture Analysis
- **File**: architecture-$TIMESTAMP.csv
- **Focus**: Service mesh, API patterns, Data flow mapping
- **Patterns**: Microservices, Event-driven architecture, Circuit breakers

### Code Quality
- **File**: quality-$TIMESTAMP.json
- **Focus**: Technical debt, Dependency analysis, Angular/Node.js optimizations
- **Metrics**: Complexity, Duplication, Test coverage gaps

### Comprehensive Results
- **File**: comprehensive-$TIMESTAMP.sarif
- **Contains**: All findings from above categories
- **Integration**: Ready for GitHub Security, VS Code, enterprise dashboards

## Next Steps

1. **High Priority**: Review security-results-$TIMESTAMP.sarif for critical vulnerabilities
2. **Compliance**: Address PCI DSS findings in pci-compliance-$TIMESTAMP.json
3. **Performance**: Optimize issues identified in performance-$TIMESTAMP.csv
4. **AI Security**: Review AI integration security in ai-security-$TIMESTAMP.sarif
5. **Container**: Harden container configurations per container-security-$TIMESTAMP.json

## Integration Commands

### Upload to GitHub Security
\`\`\`bash
gh api repos/:owner/:repo/code-scanning/sarifs \\
  --method POST \\
  --field sarif=@$OUTPUT_DIR/comprehensive-$TIMESTAMP.sarif \\
  --field ref=refs/heads/main
\`\`\`

### VS Code Integration
\`\`\`bash
code --install-extension ms-vscode.codeql
# Open .sarif files directly in VS Code
\`\`\`

### Enterprise Dashboard
Upload SARIF files to your security dashboard or SIEM system.
EOF

echo "✅ Comprehensive scan complete!"
echo ""
echo "📊 Results Summary:"
echo "  Security Results: $OUTPUT_DIR/security-results-$TIMESTAMP.sarif"
echo "  PCI Compliance: $OUTPUT_DIR/pci-compliance-$TIMESTAMP.json"
echo "  Performance: $OUTPUT_DIR/performance-$TIMESTAMP.csv"
echo "  AI Security: $OUTPUT_DIR/ai-security-$TIMESTAMP.sarif"
echo "  Container Security: $OUTPUT_DIR/container-security-$TIMESTAMP.json"
echo "  Architecture: $OUTPUT_DIR/architecture-$TIMESTAMP.csv"
echo "  Code Quality: $OUTPUT_DIR/quality-$TIMESTAMP.json"
echo "  Comprehensive: $OUTPUT_DIR/comprehensive-$TIMESTAMP.sarif"
echo ""
echo "📄 Summary Report: $OUTPUT_DIR/scan-summary-$TIMESTAMP.md"
echo ""
echo "🚀 Next Steps:"
echo "  1. Review critical security findings"
echo "  2. Address PCI DSS compliance issues"
echo "  3. Optimize performance bottlenecks"
echo "  4. Upload SARIF to GitHub Security"
echo ""
echo "💡 Integration:"
echo "  GitHub: gh api repos/:owner/:repo/code-scanning/sarifs --method POST --field sarif=@$OUTPUT_DIR/comprehensive-$TIMESTAMP.sarif"
echo "  VS Code: Install CodeQL extension and open .sarif files"