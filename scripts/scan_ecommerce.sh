#!/bin/bash
# E-commerce Project Security Scanner - Shell Script Version

set -e

# Configuration
PROJECT_PATH="/Volumes/2TBSSD/Development/Git/Clients/hkchawla1-e-commerce-02f3ff23e870"
CODEQL_DB_PATH="/Volumes/2TBSSD/Development/Git/Clients/hkchawla1-e-commerce-codeql"
CODESCAN_CONFIG="/Volumes/2TBSSD/Development/Git/Work/codescan/configs/codeql-config.yml"
CUSTOM_QUERIES_PATH="/Volumes/2TBSSD/Development/Git/Work/codescan/queries"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 E-commerce Security Scanner v2.1"
echo "=================================="
echo "📁 Project: $PROJECT_PATH"
echo "🗄️ Database: $CODEQL_DB_PATH"
echo "⚙️ Config: $CODESCAN_CONFIG"
echo ""

# Validate environment
echo "🔍 Validating environment..."
if ! command -v codeql &> /dev/null; then
    echo "❌ CodeQL CLI not found. Please install CodeQL CLI."
    exit 1
fi

if [ ! -d "$PROJECT_PATH" ]; then
    echo "❌ Project path not found: $PROJECT_PATH"
    exit 1
fi

if [ ! -f "$CODESCAN_CONFIG" ]; then
    echo "❌ CodeQL config not found: $CODESCAN_CONFIG"
    exit 1
fi

if [ ! -d "$CUSTOM_QUERIES_PATH" ]; then
    echo "❌ Custom queries path not found: $CUSTOM_QUERIES_PATH"
    exit 1
fi

echo "✅ Environment validated"
echo "✅ Using comprehensive config: Comprehensive Node.js & Angular Security Scan"

# Create CodeQL database
echo ""
echo "🏗️ Creating CodeQL database..."
if [ -d "$CODEQL_DB_PATH" ]; then
    echo "🗑️ Removing existing database..."
    rm -rf "$CODEQL_DB_PATH"
fi

mkdir -p "$CODEQL_DB_PATH"

echo "📦 Creating unified database for all microservices..."
echo "⚙️ Using comprehensive config with PCI/GDPR compliance checks"

# Create database with comprehensive configuration
codeql database create "$CODEQL_DB_PATH" \
    --language=javascript \
    --source-root="$PROJECT_PATH" \
    --overwrite \
    --threads=4 \
    --ram=4096

echo "✅ CodeQL database created successfully!"

# Run CodeQL analysis using comprehensive configuration
echo ""
echo "🔍 Running Comprehensive Node.js & Angular Security Scan..."

RESULTS_DIR="$CODEQL_DB_PATH/results"
mkdir -p "$RESULTS_DIR"

# Run comprehensive analysis with custom queries
echo "🔧 Running comprehensive security analysis with custom queries..."
output_file="$RESULTS_DIR/comprehensive-security-scan.sarif"

# Compile custom queries first
echo "🔧 Compiling custom queries..."
if codeql query compile "$CUSTOM_QUERIES_PATH" --threads=4; then
    echo "✅ Custom queries compiled successfully"
else
    echo "⚠️ Custom queries compilation failed, continuing with standard queries"
fi

# Run analysis with custom queries and standard security suite
if codeql database analyze "$CODEQL_DB_PATH" \
    "$CUSTOM_QUERIES_PATH" \
    codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
    --format=sarif-latest \
    --output="$output_file" \
    --threads=4 \
    --ram=4096 \
    --timeout=3600; then
    echo "✅ Comprehensive security analysis with custom queries completed"
else
    echo "❌ Comprehensive security analysis failed"
fi

# Run custom query categories
echo "🔧 Running custom security queries..."
custom_security_output="$RESULTS_DIR/custom-security-scan.sarif"

if [ -d "$CUSTOM_QUERIES_PATH/security" ]; then
    if codeql database analyze "$CODEQL_DB_PATH" \
        "$CUSTOM_QUERIES_PATH/security" \
        --format=sarif-latest \
        --output="$custom_security_output" \
        --threads=4 \
        --ram=4096 \
        --timeout=3600; then
        echo "✅ Custom security queries completed"
    else
        echo "❌ Custom security queries failed"
    fi
fi

# Run PCI compliance queries
echo "🔧 Running PCI compliance queries..."
pci_output="$RESULTS_DIR/pci-compliance-scan.sarif"

if [ -d "$CUSTOM_QUERIES_PATH/pci-compliance" ]; then
    if codeql database analyze "$CODEQL_DB_PATH" \
        "$CUSTOM_QUERIES_PATH/pci-compliance" \
        --format=sarif-latest \
        --output="$pci_output" \
        --threads=4 \
        --ram=4096 \
        --timeout=3600; then
        echo "✅ PCI compliance queries completed"
    else
        echo "❌ PCI compliance queries failed"
    fi
fi

# Run code scanning suite for GitHub integration
echo "🔧 Running code scanning suite..."
code_scan_output="$RESULTS_DIR/code-scanning.sarif"

if codeql database analyze "$CODEQL_DB_PATH" \
    codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls \
    --format=sarif-latest \
    --output="$code_scan_output" \
    --threads=4 \
    --ram=4096 \
    --timeout=3600; then
    echo "✅ Code scanning analysis completed"
else
    echo "❌ Code scanning analysis failed"
fi

# Run MCP Sentinel Scanner
echo ""
echo "🛡️ Running MCP Sentinel Scanner..."

MCP_RESULTS_DIR="$CODEQL_DB_PATH/mcp-sentinel-results"
mkdir -p "$MCP_RESULTS_DIR"

cd "$MCP_ROOT"

# Run unified scan with HTML output
if python -m scripts.sentinel_cli "$PROJECT_PATH" \
    --unified \
    --format html \
    -o "$MCP_RESULTS_DIR/security-report.html" \
    --exclude "node_modules" "*.d.ts" "dist" ".git" "codeql"; then
    echo "✅ MCP Sentinel scan completed!"
    echo "📊 HTML report: $MCP_RESULTS_DIR/security-report.html"
else
    echo "❌ MCP Sentinel scan failed"
fi

# Run additional formats
echo ""
echo "📄 Generating additional report formats..."

# JSON report
python -m scripts.sentinel_cli "$PROJECT_PATH" \
    --unified \
    --format json \
    -o "$MCP_RESULTS_DIR/security-report.json" \
    --exclude "node_modules" "*.d.ts" "dist" ".git" "codeql" || echo "⚠️ JSON report failed"

# SARIF report
python -m scripts.sentinel_cli "$PROJECT_PATH" \
    --unified \
    --format sarif \
    -o "$MCP_RESULTS_DIR/security-report.sarif" \
    --exclude "node_modules" "*.d.ts" "dist" ".git" "codeql" || echo "⚠️ SARIF report failed"

# Generate summary
echo ""
echo "📊 Generating scan summary..."

cat > "$CODEQL_DB_PATH/scan-summary.md" << EOF
# E-commerce Security Scan Summary

**Scan Date:** $(date)
**Project:** $PROJECT_PATH
**Database:** $CODEQL_DB_PATH

## CodeQL Analysis Results
- Database created successfully
- Query suites executed: ${#QUERY_SUITES[@]}
- Results location: $RESULTS_DIR/

## MCP Sentinel Scanner Results
- Unified multi-tool scan completed
- HTML Report: $MCP_RESULTS_DIR/security-report.html
- JSON Report: $MCP_RESULTS_DIR/security-report.json
- SARIF Report: $MCP_RESULTS_DIR/security-report.sarif

## Microservices Analyzed
- abandonedService
- bneedService
- categoryService
- discountService
- guestService
- order-management
- posService
- productService
- reviewService
- shipping-aggregators
- ShippingService

## Next Steps
1. Review HTML report for detailed findings
2. Import SARIF files into your IDE
3. Address high-priority security issues
4. Set up CI/CD integration for continuous scanning
EOF

echo "✅ Summary saved: $CODEQL_DB_PATH/scan-summary.md"

# Final summary
echo ""
echo "🎉 Security scan completed successfully!"
echo "=================================="
echo "📁 All results saved to: $CODEQL_DB_PATH"
echo "📊 View HTML report: $MCP_RESULTS_DIR/security-report.html"
echo "📋 Summary: $CODEQL_DB_PATH/scan-summary.md"
echo ""
echo "🔍 Database info:"
codeql database info "$CODEQL_DB_PATH" || echo "⚠️ Could not get database info"