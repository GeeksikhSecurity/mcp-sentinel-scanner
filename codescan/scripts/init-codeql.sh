#!/bin/bash
# CodeQL Database Initialization Script for Node.js & Angular Projects

set -e

PROJECT_PATH=${1:-$(pwd)}
DB_NAME="nodejs-angular-db"
CODEQL_CONFIG="./configs/codeql-config.yml"

echo "🚀 Initializing CodeQL Database for Node.js & Angular Project"
echo "Project Path: $PROJECT_PATH"
echo "Database Name: $DB_NAME"
echo "=" * 60

# Check if CodeQL is installed
if ! command -v codeql &> /dev/null; then
    echo "❌ CodeQL CLI not found. Please install CodeQL CLI first."
    echo "Download from: https://github.com/github/codeql-cli-binaries/releases"
    exit 1
fi

# Check if project has package.json
if [ ! -f "$PROJECT_PATH/package.json" ]; then
    echo "❌ No package.json found in $PROJECT_PATH"
    echo "Please ensure this is a Node.js project directory"
    exit 1
fi

echo "📦 Installing dependencies..."
cd "$PROJECT_PATH"

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    if command -v npm &> /dev/null; then
        npm install
    elif command -v yarn &> /dev/null; then
        yarn install
    else
        echo "❌ Neither npm nor yarn found. Please install dependencies manually."
        exit 1
    fi
fi

echo "🔍 Creating CodeQL database..."

# Remove existing database if it exists
if [ -d "$DB_NAME" ]; then
    echo "🗑️  Removing existing database..."
    rm -rf "$DB_NAME"
fi

# Create CodeQL database
codeql database create "$DB_NAME" \
    --language=javascript \
    --source-root="$PROJECT_PATH" \
    --command="npm run build || yarn build || echo 'No build command found'" \
    --overwrite

echo "✅ CodeQL database created successfully!"

# Verify database
echo "🔍 Verifying database..."
codeql database info "$DB_NAME"

echo "📊 Database statistics:"
codeql database analyze "$DB_NAME" \
    --format=csv \
    --output=database-stats.csv \
    codeql/javascript-queries:Diagnostics/DatabaseQuality.ql

echo "✅ CodeQL database initialization complete!"
echo "Database location: $(pwd)/$DB_NAME"
echo "Next steps:"
echo "  1. Run security scan: ./scripts/run-security-scan.sh"
echo "  2. Run performance analysis: ./scripts/run-performance-scan.sh"
echo "  3. Run comprehensive scan: ./scripts/run-comprehensive-scan.sh"