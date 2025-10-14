# MCP Sentinel Scanner - Technology Stack

## Programming Languages

### Primary Language
- **Python 3.9+** - Core application development
- **Minimum Version**: Python 3.9
- **Supported Versions**: 3.9, 3.10, 3.11, 3.12
- **Type Hints**: Full typing support with mypy validation

### Analysis Target Languages
- **Python** - Primary analysis target with AST parsing
- **TypeScript/JavaScript** - React pattern detection and NPM analysis
- **Go** - Static analysis support
- **Rust** - Security pattern detection
- **Java** - Enterprise application scanning

## Build System & Package Management

### Build Configuration
- **Build System**: Hatchling (modern Python packaging)
- **Package Definition**: pyproject.toml (PEP 621 compliant)
- **Legacy Support**: setup.py for backward compatibility
- **Version**: 1.5.0 (pyproject.toml), 1.0.0 (setup.py)

### Dependency Management
- **Core Dependencies**: colorama, tabulate
- **Development Dependencies**: pytest, black, isort, flake8, mypy
- **Optional Dependencies**: External security tools (TruffleHog, Semgrep)
- **Documentation**: Sphinx, sphinx-rtd-theme, myst-parser

## Development Tools & Quality Assurance

### Code Quality
- **Formatter**: Black (line-length: 100)
- **Import Sorting**: isort (black profile)
- **Linting**: flake8 (max-line-length: 100)
- **Type Checking**: mypy (strict mode)
- **Security**: bandit (security linting)

### Testing Framework
- **Test Runner**: pytest 7.0+
- **Coverage**: pytest-cov (100% target coverage)
- **Mocking**: pytest-mock
- **Async Testing**: pytest-asyncio
- **Performance**: pytest-benchmark
- **Test Organization**: unit/, integration/, external/ markers

### Pre-commit Hooks
- **Configuration**: .pre-commit-config.yaml
- **Hooks**: black, isort, flake8, mypy, bandit
- **Git Integration**: Automated quality checks before commits

## External Tool Integration

### Security Scanners
- **TruffleHog** - Secret detection (requires Go installation)
- **Semgrep** - Static analysis patterns
- **CodeQL** - Advanced code analysis (GitHub integration)
- **Integration**: Adapter pattern for tool orchestration

### CI/CD Integration
- **GitHub Actions** - Automated testing and security scanning
- **Docker Support** - Containerized deployment
- **SARIF Output** - Security dashboard integration
- **Multi-platform**: Linux, macOS, Windows support

## Development Commands

### Setup & Installation
```bash
# Development installation
pip install -e ".[dev]"

# Install with all optional dependencies
pip install -e ".[dev,docs,external-tools]"

# Pre-commit setup
pre-commit install
```

### Testing & Quality
```bash
# Run all tests with coverage
pytest --cov=src --cov-report=html

# Type checking
mypy src scripts

# Code formatting
black src scripts tests
isort src scripts tests

# Linting
flake8 src scripts tests

# Security scanning
bandit -r src scripts
```

### Build & Distribution
```bash
# Build package
python -m build

# Install locally
pip install -e .

# Run scanner
mcp-scan /path/to/code --unified
```

### Docker Development
```bash
# Build image
docker build -t mcp-sentinel-scanner .

# Run container
docker run --rm -v $(pwd):/scan mcp-sentinel-scanner /scan

# Development with volume mounting
docker-compose up scanner
```

## Configuration Management

### Configuration Files
- **pyproject.toml** - Primary build and tool configuration
- **setup.py** - Legacy packaging support
- **requirements.txt** - Core dependencies
- **requirements-dev.txt** - Development dependencies
- **.flake8** - Linting configuration
- **Makefile** - Development automation

### Environment Configuration
- **configs/default_config.json** - Base scanner settings
- **configs/ci_config.json** - CI/CD specific configuration
- **configs/production_config.json** - Production deployment settings
- **configs/unified_config.json** - Multi-tool orchestration

## Performance & Scalability

### Optimization Features
- **Parallel Processing** - Multi-threaded file analysis
- **Memory Management** - Efficient resource utilization
- **Caching** - Result caching for incremental scans
- **Batch Processing** - Optimized for large codebases (1,400+ files/sec)

### Monitoring & Metrics
- **Coverage Reporting** - XML, HTML, terminal output
- **Performance Benchmarking** - pytest-benchmark integration
- **Security Metrics** - ASR scoring and confidence calculation
- **CI/CD Metrics** - Automated quality gates and reporting

## Deployment Architecture

### Distribution Methods
- **PyPI Package** - pip installable package
- **Docker Images** - Pre-built container images
- **Source Installation** - Git clone and development setup
- **CI/CD Integration** - GitHub Actions, Jenkins, Bitbucket

### Enterprise Features
- **Configuration Management** - Environment-specific settings
- **Audit Logging** - Comprehensive scan history
- **API Integration** - RESTful endpoints for dashboards
- **Compliance Reporting** - SARIF, JSON, HTML output formats