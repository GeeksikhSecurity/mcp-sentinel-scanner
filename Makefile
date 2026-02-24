# MCP Sentinel Scanner - Development Makefile

.PHONY: help install install-dev test test-cov lint format type-check security clean build docs serve-docs release

# Default target
help:
	@echo "MCP Sentinel Scanner - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install      Install package in production mode"
	@echo "  install-dev  Install package in development mode with all dependencies"
	@echo ""
	@echo "Development:"
	@echo "  test         Run test suite"
	@echo "  test-cov     Run tests with coverage report"
	@echo "  lint         Run all linting checks"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run mypy type checking"
	@echo "  security     Run security checks with bandit"
	@echo ""
	@echo "Documentation:"
	@echo "  docs         Build documentation"
	@echo "  serve-docs   Serve documentation locally"
	@echo ""
	@echo "Release:"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build package for distribution"
	@echo "  release      Build and upload to PyPI (requires credentials)"
	@echo ""
	@echo "Utilities:"
	@echo "  scan-self    Run scanner on itself for testing"
	@echo "  benchmark    Run performance benchmarks"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,docs]"
	pre-commit install

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/index.html"

test-integration:
	pytest tests/test_integration.py -v

test-performance:
	pytest tests/ -v --benchmark-only

# Code Quality
lint: format type-check security
	flake8 src scripts tests
	@echo "All linting checks passed!"

format:
	black src scripts tests
	isort src scripts tests

type-check:
	mypy src scripts

security:
	bandit -r src scripts

# Documentation
docs:
	cd docs && make html
	@echo "Documentation built in docs/_build/html/index.html"

serve-docs:
	cd docs/_build/html && python -m http.server 8000

# Build and Release
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build
	twine check dist/*

release: build
	twine upload dist/*

# Repo corpus (regression / nightly)
corpus-smoke:
	PYTHONPATH=. python3 scripts/run_repo_corpus.py --tier smoke --output-dir reports/repo_corpus
	@echo "Corpus smoke complete: reports/repo_corpus/"

corpus-full:
	PYTHONPATH=. python3 scripts/run_repo_corpus.py --tier full --output-dir reports/repo_corpus_full
	@echo "Corpus full complete: reports/repo_corpus_full/"

corpus-nightly:
	PYTHONPATH=. python3 scripts/run_repo_corpus.py --tier nightly --output-dir reports/repo_corpus_nightly --cache-dir .cache/repo_corpus
	@echo "Corpus nightly complete: reports/repo_corpus_nightly/ (requires network)"

# Utilities
scan-self:
	python -m scripts.sentinel_cli . --format html -o self-scan-report.html
	@echo "Self-scan complete! Report: self-scan-report.html"

scan-self-unified:
	python -m scripts.sentinel_cli . --unified --format html -o unified-scan-report.html
	@echo "Unified self-scan complete! Report: unified-scan-report.html"

benchmark:
	python -c "
	import time
	from pathlib import Path
	from src.unified_scanner import UnifiedScanner
	
	print('Running performance benchmark...')
	scanner = UnifiedScanner()
	start = time.time()
	result = scanner.scan(Path('.'))
	duration = time.time() - start
	
	print(f'Scan completed in {duration:.2f}s')
	print(f'Files scanned: {result.summary.files_scanned}')
	print(f'Vulnerabilities found: {result.summary.vulnerabilities_found}')
	print(f'Scan speed: {result.summary.files_scanned/duration:.1f} files/sec')
	"

# Development helpers
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify installation"

pre-commit-all:
	pre-commit run --all-files

tox-test:
	tox

# Docker
docker-build:
	docker build -t mcp-sentinel-scanner:latest .

docker-test:
	docker run --rm -v $(PWD):/scan mcp-sentinel-scanner:latest /scan

docker-shell:
	docker run --rm -it -v $(PWD):/scan --entrypoint /bin/bash mcp-sentinel-scanner:latest

# CI/CD helpers
ci-test: install-dev lint test-cov
	@echo "CI pipeline simulation complete!"

# Quick development workflow
dev: format lint test
	@echo "Development workflow complete!"

# Show project statistics
stats:
	@echo "Project Statistics:"
	@echo "==================="
	@find src -name "*.py" | xargs wc -l | tail -1 | awk '{print "Source lines: " $$1}'
	@find tests -name "*.py" | xargs wc -l | tail -1 | awk '{print "Test lines: " $$1}'
	@find . -name "*.py" -not -path "./build/*" -not -path "./.venv/*" | wc -l | awk '{print "Python files: " $$1}'
	@pytest tests/ --collect-only -q | grep "test session starts" -A 1 | tail -1 | awk '{print "Test cases: " $$1}'