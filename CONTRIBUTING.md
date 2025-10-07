# Contributing to MCP Sentinel Scanner

Thank you for your interest in contributing to the MCP Sentinel Scanner! This document provides guidelines and information for contributors.

## 🚀 Quick Start

### Development Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/mcp-security/mcp-sentinel-scanner.git
   cd mcp-sentinel-scanner
   ```

2. **Set up Python environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev,docs]"
   ```

3. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

4. **Run tests to verify setup**:
   ```bash
   pytest tests/ -v
   ```

### Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Run the test suite**:
   ```bash
   pytest tests/ -v --cov=src
   ```

4. **Run code quality checks**:
   ```bash
   black src scripts tests
   isort src scripts tests
   flake8 src scripts tests
   mypy src scripts
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

6. **Push and create a pull request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## 📋 Contribution Guidelines

### Code Style

We follow Python best practices and use automated tools to maintain code quality:

- **Formatting**: [Black](https://black.readthedocs.io/) with 100-character line length
- **Import Sorting**: [isort](https://pycqa.github.io/isort/) with Black profile
- **Linting**: [flake8](https://flake8.pycqa.org/) for style guide enforcement
- **Type Checking**: [mypy](https://mypy.readthedocs.io/) for static type analysis
- **Security**: [bandit](https://bandit.readthedocs.io/) for security issue detection

### Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) for clear and consistent commit messages:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types**:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```bash
feat(scanner): add React vulnerability detection
fix(cli): handle missing config file gracefully
docs: update installation instructions
test: add integration tests for unified scanner
```

### Testing Requirements

All contributions must include appropriate tests:

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **Coverage**: Maintain >90% test coverage
4. **Performance**: Include performance tests for critical paths

**Test Structure**:
```
tests/
├── unit/                 # Unit tests
│   ├── test_scanner.py
│   └── test_analyzers.py
├── integration/          # Integration tests
│   └── test_workflows.py
└── fixtures/            # Test data and fixtures
    └── vulnerable_code/
```

**Writing Tests**:
```python
import pytest
from src.analyzers import ReactAnalyzer

class TestReactAnalyzer:
    def test_detect_xss_vulnerability(self, tmp_path):
        """Test XSS detection in React components."""
        # Arrange
        test_file = tmp_path / "component.jsx"
        test_file.write_text("""
        function Component({ userInput }) {
            return <div dangerouslySetInnerHTML={{__html: userInput}} />;
        }
        """)
        
        analyzer = ReactAnalyzer()
        
        # Act
        findings = analyzer.analyze(test_file)
        
        # Assert
        assert len(findings) == 1
        assert findings[0].category == "react_xss"
        assert findings[0].severity == "HIGH"
```

### Documentation Standards

- **Docstrings**: All public functions, classes, and modules must have docstrings
- **Type Hints**: All function signatures must include type hints
- **Examples**: Include usage examples in docstrings
- **README**: Update README.md for user-facing changes

**Docstring Format**:
```python
def analyze_vulnerabilities(target: Path, config: Optional[Dict] = None) -> List[Finding]:
    """Analyze target for security vulnerabilities.
    
    Args:
        target: Path to file or directory to scan
        config: Optional configuration dictionary
        
    Returns:
        List of vulnerability findings
        
    Raises:
        FileNotFoundError: If target path doesn't exist
        
    Example:
        >>> analyzer = VulnerabilityAnalyzer()
        >>> findings = analyzer.analyze_vulnerabilities(Path("./src"))
        >>> print(f"Found {len(findings)} vulnerabilities")
    """
```

## 🎯 Areas for Contribution

### High Priority
- **Multi-language Support**: Add TypeScript, JavaScript, Java analyzers
- **Performance Optimization**: Improve scan speed and memory usage
- **False Positive Reduction**: Enhance ML models and context analysis
- **Integration**: Add support for more CI/CD platforms

### Medium Priority
- **Vulnerability Rules**: Add new detection patterns
- **Output Formats**: Support additional report formats
- **Configuration**: Enhance configuration options
- **Documentation**: Improve guides and tutorials

### Good First Issues
- **Test Coverage**: Add tests for uncovered code paths
- **Documentation**: Fix typos, improve examples
- **Bug Fixes**: Address reported issues
- **Code Quality**: Refactor complex functions

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment Information**:
   - Python version
   - Operating system
   - Package version

2. **Reproduction Steps**:
   - Minimal code example
   - Command line arguments
   - Expected vs actual behavior

3. **Additional Context**:
   - Error messages and stack traces
   - Configuration files
   - Sample files that trigger the issue

**Bug Report Template**:
```markdown
## Bug Description
Brief description of the issue

## Environment
- Python version: 3.11.0
- OS: macOS 13.0
- Package version: 1.5.0

## Reproduction Steps
1. Run command: `mcp-scan ./test-project`
2. Observe error: ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Additional Context
Any other relevant information
```

## 💡 Feature Requests

For feature requests, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** and problem being solved
3. **Propose a solution** if you have ideas
4. **Consider implementation complexity** and maintenance burden

## 🔒 Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please email security@mcp-project.org with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## 📚 Development Resources

### Architecture Overview
```
src/
├── adapters/           # External tool integrations
├── analyzers/          # Language-specific analyzers
├── fp_reducer/         # False positive reduction
├── reporters/          # Output format generators
└── unified_scanner.py  # Main orchestration logic
```

### Key Components
- **MCPSentinelScanner**: Core scanning engine
- **UnifiedScanner**: Multi-tool orchestrator
- **ReactAnalyzer**: React-specific vulnerability detection
- **TaintAnalyzer**: Data flow analysis
- **ContextAnalyzer**: False positive reduction

### Testing Strategy
- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Performance Tests**: Measure scan speed and memory usage

### Debugging Tips
1. **Use pytest with verbose output**: `pytest -v -s`
2. **Run specific tests**: `pytest tests/test_scanner.py::test_specific_function`
3. **Debug with pdb**: Add `import pdb; pdb.set_trace()` in code
4. **Check logs**: Enable debug logging in configuration

## 🏆 Recognition

Contributors will be recognized in:
- **CHANGELOG.md**: Major contributions listed in release notes
- **README.md**: Contributors section with GitHub profiles
- **Documentation**: Author attribution for significant additions

## 📞 Getting Help

- **GitHub Discussions**: https://github.com/mcp-security/mcp-sentinel-scanner/discussions
- **Issues**: https://github.com/mcp-security/mcp-sentinel-scanner/issues
- **Email**: security@mcp-project.org

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to MCP Sentinel Scanner! 🚀