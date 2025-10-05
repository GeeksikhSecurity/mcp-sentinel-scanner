# Claude Code Configuration for MCP Sentinel Scanner

This directory contains custom rules, prompts, and workflows for Claude Code to effectively work with the MCP Sentinel Scanner security analysis tool.

## Files

### `.claude_code_rules`
Main configuration file defining:
- Project context and permissions
- False positive elimination strategies
- Debugging and refactoring workflows
- Security analysis procedures
- Testing requirements
- Git workflow conventions

### `prompts/security_analysis.md`
Pre-written prompts for common security analysis tasks:
- False positive investigation
- Custom security rule creation
- Systematic false positive reduction
- Workflow debugging
- Performance optimization
- MCP-specific pattern addition
- Pre-commit security checks

## Quick Start

### Run Security Analysis
```bash
# Use the security analysis prompt
claude code --prompt "$(cat .claude/prompts/security_analysis.md | sed -n '/^## False Positive Investigation/,/^##/p')"
```

### Eliminate False Positives
```bash
# Run systematic reduction
python -m scripts.sentinel_cli . --config configs/ci_config.json --format json -o scan.json

# Analyze findings
claude code --prompt "Analyze scan.json for false positives following .claude_code_rules"
```

### Add Custom Security Rule
```bash
claude code --prompt "Create a custom security rule for {{vulnerability_type}} following .claude/prompts/security_analysis.md"
```

## Key Principles

### 1. False Positive Awareness
The scanner can detect its own pattern definitions. Use these strategies:

**String Concatenation:**
```python
# Instead of:
SINKS = {"pickle.loads", "yaml.load"}

# Use:
SINKS = {"pickle." + "loads", "yaml." + "load"}
```

**Exclusions:**
```json
// In configs/ci_config.json
{
  "exclude": ["tests/", "vulnerable_test"]
}
```

**Comments:**
```python
# nosec: B403 - This is a pattern definition, not actual code
DANGEROUS_FUNCTIONS = {"eval", "exec"}
```

### 2. Test Code vs Production Code
- Test files (`tests/`) intentionally contain vulnerable code
- Exclude from CRITICAL blocking in CI/CD
- Production code (`src/`) must have 0 CRITICAL findings

### 3. Security-First Development
- All production code changes must pass security scan
- 96%+ test coverage for core modules
- SARIF upload to GitHub Security for visibility
- Custom rules for MCP-specific threats

## Workflows

### Debugging Workflow
1. Analyze: Read files and understand state
2. Reproduce: Create minimal test case
3. Diagnose: Identify root cause
4. Propose: Suggest 2-3 solutions
5. Implement: Apply least invasive fix
6. Verify: Run full test suite
7. Document: Update comments/docs

### Security Analysis Workflow
1. Scan: Run with CI config
2. Review: Check CRITICAL findings
3. Categorize: Real vs false positive
4. Fix: Refactor real vulnerabilities
5. Suppress: Handle false positives
6. Validate: Re-scan for 0 CRITICAL
7. Document: Add to patterns

### Refactoring Workflow
1. Scope: Define what and why
2. Branch: Create feature branch
3. Backup: Ensure clean working tree
4. Incremental: Small changes with tests
5. Coverage: Maintain 96%+ coverage
6. Performance: Verify 57+ files/sec
7. Document: Update public API docs

## Common Commands

### Security Scanning
```bash
# Full scan
python -m scripts.sentinel_cli . --config configs/ci_config.json

# CRITICAL only
python -m scripts.sentinel_cli . --config configs/ci_config.json --severity CRITICAL

# SARIF output
python -m scripts.sentinel_cli . --config configs/ci_config.json --format sarif -o results.sarif

# HTML report
python -m scripts.sentinel_cli . --config configs/ci_config.json --format html -o report.html
```

### Testing
```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Specific test
pytest tests/test_scanner.py::test_name -v

# Watch mode
pytest tests/ -v --looponfail
```

### Analysis
```bash
# Check for secrets
grep -r "api_key\|secret\|password" src/ tests/

# Count false positive suppressions
grep -r "# nosec" src/ | wc -l

# Validate JSON configs
jq '.' configs/ci_config.json
jq '.' configs/security_rules.json
```

## Custom Rules Integration

### Adding a New Rule
1. Define in `configs/security_rules.json`:
```json
{
  "id": "mcp-new-rule",
  "name": "Description",
  "severity": "HIGH",
  "category": "category_type",
  "pattern": "regex_pattern",
  "description": "What it detects",
  "cwe": "CWE-XXX",
  "recommendation": "How to fix"
}
```

2. Test the pattern:
```python
import re
pattern = re.compile(r"regex_pattern")
# Test against positive cases (should match)
# Test against negative cases (should NOT match)
```

3. Add test case:
```python
# tests/unit/test_custom_rules.py
def test_new_rule_detection():
    scanner = MCPSentinelScanner()
    # Add test code
```

4. Scan and validate:
```bash
python -m scripts.sentinel_cli . --config configs/production_config.json
```

## False Positive Patterns

### Pattern Definitions
**Problem:** Scanner detects its own detection patterns
**Solution:** String concatenation
```python
SINKS = {"pickle." + "loads"}  # Not detected as vulnerability
```

### Test Code
**Problem:** Intentional vulnerable code in tests
**Solution:** Exclusion
```json
{"exclude": ["tests/", "vulnerable_test"]}
```

### Safe Usage
**Problem:** Pattern used safely in specific context
**Solution:** Comment
```python
result = eval(expr)  # nosec: B307 - Controlled environment with validated input
```

## Performance Targets

- **Scan Speed:** 57+ files/second
- **Test Coverage:** 96%+ for core modules
- **Test Count:** 52+ tests
- **False Positive Rate:** 0% in production code
- **ASR Score:** Accurate severity assessment

## CI/CD Integration

### GitHub Actions Workflows
- **CI:** Test across Python 3.9-3.12
- **Security Scan:** Self-scan with SARIF upload

### Success Criteria
- All tests pass (52/52)
- 0 CRITICAL in production code
- Coverage >= 96%
- SARIF validation passes
- Workflows complete successfully

## Best Practices

1. **Always follow .claude_code_rules** for permissions and workflows
2. **Test incrementally** after each change
3. **Maintain coverage** at 96%+ for core modules
4. **Document false positives** in config with explanations
5. **Use prompts/** templates for consistency
6. **Verify SARIF** generation before committing
7. **Check self-scan** passes before pushing
8. **Review # nosec** usage - should be minimal and justified

## Resources

- [SECURITY.md](../SECURITY.md) - Vulnerability disclosure policy
- [VISUAL_GUIDE.md](../VISUAL_GUIDE.md) - ASCII architecture diagrams
- [configs/security_rules.json](../configs/security_rules.json) - Custom detection rules
- [configs/ci_config.json](../configs/ci_config.json) - CI/CD scan configuration

## Support

For issues with Claude Code configuration:
1. Check `.claude_code_rules` for current settings
2. Review `prompts/security_analysis.md` for examples
3. Consult [Claude Code documentation](https://docs.claude.com/claude-code)
4. Open GitHub issue with `claude-config` label
