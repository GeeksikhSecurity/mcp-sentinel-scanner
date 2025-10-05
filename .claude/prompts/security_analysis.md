# Security Analysis Prompts for Claude Code

## False Positive Investigation

```
Analyze this security finding and determine if it's a false positive:

**Finding Details:**
- File: {{file_path}}
- Line: {{line_number}}
- Category: {{category}}
- Severity: {{severity}}
- Code: {{code_snippet}}

**Analysis Checklist:**
1. ✓ Is this in test code? (tests/, *_test.py, vulnerable_test.py)
2. ✓ Is this a pattern definition? (SINKS, SOURCES, PATTERNS, DANGEROUS_FUNCTIONS)
3. ✓ Is the pattern used in a safe context? (string literals, comments, docs)
4. ✓ Is there a # nosec comment explaining why it's safe?
5. ✓ Could this realistically be exploited in production?

**If False Positive, Recommend Fix:**
- **Exclusion**: Add to configs/ci_config.json exclude list
- **String Concat**: Use "pickle." + "loads" to build at runtime
- **Comment**: Add # nosec: B403 - <reason>
- **Refactor**: Move pattern to separate data file

**Output:**
- Verdict: [REAL_VULNERABILITY | FALSE_POSITIVE | NEEDS_REVIEW]
- Reasoning: <explanation>
- Recommended Action: <specific fix>
```

## Custom Security Rule Creation

```
Create a custom security rule for MCP Sentinel Scanner:

**Vulnerability Type:** {{vuln_name}}
**Description:** {{description}}
**Target Code Pattern:** {{example_code}}
**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]

**Steps:**
1. Design regex pattern that matches vulnerable code
2. Test pattern against positive examples (should match)
3. Test pattern against negative examples (should NOT match)
4. Determine appropriate CWE mapping
5. Write clear remediation recommendation
6. Add to configs/security_rules.json
7. Create test case in tests/unit/test_custom_rules.py
8. Document in SECURITY.md

**Template:**
```json
{
  "id": "mcp-{{vuln_id}}",
  "name": "{{rule_name}}",
  "severity": "{{severity}}",
  "category": "{{category}}",
  "pattern": "{{regex_pattern}}",
  "description": "{{description}}",
  "cwe": "CWE-{{number}}",
  "recommendation": "{{fix_recommendation}}"
}
```

**Validation:**
- [ ] Pattern matches all positive test cases
- [ ] Pattern has zero false positives in src/
- [ ] CWE mapping is accurate
- [ ] Recommendation is actionable
- [ ] Test coverage added
```

## Systematic False Positive Reduction

```
Execute a systematic false positive reduction session:

**Phase 1: Discovery**
1. Run full scan: `python -m scripts.sentinel_cli . --config configs/ci_config.json --format json -o scan-results.json`
2. Extract all CRITICAL/HIGH findings
3. Group by file type: production (src/) vs test (tests/) vs docs

**Phase 2: Categorization**
For each finding, determine:
- Category A: Real vulnerability in production code → FIX IMMEDIATELY
- Category B: Test code with intentional vulnerability → EXCLUDE
- Category C: Pattern definition self-detection → STRING CONCAT
- Category D: Safe usage with context → ADD # nosec
- Category E: Ambiguous code → REFACTOR FOR CLARITY

**Phase 3: Remediation**
- Category A: Refactor with secure alternative
- Category B: Add to exclude patterns in configs/ci_config.json
- Category C: Use "dangerous" + ".function" string concatenation
- Category D: Add # nosec: CODE - Clear explanation
- Category E: Improve code clarity, then reassess

**Phase 4: Validation**
1. Re-scan with updated config
2. Verify 0 CRITICAL in production code (src/)
3. Ensure test coverage maintained (96%+)
4. Run all tests: `pytest tests/ -v --cov=src`
5. Document changes in commit message

**Phase 5: Documentation**
- Update configs/ci_config.json with new patterns
- Add false_positive_patterns with explanations
- Document in SECURITY.md under "Known Limitations"
- Create regression test for each fixed false positive

**Success Criteria:**
✓ 0 CRITICAL vulnerabilities in src/
✓ All tests passing (52/52)
✓ Coverage >= 96% for core modules
✓ Security scan workflow passes
✓ No real vulnerabilities missed
```

## Security Scan Workflow Debugging

```
Debug failing security-scan workflow:

**Step 1: Reproduce Locally**
```bash
python -m scripts.sentinel_cli . \
  --config configs/ci_config.json \
  --format json \
  -o reports/scan-results.json \
  --severity CRITICAL
```

**Step 2: Check Results**
```bash
jq '.scan_summary.severity_distribution' reports/scan-results.json
jq '.findings[] | select(.severity == "CRITICAL")' reports/scan-results.json
```

**Step 3: Analyze Each CRITICAL Finding**
For each finding:
1. Check file path - is it in production code (src/)?
2. Read surrounding context (10 lines before/after)
3. Determine if real vulnerability or false positive
4. Apply appropriate fix from .claude_code_rules

**Step 4: Verify Fix**
```bash
# Re-scan
python -m scripts.sentinel_cli . --config configs/ci_config.json -o /tmp/scan.json

# Check CRITICAL count
jq '.scan_summary.severity_distribution.CRITICAL // 0' /tmp/scan.json

# Should output: 0
```

**Step 5: Test in CI**
```bash
git add -A
git commit -m "fix: eliminate false positives in security scan"
git push origin main

# Monitor workflow
gh run watch
```

**Common Issues:**
- **Issue:** Test files causing CRITICAL
  - **Fix:** Add "tests/" to exclude in configs/ci_config.json

- **Issue:** Pattern definitions flagged
  - **Fix:** Use string concatenation: "pickle." + "loads"

- **Issue:** SARIF validation errors
  - **Fix:** Check src/reporters/sarif_reporter.py for invalid properties

- **Issue:** Workflow permissions denied
  - **Fix:** Add security-events: write to workflow permissions
```

## Performance Optimization

```
Optimize scanner performance while maintaining accuracy:

**Current Baseline:**
- Speed: 57 files/second
- Coverage: 96% core modules
- Test Count: 52 tests
- False Positive Rate: Target 0% in production code

**Optimization Targets:**
1. **Pattern Matching:** Optimize regex compilation and caching
2. **File I/O:** Reduce redundant file reads
3. **Parallelization:** Improve worker thread utilization (current: 4-8)
4. **AST Analysis:** Cache parsed trees for related checks

**Steps:**
1. **Profile Current Performance:**
   ```python
   python -m cProfile -o profile.stats -m scripts.sentinel_cli .
   python -m pstats profile.stats
   ```

2. **Identify Bottlenecks:**
   - Sort by cumulative time
   - Focus on top 10 slowest functions
   - Check for redundant operations

3. **Optimize:**
   - Compile regex patterns once at init
   - Use memoization for repeated calculations
   - Batch file operations
   - Optimize parallel worker count

4. **Benchmark:**
   ```bash
   time python -m scripts.sentinel_cli . --config configs/ci_config.json
   ```

5. **Validate Accuracy:**
   - Run full test suite
   - Compare findings before/after
   - Ensure no detection quality degradation

**Success Criteria:**
✓ Scan speed improvement > 20%
✓ No reduction in detection accuracy
✓ All tests still passing
✓ Memory usage unchanged or improved
```

## Adding MCP-Specific Patterns

```
Add detection patterns specific to MCP server vulnerabilities:

**MCP Attack Surface:**
1. Tool execution with user-controlled parameters
2. Context access with sensitive information
3. Resource/file access through tool APIs
4. Environment variable exposure
5. Inter-server communication

**Example Custom Rules:**

**1. Unsafe Tool Execution**
```json
{
  "id": "mcp-unsafe-tool-exec",
  "name": "MCP Unsafe Tool Execution",
  "severity": "CRITICAL",
  "category": "code_injection",
  "pattern": "tools\\.execute\\([^)]*\\+[^)]*\\)",
  "description": "Tool execution with string concatenation allows injection",
  "cwe": "CWE-94",
  "recommendation": "Use parameterized tool execution or validate inputs"
}
```

**2. Context Data Exposure**
```json
{
  "id": "mcp-context-leak",
  "name": "MCP Context Data Exposure",
  "severity": "HIGH",
  "category": "information_disclosure",
  "pattern": "context\\.(get|read).*log\\(|print\\(",
  "description": "Sensitive context data logged or printed",
  "cwe": "CWE-532",
  "recommendation": "Avoid logging context data; use structured logging with redaction"
}
```

**3. Unvalidated Server Communication**
```json
{
  "id": "mcp-unvalidated-ipc",
  "name": "MCP Unvalidated IPC",
  "severity": "HIGH",
  "category": "input_validation",
  "pattern": "server\\.call\\([^)]*request\\.",
  "description": "Direct use of request data in server calls without validation",
  "cwe": "CWE-20",
  "recommendation": "Validate all request parameters before server communication"
}
```

**Testing New Patterns:**
1. Create test file: tests/mcp_patterns_test.py
2. Add positive cases (should detect)
3. Add negative cases (should not detect)
4. Run: pytest tests/mcp_patterns_test.py -v
5. Integrate into configs/security_rules.json
```

## Pre-Commit Security Checks

```
Run comprehensive pre-commit security checks:

**Checklist:**
1. ✓ Run tests with coverage
   ```bash
   pytest tests/ -v --cov=src --cov-report=term-missing
   ```

2. ✓ Self-scan for vulnerabilities
   ```bash
   python -m scripts.sentinel_cli . \
     --config configs/ci_config.json \
     --severity CRITICAL
   ```

3. ✓ Check for secrets
   ```bash
   grep -r "api_key\|secret_key\|password\s*=\s*['\"]" src/ tests/
   ```

4. ✓ Verify no # nosec abuse
   ```bash
   grep -r "# nosec" src/ | wc -l
   # Should be minimal and each should have clear justification
   ```

5. ✓ Check SARIF generation
   ```bash
   python -m scripts.sentinel_cli . \
     --config configs/ci_config.json \
     --format sarif \
     -o /tmp/test.sarif

   jq 'keys' /tmp/test.sarif
   # Should show: ["$schema", "runs", "version"]
   ```

6. ✓ Validate configs
   ```bash
   python -c "import json; json.load(open('configs/ci_config.json'))"
   python -c "import json; json.load(open('configs/security_rules.json'))"
   ```

**Auto-fix Common Issues:**
- Format code: `black src/ tests/`
- Sort imports: `isort src/ tests/`
- Remove unused imports: `autoflake --remove-all-unused-imports -i src/**/*.py`

**Commit Only If:**
✓ All tests pass
✓ 0 CRITICAL in production code
✓ Coverage >= 96%
✓ No secrets detected
✓ Configs valid
✓ SARIF generation works
```
