# CodeQL Integration PRD: MCP Sentinel Scanner v2.0

## Executive Summary

Integrate GitHub's CodeQL semantic analysis engine into MCP Sentinel Scanner to dramatically reduce the **88.4% false positive rate** through advanced dataflow analysis and context-aware vulnerability detection.

## Problem Statement

### Current Scanner Limitations
- **88.4% false positive rate** across 8 test repositories
- **8,482 import statement false positives** (pattern matching failure)
- **100% test file contamination** (no semantic understanding)
- **Path traversal over-detection** (92.5% of all findings)

### Root Cause Analysis
Current scanner uses **syntactic pattern matching** without semantic understanding:
```python
# FALSE POSITIVE - Scanner flags as path traversal
import { utils } from '../helpers/validator';

# MISSED VULNERABILITY - Scanner doesn't understand data flow
const userPath = req.params.path;
fs.readFile(userPath, callback); // Real vulnerability missed
```

## Solution: CodeQL Semantic Analysis

### Why CodeQL?
1. **Dataflow Analysis** - Tracks data from source to sink
2. **Context Awareness** - Understands imports vs vulnerabilities
3. **Language Support** - Python, JavaScript, TypeScript, Java, C++
4. **Proven Accuracy** - Used by GitHub Security Lab
5. **Custom Queries** - MCP-specific vulnerability patterns

## Product Requirements

### Core Integration (v2.0)

#### 1. CodeQL Database Creation
```bash
# Automatic database creation for each scan
codeql database create /tmp/codeql-db --language=python,javascript
```

**Requirements:**
- Auto-detect project languages
- Handle multi-language repositories
- Cache databases for incremental scans
- 30-second timeout for large projects

#### 2. MCP-Specific Query Suite
```ql
// Custom query: MCP server privilege escalation
import python
import semmle.python.dataflow.TaintTracking

class MCPPrivilegeEscalation extends TaintTracking::Configuration {
  MCPPrivilegeEscalation() { this = "MCPPrivilegeEscalation" }
  
  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(Call).getFunc().toString() = "mcp.get_user_input"
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr().(Call).getFunc().toString() = "subprocess.run"
  }
}
```

**Query Categories:**
- **MCP Authentication Bypass** - `mcp_auth_bypass.ql`
- **MCP Command Injection** - `mcp_command_injection.ql`
- **MCP Path Traversal** - `mcp_path_traversal.ql`
- **MCP Privilege Escalation** - `mcp_privilege_escalation.ql`
- **MCP Data Exfiltration** - `mcp_data_exfiltration.ql`

#### 3. Hybrid Analysis Pipeline
```python
class HybridAnalyzer:
    def analyze(self, codebase_path: str) -> ScanResults:
        # Phase 1: Fast pattern matching (existing)
        pattern_results = self.pattern_analyzer.scan(codebase_path)
        
        # Phase 2: CodeQL semantic analysis
        codeql_results = self.codeql_analyzer.scan(codebase_path)
        
        # Phase 3: Result fusion with confidence scoring
        return self.merge_results(pattern_results, codeql_results)
```

#### 4. False Positive Reduction
```python
class SemanticFilter:
    def filter_false_positives(self, findings: List[Finding]) -> List[Finding]:
        filtered = []
        for finding in findings:
            # CodeQL confirms dataflow exists
            if self.codeql_confirms_vulnerability(finding):
                finding.confidence = min(finding.confidence + 0.3, 1.0)
                filtered.append(finding)
            # CodeQL contradicts pattern match
            elif self.codeql_contradicts_finding(finding):
                finding.confidence = max(finding.confidence - 0.5, 0.0)
                if finding.confidence > 0.2:
                    filtered.append(finding)
        return filtered
```

### Advanced Features (v2.1)

#### 1. Custom MCP Query Development
- **Query Builder UI** - Visual query construction
- **MCP Pattern Library** - Pre-built vulnerability patterns
- **Community Queries** - Shared query repository
- **Query Testing Framework** - Validate queries against known vulnerabilities

#### 2. Incremental Analysis
```python
class IncrementalCodeQL:
    def scan_changes(self, git_diff: str) -> ScanResults:
        # Only analyze changed files and their dependencies
        changed_files = self.parse_git_diff(git_diff)
        affected_queries = self.get_relevant_queries(changed_files)
        return self.codeql.run_queries(affected_queries, changed_files)
```

#### 3. IDE Integration
- **VS Code Extension** - Real-time CodeQL analysis
- **JetBrains Plugin** - IntelliJ/PyCharm integration
- **Language Server** - LSP-compatible analysis

## Technical Architecture

### CodeQL Integration Layer
```
┌─────────────────────────────────────────────────────────────┐
│  MCP Sentinel Scanner v2.0 Architecture                    │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│  │   Pattern    │   │    CodeQL    │   │   Result     │   │
│  │   Analyzer   │   │   Analyzer   │   │   Fusion     │   │
│  │              │   │              │   │              │   │
│  │ • Regex      │   │ • Dataflow   │   │ • Confidence │   │
│  │ • AST        │   │ • Taint      │   │ • Dedup      │   │
│  │ • Entropy    │   │ • Semantic   │   │ • Priority   │   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │
│         │                   │                   │         │
│         └───────────────────┼───────────────────┘         │
│                             │                             │
│  ┌──────────────────────────▼──────────────────────────┐  │
│  │           Unified Results Engine                    │  │
│  │  • SARIF 2.1.0 • HTML • JSON • Markdown • Terminal │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Performance Requirements
- **Database Creation**: <60 seconds for 10K files
- **Query Execution**: <30 seconds for standard suite
- **Memory Usage**: <4GB for large repositories
- **Incremental Scans**: <10 seconds for typical changes

## Expected Impact

### Accuracy Improvements
```
Current State (v1.5)     →     Target State (v2.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
False Positive Rate: 88.4%  →  False Positive Rate: <15%
Precision: ~11%              →  Precision: >85%
Import FPs: 8,482            →  Import FPs: <100
Test File FPs: 100%          →  Test File FPs: <5%
Path Traversal FPs: 92.5%    →  Path Traversal FPs: <20%
```

### Performance Targets
- **Scan Speed**: Maintain 50+ files/sec average
- **Memory Efficiency**: <4GB for enterprise repositories
- **CI/CD Integration**: <5 minutes for typical projects
- **Developer Experience**: <30 seconds for incremental scans

## Implementation Plan

### Phase 1: Core Integration (8 weeks)
- **Week 1-2**: CodeQL CLI integration and database creation
- **Week 3-4**: Basic MCP query suite development
- **Week 5-6**: Result fusion and confidence scoring
- **Week 7-8**: Testing against 8 repository benchmark

### Phase 2: Advanced Features (6 weeks)
- **Week 9-10**: Custom query builder and MCP pattern library
- **Week 11-12**: Incremental analysis and caching
- **Week 13-14**: Performance optimization and benchmarking

### Phase 3: Enterprise Features (4 weeks)
- **Week 15-16**: IDE integrations and language server
- **Week 17-18**: Advanced reporting and dashboard integration

## Success Metrics

### Accuracy Metrics
- **False Positive Rate**: <15% (from 88.4%)
- **True Positive Rate**: >90% (maintain recall)
- **Precision**: >85% (from ~11%)
- **F1 Score**: >87% (balanced accuracy)

### Performance Metrics
- **Scan Speed**: >50 files/sec (maintain current)
- **Database Creation**: <60 seconds for 10K files
- **Memory Usage**: <4GB for large repositories
- **CI/CD Time**: <5 minutes for typical projects

### Developer Experience
- **Setup Time**: <2 minutes (automated CodeQL installation)
- **Learning Curve**: <1 hour (familiar CLI interface)
- **IDE Integration**: Real-time feedback in <5 seconds
- **Custom Queries**: Non-experts can create queries in <30 minutes

## Risk Mitigation

### Technical Risks
1. **CodeQL Installation Complexity**
   - *Mitigation*: Automated installer with fallback to Docker
   
2. **Performance Degradation**
   - *Mitigation*: Parallel execution and intelligent caching
   
3. **Query Development Complexity**
   - *Mitigation*: Pre-built query library and visual builder

### Business Risks
1. **GitHub Dependency**
   - *Mitigation*: Maintain pattern-based fallback mode
   
2. **License Compliance**
   - *Mitigation*: Use CodeQL CLI (free for open source)

## Competitive Analysis

### CodeQL vs Alternatives
| Feature | CodeQL | Semgrep | SonarQube | Snyk |
|---------|--------|---------|-----------|------|
| **Dataflow Analysis** | ✅ Excellent | ⚠️ Limited | ✅ Good | ⚠️ Basic |
| **Custom Queries** | ✅ QL Language | ✅ YAML Rules | ❌ Limited | ❌ No |
| **Language Support** | ✅ 10+ Languages | ✅ 15+ Languages | ✅ 25+ Languages | ✅ 10+ Languages |
| **False Positive Rate** | ✅ <10% | ⚠️ 15-25% | ⚠️ 20-30% | ⚠️ 10-20% |
| **Open Source** | ✅ CLI Free | ✅ Community | ❌ Commercial | ❌ Commercial |

**Verdict**: CodeQL provides the best balance of accuracy, customization, and cost for MCP-specific analysis.

## Conclusion

CodeQL integration represents a **paradigm shift** from syntactic pattern matching to semantic vulnerability analysis. This upgrade will:

1. **Solve the false positive crisis** (88.4% → <15%)
2. **Enable MCP-specific vulnerability detection**
3. **Maintain performance** while dramatically improving accuracy
4. **Position the scanner** as enterprise-ready security tool

**Investment**: 18 weeks development time
**Return**: Production-ready scanner with industry-leading accuracy
**Risk**: Low (proven technology with fallback options)

---

**Next Steps**: Approve PRD and begin Phase 1 implementation with CodeQL CLI integration and basic MCP query development.