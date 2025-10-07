# Product Requirements Document: Unified Security Scanner for npm/React

**Version:** 1.0
**Date:** 2025-10-05
**Status:** Draft
**Author:** AI Engineering Team
**Attribution:** [Kiro:Claude-Sonnet-4.5:2025-10-05]

---

## Executive Summary

### Vision
Build a unified security scanning platform that orchestrates multiple best-in-class security tools (TruffleHog, Semgrep, custom scanners) to provide comprehensive static code analysis for npm and React codebases with industry-leading false positive reduction (<5%).

### Problem Statement
Current security scanning workflows suffer from:
- **Tool Fragmentation**: Teams run 3-5 separate security tools with inconsistent output formats
- **False Positive Fatigue**: 40-60% false positive rates lead to alert fatigue and ignored warnings
- **Manual Correlation**: No unified view across different scanner outputs
- **React/npm Gaps**: Generic scanners miss framework-specific vulnerabilities (hooks, context, env vars)
- **CI/CD Friction**: Multiple tool integrations slow pipelines by 5-10 minutes

### Success Metrics
| Metric | Target | Baseline | Timeline |
|--------|--------|----------|----------|
| False Positive Rate | <5% | 40-60% (industry) | 6 months |
| Detection Accuracy | >95% | 70-85% | 6 months |
| Scan Time (10K LOC) | <60 seconds | 5-10 minutes | 3 months |
| CI/CD Integration | 100% compatible | 60% | 3 months |
| Developer Adoption | 80% team usage | 30% | 9 months |

---

## Market Analysis

### Target Users
1. **Primary**: Frontend Engineering Teams (React, Next.js, Vue, Angular)
2. **Secondary**: Security Engineering Teams
3. **Tertiary**: DevOps/Platform Engineering

### Competitive Landscape

| Tool | Strengths | Weaknesses | Our Advantage |
|------|-----------|------------|---------------|
| **TruffleHog** | Excellent secret detection, entropy analysis | High false positives on test data | Context-aware filtering, exclude patterns |
| **Semgrep** | Fast pattern matching, custom rules | Limited semantic analysis | Multi-layer AST + pattern hybrid |
| **GitHub CodeQL** | Deep semantic analysis | Slow (10+ min scans), limited languages | Fast multi-tool orchestration |
| **Snyk Code** | Good React support | Proprietary, expensive | Open-source, extensible |
| **SonarQube** | Comprehensive quality metrics | Heavyweight, infrastructure required | Zero-infrastructure, CLI-first |

### Unique Value Proposition
**"5-minute security scans with 95% accuracy through intelligent multi-tool orchestration and ML-powered false positive reduction"**

---

## Product Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Unified Security Scanner Platform                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   │
│  │   CLI Entry   │   │  VSCode Ext   │   │  CI/CD Plugin │   │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘   │
│          │                   │                   │             │
│          └───────────────────┼───────────────────┘             │
│                              │                                 │
│                    ┌─────────▼─────────┐                       │
│                    │  Orchestrator     │                       │
│                    │  - Task Queue     │                       │
│                    │  - Result Merger  │                       │
│                    │  - FP Filter      │                       │
│                    └─────────┬─────────┘                       │
│                              │                                 │
│          ┌───────────────────┼───────────────────┐             │
│          │                   │                   │             │
│  ┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐   │
│  │  TruffleHog   │   │   Semgrep     │   │ Custom NPM    │   │
│  │   Adapter     │   │   Adapter     │   │   Scanner     │   │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘   │
│          │                   │                   │             │
│          └───────────────────┼───────────────────┘             │
│                              │                                 │
│                    ┌─────────▼─────────┐                       │
│                    │  Result Processor │                       │
│                    │  - Deduplication  │                       │
│                    │  - Severity Score │                       │
│                    │  - Remediation    │                       │
│                    └─────────┬─────────┘                       │
│                              │                                 │
│          ┌───────────────────┼───────────────────┐             │
│          │                   │                   │             │
│  ┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐   │
│  │  SARIF 2.1.0  │   │     JSON      │   │  HTML Report  │   │
│  │   (GitHub)    │   │  (Pipeline)   │   │  (Dashboard)  │   │
│  └───────────────┘   └───────────────┘   └───────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

**Core Platform**
- **Language**: TypeScript 5.0+ (npm ecosystem alignment, type safety)
- **Runtime**: Node.js 20 LTS (ESM modules, native fetch)
- **Package Manager**: pnpm (fast, efficient monorepo support)
- **Build Tool**: tsup (fast bundling, tree-shaking)

**Scanner Integration**
- **TruffleHog**: v3.x via subprocess/API
- **Semgrep**: v1.x via subprocess/API
- **Custom Scanners**: In-process TypeScript modules

**Analysis Engine**
- **AST Parser**: @babel/parser (React/JSX support)
- **Pattern Matching**: regex2 (faster than native regex)
- **Entropy Detection**: Shannon entropy (adapted from TruffleHog)
- **Taint Analysis**: Custom implementation inspired by MCP Sentinel Scanner

**False Positive Reduction**
- **ML Model**: TensorFlow.js Lite (on-device inference, no cloud calls)
- **Training Data**: Open-source vulnerability datasets + labeled false positives
- **Context Analysis**: AST + surrounding code inspection

**Output & Integration**
- **Formats**: SARIF 2.1.0, JSON, Markdown, HTML, JUnit XML
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, Bitbucket, CircleCI
- **IDE**: VSCode extension, IntelliJ plugin (Phase 2)

---

## Core Features

### 1. Multi-Tool Orchestration

**Description**: Intelligent coordination of security tools based on file types and scan targets.

**Capabilities**:
- **Smart Routing**: `.tsx` files → Semgrep React rules + Custom hooks analyzer
- **Parallel Execution**: Run TruffleHog + Semgrep + Custom scanners concurrently
- **Resource Management**: Limit concurrent processes based on CPU cores
- **Incremental Scanning**: Only scan changed files in CI/CD

**User Stories**:
- **US-001**: As a developer, I want to scan my React app with one command so I don't need to learn 5 different tools
- **US-002**: As a DevOps engineer, I want scans to finish in <5 minutes so CI/CD pipelines aren't blocked

**Acceptance Criteria**:
```gherkin
Feature: Multi-tool orchestration
  Scenario: Scan React project with multiple tools
    Given a React project with 10,000 lines of code
    When I run "unified-scanner scan ."
    Then TruffleHog, Semgrep, and NPM scanner run in parallel
    And the scan completes in under 60 seconds
    And results are merged into a single report
```

### 2. React/npm-Specific Detection

**Description**: Custom rules for React and npm ecosystem vulnerabilities.

**React Vulnerability Patterns**:

| Pattern | Severity | Example | Detection Method |
|---------|----------|---------|------------------|
| Hardcoded API keys in .env files | CRITICAL | `REACT_APP_API_KEY="sk-..."` | Regex + entropy |
| Dangerously set innerHTML | HIGH | `<div dangerouslySetInnerHTML={{__html: userInput}}` | AST analysis |
| Hardcoded credentials in hooks | CRITICAL | `const API_KEY = "abc123"` | AST + taint |
| Insecure localStorage usage | MEDIUM | `localStorage.setItem('token', jwt)` | Pattern match |
| Missing prop validation | LOW | Component without PropTypes/TS | AST analysis |
| useEffect dependency issues | MEDIUM | Missing dependency in array | React Hooks linter |
| Context API secrets exposure | HIGH | API keys in context provider | AST + taint |

**npm Package Vulnerabilities**:
- **Dependency Confusion**: Detect internal package names in package.json
- **Typosquatting**: Levenshtein distance check against npm registry
- **Outdated Dependencies**: Cross-reference with npm audit/Snyk database
- **Malicious Scripts**: Analyze package.json scripts for suspicious commands

**User Stories**:
- **US-003**: As a React developer, I want to detect hardcoded API keys in my .env files before they reach production
- **US-004**: As a security engineer, I want to identify all usages of dangerouslySetInnerHTML with untrusted data

**Acceptance Criteria**:
```gherkin
Feature: React-specific vulnerability detection
  Scenario: Detect hardcoded credentials in React hooks
    Given a component file with:
      """
      const useAuth = () => {
        const API_KEY = "sk-1234567890abcdef"; // Hardcoded
        return { apiKey: API_KEY };
      }
      """
    When I run the scanner
    Then it detects a CRITICAL finding
    And the finding includes line number and remediation
    And suggests using environment variables
```

### 3. False Positive Reduction Engine

**Description**: ML-powered and rule-based system to eliminate false positives.

**Strategies** (adapted from MCP Sentinel Scanner):

1. **Context-Aware Analysis**
```typescript
// FALSE POSITIVE: Test fixture
describe('Auth test', () => {
  const MOCK_API_KEY = 'test-key-12345'; // Entropy high but context = test
});

// TRUE POSITIVE: Production code
export const API_KEY = 'sk-prod-abc123'; // High entropy + production context
```

2. **String Concatenation Detection**
```typescript
// FALSE POSITIVE: Pattern definition
const DANGEROUS_PATTERNS = ['eval', 'innerHTML']; // Scanner's own rules

// TRUE POSITIVE: Actual usage
const result = eval(userInput); // Real vulnerability
```

3. **Exclusion Patterns**
```json
{
  "false_positive_patterns": [
    {
      "file": "**/*.test.tsx",
      "pattern": "API_KEY|SECRET|PASSWORD",
      "reason": "Test fixtures with mock credentials"
    },
    {
      "file": "**/storybook/**",
      "pattern": ".*",
      "reason": "Component documentation"
    }
  ]
}
```

4. **ML-Based Classification**
```typescript
interface FalsePositiveFeatures {
  fileType: 'test' | 'story' | 'config' | 'source';
  hasTestKeywords: boolean; // 'mock', 'fixture', 'example'
  entropyScore: number; // 0.0-1.0
  contextSurrounding: string[]; // 5 lines before/after
  inCommentBlock: boolean;
  variableNamePattern: string; // MOCK_, TEST_, EXAMPLE_
}

// TensorFlow.js model trained on 10K+ labeled samples
const isProbablyFalsePositive = mlModel.predict(features);
```

**User Stories**:
- **US-005**: As a developer, I want test files excluded from secret scans so I'm not overwhelmed with fake alerts
- **US-006**: As a security engineer, I want to train the scanner on our codebase patterns to reduce false positives

**Acceptance Criteria**:
```gherkin
Feature: False positive reduction
  Scenario: Exclude test fixtures
    Given a test file with mock credentials
    When I run the scanner with default config
    Then the mock credentials are not flagged
    And a summary shows "5 findings excluded (test context)"

  Scenario: ML-based classification
    Given a finding with high entropy in a variable named "EXAMPLE_TOKEN"
    When the ML model analyzes the context
    Then it classifies as false positive with 92% confidence
    And the finding is suppressed with explanation
```

### 4. Unified Reporting

**Description**: Consistent output format across all tools with actionable remediation.

**Output Formats**:

1. **Terminal (CLI)**
```
┌─────────────────────────────────────────────────────────────┐
│  Unified Security Scanner v1.0                              │
│  Scanned: 1,247 files (10,432 LOC) in 42.3s               │
├─────────────────────────────────────────────────────────────┤
│  CRITICAL: 2  │  HIGH: 5  │  MEDIUM: 12  │  LOW: 8         │
└─────────────────────────────────────────────────────────────┘

🔴 CRITICAL [CWE-798] Hardcoded API Key
   src/config/api.ts:12
   const API_KEY = "sk-proj-abc123def456";

   🔧 Remediation:
   Move to environment variable:
   const API_KEY = process.env.REACT_APP_API_KEY;

   📚 References:
   - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
   - CWE-798: Use of Hard-coded Credentials

─────────────────────────────────────────────────────────────

🟠 HIGH [CWE-79] Unsafe HTML Injection
   src/components/UserProfile.tsx:45
   <div dangerouslySetInnerHTML={{__html: userBio}} />

   🔧 Remediation:
   Use DOMPurify to sanitize:
   import DOMPurify from 'dompurify';
   <div dangerouslySetInnerHTML={{
     __html: DOMPurify.sanitize(userBio)
   }} />

   📚 References:
   - https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
```

2. **SARIF 2.1.0 (GitHub Security)**
```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Unified Security Scanner",
        "version": "1.0.0",
        "rules": [
          {
            "id": "hardcoded-api-key",
            "name": "HardcodedApiKey",
            "shortDescription": {
              "text": "Hardcoded API key detected"
            },
            "properties": {
              "tags": ["security", "credentials", "react"],
              "precision": "high"
            }
          }
        ]
      }
    },
    "results": [...]
  }]
}
```

3. **Interactive HTML Dashboard**
```html
<!-- Chart.js visualization with drill-down -->
<canvas id="severityChart"></canvas>
<canvas id="categoryChart"></canvas>
<canvas id="trendChart"></canvas>

<!-- Filterable table -->
<table id="findingsTable">
  <thead>
    <tr>
      <th>Severity</th>
      <th>Category</th>
      <th>File</th>
      <th>Line</th>
      <th>Remediation</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    <!-- Generated from scan results -->
  </tbody>
</table>
```

**User Stories**:
- **US-007**: As a developer, I want to see scan results in my terminal with clear remediation steps
- **US-008**: As a manager, I want an HTML dashboard showing security trends over time

**Acceptance Criteria**:
```gherkin
Feature: Unified reporting
  Scenario: Generate SARIF for GitHub
    Given a scan with 10 findings
    When I run "unified-scanner scan --format=sarif"
    Then a valid SARIF 2.1.0 file is created
    And it can be uploaded to GitHub Security tab
    And all findings appear with correct severity

  Scenario: Interactive HTML dashboard
    Given scan results from last 30 days
    When I run "unified-scanner dashboard"
    Then an HTML file opens in browser
    And it shows severity trends as line chart
    And I can filter by severity/category
```

### 5. CI/CD Integration

**Description**: Seamless integration with popular CI/CD platforms.

**Supported Platforms**:
- GitHub Actions
- GitLab CI
- Jenkins (Declarative + Scripted)
- Bitbucket Pipelines
- CircleCI
- Azure DevOps

**GitHub Actions Example**:
```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run Unified Scanner
        uses: unified-scanner/action@v1
        with:
          config: .security/production.json
          fail-on: critical,high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/results.sarif

      - name: Comment on PR
        uses: unified-scanner/pr-comment@v1
        with:
          results: reports/results.json
```

**User Stories**:
- **US-009**: As a DevOps engineer, I want to block PRs with CRITICAL findings automatically
- **US-010**: As a developer, I want scan results posted as PR comments so I can fix issues before merge

**Acceptance Criteria**:
```gherkin
Feature: GitHub Actions integration
  Scenario: Block PR on critical findings
    Given a PR with 1 CRITICAL finding
    When the security scan workflow runs
    Then the workflow fails with exit code 1
    And a comment is posted with finding details
    And the PR cannot be merged
```

---

## Technical Requirements

### Performance Requirements

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Scan Speed (10K LOC) | <60 seconds | Time from CLI start to report generation |
| Memory Usage | <512 MB | Peak RSS during scan |
| CPU Usage | <80% (4 cores) | Average CPU % during scan |
| Startup Time | <2 seconds | CLI init to first file scanned |
| Incremental Scan | <10 seconds | Only changed files (git diff) |

**Optimization Strategies**:
- **Parallel Processing**: Worker pool (4-8 workers based on CPU cores)
- **Caching**: Hash-based result caching for unchanged files
- **Streaming**: Process files as they're discovered, don't wait for full list
- **Smart Scheduling**: Run fast scanners first (pattern matching before AST)

### Scalability Requirements

| Project Size | LOC | Files | Scan Time | Workers |
|--------------|-----|-------|-----------|---------|
| Small | <5K | <100 | <30s | 2 |
| Medium | 5K-50K | 100-1K | <2min | 4 |
| Large | 50K-200K | 1K-5K | <5min | 8 |
| Enterprise | >200K | >5K | <15min | 16 |

**Horizontal Scaling** (Phase 2):
- Distributed scanning across CI/CD runners
- Result aggregation via central coordinator
- Shared cache layer (Redis/Memcached)

### Security Requirements

| Requirement | Implementation | Validation |
|-------------|----------------|------------|
| No data exfiltration | All processing local, no external API calls | Network activity audit |
| Secure credential handling | Never log/store found secrets | Code review + tests |
| SBOM generation | Track all dependencies | CycloneDX format |
| Supply chain security | Verify tool signatures | Sigstore/cosign |
| Least privilege | Run as non-root user | Docker/container tests |

### Compatibility Requirements

**Node.js Versions**: 18.x, 20.x (LTS), 22.x
**Operating Systems**: Linux, macOS, Windows
**Package Managers**: npm, yarn, pnpm, bun
**Frameworks**: React 16-18, Next.js 12-14, Vue 3, Angular 14+

---

## Data Model

### Configuration Schema

```typescript
interface UnifiedScannerConfig {
  version: string; // Config schema version

  // Tool orchestration
  tools: {
    truffleHog: {
      enabled: boolean;
      version?: string; // Pin specific version
      args?: string[]; // Additional CLI args
      exclude?: string[]; // Tool-specific exclusions
    };
    semgrep: {
      enabled: boolean;
      rules: string[]; // Rule IDs or paths
      config?: string; // Path to semgrep.yml
    };
    customScanners: {
      enabled: boolean;
      modules: string[]; // Paths to custom scanner modules
    };
  };

  // Scan configuration
  scan: {
    target: string; // Path to scan
    exclude: string[]; // Glob patterns
    includeTests: boolean;
    maxFileSize: number; // Bytes
    maxDepth: number; // Directory depth
    followSymlinks: boolean;
  };

  // False positive reduction
  falsePositives: {
    mlModel: {
      enabled: boolean;
      modelPath?: string; // Custom model
      confidenceThreshold: number; // 0.0-1.0
    };
    patterns: Array<{
      file: string; // Glob pattern
      pattern: string; // Regex
      reason: string;
    }>;
    excludeTestFiles: boolean;
    excludeStorybook: boolean;
  };

  // Output configuration
  output: {
    formats: Array<'terminal' | 'json' | 'sarif' | 'html' | 'markdown'>;
    dir: string; // Output directory
    verbose: boolean;
    quiet: boolean;
  };

  // Severity configuration
  severity: {
    threshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    failOn: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>;
  };

  // Performance tuning
  performance: {
    parallelWorkers: number;
    cacheEnabled: boolean;
    cacheDir?: string;
    incrementalScan: boolean;
  };
}
```

### Finding Schema

```typescript
interface Finding {
  // Identification
  id: string; // Unique UUID
  ruleId: string; // e.g., "hardcoded-api-key"
  source: 'truffleHog' | 'semgrep' | 'custom-npm' | 'custom-react';

  // Classification
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: 'secrets' | 'injection' | 'auth' | 'crypto' | 'dependency' | 'other';
  cwe?: string; // CWE-798
  owasp?: string; // A07:2021

  // Location
  file: string; // Relative path
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;

  // Content
  title: string; // "Hardcoded API Key"
  description: string; // Detailed explanation
  snippet: string; // Code snippet

  // Remediation
  remediation: {
    summary: string; // Short fix description
    code?: string; // Example fix
    references: string[]; // URLs to docs
    effort: 'low' | 'medium' | 'high'; // Estimated fix time
  };

  // Metadata
  confidence: number; // 0.0-1.0
  falsePositiveProbability?: number; // ML model output
  suppressedBy?: string; // 'ml-model' | 'config' | 'comment'

  // Timestamps
  detectedAt: string; // ISO 8601
  firstSeenAt?: string; // Trend tracking
}
```

### Scan Result Schema

```typescript
interface ScanResult {
  // Metadata
  scanId: string; // UUID
  version: string; // Scanner version
  startedAt: string; // ISO 8601
  completedAt: string;
  duration: number; // Seconds

  // Scan info
  target: string; // Path scanned
  filesScanned: number;
  linesOfCode: number;

  // Tool execution
  toolsRun: Array<{
    name: string;
    version: string;
    duration: number;
    exitCode: number;
    error?: string;
  }>;

  // Findings
  findings: Finding[];
  suppressed: Finding[]; // False positives

  // Statistics
  stats: {
    total: number;
    bySeverity: Record<Finding['severity'], number>;
    byCategory: Record<Finding['category'], number>;
    bySource: Record<Finding['source'], number>;
    suppressedCount: number;
  };

  // Performance
  performance: {
    parallelWorkers: number;
    cacheHitRate: number; // 0.0-1.0
    incrementalScan: boolean;
  };
}
```

---

## Implementation Roadmap

### Phase 1: MVP (0-3 months)

**Goal**: Core scanning with TruffleHog + Semgrep orchestration

**Deliverables**:
- ✅ CLI with basic scan command
- ✅ TruffleHog adapter (secrets detection)
- ✅ Semgrep adapter (pattern matching)
- ✅ Result merger (deduplicate, normalize)
- ✅ SARIF 2.1.0 output
- ✅ GitHub Actions workflow
- ✅ Documentation (README, API docs)

**Success Criteria**:
- Scan 10K LOC React project in <2 minutes
- Detect 90%+ of known vulnerabilities (OWASP benchmark)
- False positive rate <30%
- 80% test coverage

**Resources**:
- 2 Senior Engineers (TypeScript, Security)
- 1 DevOps Engineer (CI/CD integration)

### Phase 2: False Positive Reduction (3-6 months)

**Goal**: Reduce false positives to <10% through ML and rule refinement

**Deliverables**:
- ✅ Context-aware analysis engine
- ✅ ML model training pipeline
- ✅ Pre-trained model for React/npm codebases
- ✅ Custom exclusion rules UI
- ✅ HTML dashboard with trend tracking
- ✅ Incremental scanning (git diff)

**Success Criteria**:
- False positive rate <10%
- ML model accuracy >90%
- Scan time reduced by 50% (incremental mode)
- 85% test coverage

**Resources**:
- 1 ML Engineer (TensorFlow.js)
- 1 Frontend Engineer (Dashboard UI)
- 2 Senior Engineers (continued)

### Phase 3: React/npm Specialization (6-9 months)

**Goal**: Industry-leading React and npm vulnerability detection

**Deliverables**:
- ✅ Custom React hooks analyzer
- ✅ React Context API security rules
- ✅ npm dependency confusion detector
- ✅ Typosquatting detection
- ✅ VSCode extension
- ✅ IntelliJ plugin

**Success Criteria**:
- Detect 95%+ React-specific vulnerabilities
- <5% false positive rate
- IDE integrations used by 60% of users
- 90% test coverage

**Resources**:
- 1 React Expert (Custom rules)
- 1 IDE Integration Engineer
- Security QA Engineer

### Phase 4: Enterprise Features (9-12 months)

**Goal**: Enterprise-ready with compliance reporting and scalability

**Deliverables**:
- ✅ Policy engine (custom org rules)
- ✅ Compliance reports (SOC 2, ISO 27001, PCI-DSS)
- ✅ Distributed scanning (multi-runner)
- ✅ SBOM generation (CycloneDX)
- ✅ API server mode (REST API)
- ✅ SSO integration (SAML, OAuth)

**Success Criteria**:
- Scan 200K+ LOC in <10 minutes
- 5 enterprise customers
- 95% test coverage
- SOC 2 Type II certified

**Resources**:
- Enterprise Architect
- Compliance Engineer
- 2 Senior Engineers
- Technical Writer

---

## Development Workflow

### Repository Structure

```
unified-scanner/
├── packages/
│   ├── core/                    # Core scanning engine
│   │   ├── src/
│   │   │   ├── orchestrator/
│   │   │   ├── adapters/
│   │   │   │   ├── truffleHog.ts
│   │   │   │   ├── semgrep.ts
│   │   │   │   └── custom.ts
│   │   │   ├── analyzers/
│   │   │   │   ├── react-hooks.ts
│   │   │   │   ├── npm-packages.ts
│   │   │   │   └── taint-analysis.ts
│   │   │   ├── reporters/
│   │   │   │   ├── sarif.ts
│   │   │   │   ├── html.ts
│   │   │   │   └── terminal.ts
│   │   │   └── fp-reducer/
│   │   │       ├── ml-model.ts
│   │   │       └── rule-engine.ts
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── cli/                     # Command-line interface
│   │   ├── src/
│   │   │   ├── commands/
│   │   │   │   ├── scan.ts
│   │   │   │   ├── dashboard.ts
│   │   │   │   └── config.ts
│   │   │   └── index.ts
│   │   └── package.json
│   │
│   ├── vscode-extension/        # VSCode integration
│   ├── intellij-plugin/         # IntelliJ integration
│   └── github-action/           # GitHub Action
│
├── configs/
│   ├── default.json
│   ├── react.json
│   ├── npm.json
│   └── ci.json
│
├── rules/
│   ├── react/
│   │   ├── hooks.yml
│   │   ├── context.yml
│   │   └── dangerouslySetInnerHTML.yml
│   └── npm/
│       ├── dependency-confusion.yml
│       └── typosquatting.yml
│
├── ml-models/
│   ├── false-positive-classifier/
│   │   ├── model.json
│   │   ├── weights.bin
│   │   └── training/
│   └── severity-scorer/
│
├── docs/
│   ├── API.md
│   ├── RULES.md
│   ├── CONTRIBUTING.md
│   └── ARCHITECTURE.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── release.yml
│
├── .claude/
│   ├── prompts/
│   │   ├── false-positive-analysis.md
│   │   ├── rule-creation.md
│   │   └── refactoring.md
│   └── README.md
│
├── .claude_code_rules          # Claude Code configuration
├── pnpm-workspace.yaml
├── turbo.json                  # Turborepo config
└── package.json
```

### Testing Strategy

**Test Coverage Targets**:
- Core scanning engine: 95%+
- Adapters: 90%+
- Reporters: 100%
- CLI: 85%+
- Overall: 90%+

**Test Pyramid**:

```
        ┌─────────────────┐
        │  E2E Tests (5%) │  <- Full workflow, real repos
        │  20 scenarios   │
        └─────────────────┘
             ▲
             │
        ┌─────────────────────┐
        │ Integration (15%)   │  <- Tool adapters, pipelines
        │ 100 tests           │
        └─────────────────────┘
             ▲
             │
        ┌───────────────────────────┐
        │  Unit Tests (80%)         │  <- Pure functions, analyzers
        │  600+ tests               │
        └───────────────────────────┘
```

**Test Data**:
- **Vulnerable Sample Projects**: 50+ synthetic React apps with known vulnerabilities
- **Regression Suite**: 200+ real-world false positive cases
- **Benchmark Suite**: OWASP Benchmark, DamnVulnerableReactApp

**CI Pipeline**:
```yaml
stages:
  - lint:        # ESLint, Prettier, TSC
  - test:        # Jest unit + integration
  - security:    # Self-scan with unified-scanner
  - build:       # tsup bundle
  - e2e:         # Playwright
  - publish:     # npm publish (on release)
```

### Code Quality Standards

**Linting**:
- ESLint (Airbnb config)
- Prettier (100 char line length)
- TypeScript strict mode

**Metrics**:
- Cyclomatic complexity: <10
- Code duplication: <3%
- Function length: <50 lines
- File length: <500 lines

**Documentation**:
- JSDoc for all public APIs
- README for each package
- Architecture decision records (ADRs)

---

## False Positive Elimination Strategy

### Baseline False Positive Analysis (from MCP Sentinel Scanner learnings)

**Common False Positive Categories**:

| Category | % of FP | Root Cause | Solution |
|----------|---------|------------|----------|
| Test fixtures | 40% | Mock credentials in test files | Exclude test directories |
| Documentation | 25% | Example code in READMEs/docs | Exclude .md, .mdx files |
| Scanner self-detection | 15% | Pattern definitions detected | String concatenation |
| Configuration | 10% | Default/example configs | Context analysis |
| Third-party code | 10% | node_modules, vendor | Exclusion patterns |

### Multi-Layer Filtering Strategy

**Layer 1: Pre-Scan Exclusions** (90% FP reduction)
```typescript
const DEFAULT_EXCLUSIONS = [
  // Test files
  '**/*.test.{ts,tsx,js,jsx}',
  '**/*.spec.{ts,tsx,js,jsx}',
  '**/__tests__/**',
  '**/__mocks__/**',

  // Documentation
  '**/*.md',
  '**/*.mdx',
  '**/docs/**',
  '**/.storybook/**',

  // Dependencies
  '**/node_modules/**',
  '**/vendor/**',
  '**/dist/**',
  '**/build/**',

  // Config examples
  '**/*.example.{json,yml,yaml}',
  '**/*.sample.{json,yml,yaml}',
  '**/example.config.*',
];
```

**Layer 2: Context Analysis** (95% FP reduction)
```typescript
function isLikelyFalsePositive(finding: Finding, context: Context): boolean {
  // Check file type
  if (context.fileType === 'test' || context.fileType === 'story') {
    return true;
  }

  // Check variable naming
  const testPrefixes = ['MOCK_', 'TEST_', 'EXAMPLE_', 'SAMPLE_', 'FIXTURE_'];
  if (testPrefixes.some(prefix => finding.snippet.includes(prefix))) {
    return true;
  }

  // Check surrounding code
  const surroundingLines = context.getSurroundingLines(finding.line, 5);
  const hasTestKeywords = /describe|it\(|test\(|expect\(|jest\./i.test(
    surroundingLines.join('\n')
  );
  if (hasTestKeywords) {
    return true;
  }

  // Check comments
  const hasNoSecComment = context.getLineComment(finding.line)?.includes('nosec');
  if (hasNoSecComment) {
    return true;
  }

  return false;
}
```

**Layer 3: ML Classification** (98% FP reduction target)
```typescript
interface MLFeatures {
  // File context
  fileType: 'source' | 'test' | 'config' | 'docs';
  filePathDepth: number;
  inNodeModules: boolean;

  // Variable context
  variableName: string;
  hasTestPrefix: boolean;
  isConstant: boolean;
  isExported: boolean;

  // Code context
  inFunctionScope: boolean;
  inClassScope: boolean;
  inCommentBlock: boolean;
  surroundingCodeComplexity: number;

  // Finding metadata
  severity: Finding['severity'];
  category: Finding['category'];
  entropyScore: number;
  patternMatchCount: number;

  // Historical context
  previouslyFlagged: boolean;
  previouslySupressed: boolean;
  timesSeenInRepo: number;
}

class FalsePositiveClassifier {
  private model: tf.LayersModel;

  async predict(finding: Finding, context: Context): Promise<{
    isFalsePositive: boolean;
    confidence: number;
    reasoning: string;
  }> {
    const features = this.extractFeatures(finding, context);
    const tensor = tf.tensor2d([features]);
    const prediction = this.model.predict(tensor) as tf.Tensor;
    const confidence = (await prediction.data())[0];

    return {
      isFalsePositive: confidence > 0.7,
      confidence,
      reasoning: this.explainPrediction(features, confidence),
    };
  }
}
```

**Layer 4: Interactive Review** (99%+ FP reduction)
```bash
# Generate report with FP candidates
$ unified-scanner scan . --review-mode

# Interactive CLI
? Found 25 potential false positives. Review? (Y/n)

📄 src/utils/auth.test.ts:42
   const MOCK_API_KEY = "sk-test-12345";

   ML Confidence: 92% false positive
   Reason: Test file + MOCK_ prefix + test context

   [S]uppress  [K]eep  [N]ext  [Q]uit

> S

✓ Added suppression rule:
  File: **/*.test.ts
  Pattern: MOCK_.*
  Reason: Test fixtures with mock credentials
```

### Continuous Improvement Loop

```
┌─────────────────────────────────────────────────────────────┐
│  False Positive Reduction Feedback Loop                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Scan Production Codebase                                │
│     ↓                                                        │
│  2. Users Mark False Positives                              │
│     ↓                                                        │
│  3. Collect Labeled Data                                    │
│     ↓                                                        │
│  4. Retrain ML Model (weekly)                               │
│     ↓                                                        │
│  5. Update Pattern Rules                                    │
│     ↓                                                        │
│  6. Deploy New Model Version                                │
│     ↓                                                        │
│  7. Measure FP Rate (target: <5%)                           │
│     ↓                                                        │
│  └──────────────────────────────────┐                       │
│                                     │                       │
│  ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ←┘                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Metrics Dashboard**:
```typescript
interface FPMetrics {
  totalFindings: number;
  suppressedByML: number;
  suppressedByRules: number;
  suppressedByUser: number;
  falsePositiveRate: number; // target: <0.05
  precisionScore: number;    // target: >0.95
  recallScore: number;       // target: >0.90
  f1Score: number;           // target: >0.92
}
```

---

## Security & Privacy

### Data Handling

**What We Scan**:
- ✅ Source code (local filesystem only)
- ✅ Configuration files
- ✅ package.json dependencies

**What We Never Store**:
- ❌ Found credentials (logged but never persisted)
- ❌ Source code (processed in-memory only)
- ❌ User data

**Telemetry** (opt-in only):
```typescript
interface TelemetryData {
  // Anonymous usage stats
  scanCount: number;
  avgScanTime: number;
  findingCounts: Record<Finding['severity'], number>;

  // Performance metrics
  avgMemoryUsage: number;
  avgCpuUsage: number;

  // NO source code, NO file paths, NO credentials
}
```

### Supply Chain Security

**Dependency Management**:
- Weekly automated dependency updates (Renovate)
- npm audit on every commit
- Snyk vulnerability scanning
- SBOM generation (CycloneDX)

**Tool Verification**:
```typescript
// Verify TruffleHog and Semgrep signatures before execution
const TRUFFLEHOG_CHECKSUM = 'sha256:abc123...';
const SEMGREP_CHECKSUM = 'sha256:def456...';

async function verifyToolIntegrity(toolPath: string, expectedChecksum: string) {
  const actualChecksum = await computeSHA256(toolPath);
  if (actualChecksum !== expectedChecksum) {
    throw new Error('Tool integrity check failed');
  }
}
```

### Secure Defaults

```typescript
const SECURE_DEFAULTS = {
  // Never log found secrets
  logSecrets: false,

  // Run with minimal permissions
  runAsUser: 'scanner',

  // Sandboxed tool execution
  useContainer: true,

  // No network access
  networkIsolation: true,

  // Encrypted cache
  cacheEncryption: true,
};
```

---

## Success Metrics & KPIs

### Product Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Adoption Rate** | 1,000 active users in 6 months | Weekly active scanners |
| **False Positive Rate** | <5% | User feedback + manual review |
| **Detection Accuracy** | >95% | OWASP Benchmark score |
| **Scan Performance** | <60s for 10K LOC | P95 latency |
| **CI/CD Integration Rate** | 70% of users | GitHub Actions usage |
| **User Satisfaction** | NPS >50 | Quarterly survey |

### Technical Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Test Coverage** | >90% | Jest coverage report |
| **Code Quality** | Complexity <10 | SonarQube analysis |
| **Uptime** | 99.9% (API mode) | Status page |
| **Scan Success Rate** | >99% | Error tracking (Sentry) |
| **Memory Efficiency** | <512MB for 50K LOC | Heap profiling |

### Business Metrics

| Metric | Target | Timeline |
|--------|--------|----------|
| **Open Source Stars** | 1,000 stars | 6 months |
| **Contributors** | 20 contributors | 12 months |
| **Enterprise Customers** | 5 paying customers | 12 months |
| **ARR** | $100K | 18 months |

---

## Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| TruffleHog/Semgrep breaking changes | Medium | High | Pin versions, adapter abstraction layer |
| ML model accuracy plateaus | Medium | Medium | Hybrid ML + rule-based approach |
| Performance doesn't scale | Low | High | Early benchmarking, optimization focus |
| False positive rate stays high | High | Critical | Multi-layer filtering, user feedback loop |

### Market Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| GitHub CodeQL improves React support | Medium | High | Focus on speed + false positive reduction |
| Snyk releases similar product | Low | Medium | Open-source advantage, extensibility |
| Low developer adoption | Medium | High | Great DX, comprehensive docs, community building |

### Compliance Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| GDPR concerns with ML training data | Low | Medium | No PII in training data, clear privacy policy |
| Enterprise customers need SOC 2 | High | Medium | Phase 4 compliance certification |

---

## Open Questions

1. **ML Model Hosting**: Should we bundle the model with the CLI (<50MB) or offer on-demand download?
   - **Recommendation**: Bundle lightweight model (<10MB), offer high-accuracy model as download

2. **Semgrep Rules**: Use public semgrep-rules repo or maintain custom fork?
   - **Recommendation**: Fork + extend with React/npm-specific rules

3. **Pricing Model** (if commercializing):
   - Free: CLI + open-source
   - Pro ($29/month): VSCode extension + HTML dashboard
   - Enterprise ($299/month): SSO + compliance reports + API server

4. **Community Contribution**: How to accept custom rule contributions?
   - **Recommendation**: GitHub PR workflow with rule validation tests

---

## Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| **AST** | Abstract Syntax Tree - tree representation of source code structure |
| **Entropy** | Measure of randomness in strings (high entropy = likely secret) |
| **SARIF** | Static Analysis Results Interchange Format (ISO/IEC 30106:2021) |
| **Taint Analysis** | Tracking data flow from untrusted sources to dangerous sinks |
| **False Positive** | Benign code flagged as vulnerable |
| **True Positive** | Actual vulnerability correctly identified |
| **CWE** | Common Weakness Enumeration (vulnerability classification) |
| **OWASP** | Open Web Application Security Project |

### B. References

1. **OWASP Top 10 (2021)**: https://owasp.org/Top10/
2. **CWE Top 25 (2024)**: https://cwe.mitre.org/top25/
3. **SARIF Specification**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
4. **TruffleHog Documentation**: https://github.com/trufflesecurity/trufflehog
5. **Semgrep Documentation**: https://semgrep.dev/docs/
6. **React Security Best Practices**: https://react.dev/learn/security
7. **npm Security Advisory Database**: https://github.com/advisories

### C. Related Projects

| Project | Strengths | Integration Approach |
|---------|-----------|---------------------|
| **TruffleHog** | Best-in-class secret detection | Subprocess adapter |
| **Semgrep** | Fast pattern matching | Subprocess adapter |
| **ESLint Security Plugin** | React-specific linting | Custom rule inspiration |
| **npm audit** | Dependency vulnerabilities | Package.json analyzer |
| **retire.js** | JavaScript library vulnerabilities | Integrate in Phase 3 |
| **DependaBot** | Automated dependency updates | Complementary tool |

### D. Example Use Cases

**Use Case 1: Pre-commit Hook**
```bash
# .husky/pre-commit
#!/bin/sh
unified-scanner scan --incremental --fail-on=critical,high --quiet
```

**Use Case 2: PR Comment Bot**
```yaml
# .github/workflows/pr-comment.yml
- uses: unified-scanner/pr-comment@v1
  with:
    results: reports/results.json
    comment-template: |
      ## 🔒 Security Scan Results
      Found {{total}} potential issues:
      - 🔴 Critical: {{critical}}
      - 🟠 High: {{high}}
      - 🟡 Medium: {{medium}}
```

**Use Case 3: Security Dashboard**
```bash
# Generate 30-day trend report
unified-scanner dashboard --days=30 --output=security-report.html
```

---

## Approval & Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Product Manager | __________ | __________ | __/__/____ |
| Engineering Lead | __________ | __________ | __/__/____ |
| Security Lead | __________ | __________ | __/__/____ |
| CTO | __________ | __________ | __/__/____ |

---

**Document Version**: 1.0
**Last Updated**: 2025-10-05
**Next Review**: 2025-11-05

---

## Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-05 | AI Engineering | Initial PRD based on MCP Sentinel Scanner learnings |

