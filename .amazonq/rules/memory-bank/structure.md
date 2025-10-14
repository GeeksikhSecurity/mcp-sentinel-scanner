# MCP Sentinel Scanner - Project Structure

## Root Directory Organization

### Core Application (`/src/`)
- **Main Scanners** - Core scanning engines and unified scanner orchestration
- **Adapters** - Integration layers for external tools (Semgrep, TruffleHog)
- **Analyzers** - Language-specific analysis (NPM, React patterns)
- **Filters** - False positive reduction pipeline
- **Reporters** - Output format generation (HTML, SARIF, JSON)
- **Utils** - Shared utilities and repository management

### Configuration (`/configs/`)
- **default_config.json** - Base scanner configuration
- **security_rules.json** - Vulnerability detection patterns
- **false_positive_config.json** - FP filtering rules
- **unified_config.json** - Multi-tool orchestration settings
- **ci_config.json** - CI/CD pipeline configuration

### Scripts & CLI (`/scripts/`)
- **sentinel_cli.py** - Main command-line interface
- **enhanced_scan_cli.py** - Advanced scanning options
- **benchmark.py** - Performance testing utilities

### Testing (`/tests/`)
- **Unit Tests** - Component-level testing with 100% coverage
- **Integration Tests** - End-to-end scanning workflows
- **Test Data** - Vulnerable code samples for validation

### Documentation (`/docs/`)
- **Architecture Diagrams** - System design and data flow
- **Technical Documentation** - Implementation details
- **Deployment Guide** - Docker, CI/CD, and enterprise setup
- **Research Foundation** - Academic basis and methodology

## Core Components Architecture

### Multi-Tool Orchestration Pipeline
```
Input Code → Tool Adapters → Context Analysis → Result Aggregation → Output
     ↓           ↓              ↓                ↓               ↓
  File Tree → Semgrep     → Import Filter → Unified Results → SARIF/HTML
             TruffleHog   → Test Filter   → Risk Scoring   → Dashboard
             CodeQL       → Placeholder   → Confidence     → Reports
```

### False Positive Reduction Pipeline
```
Raw Findings → Context Analysis → Entropy Check → Pattern Match → Validated Results
      ↓             ↓               ↓              ↓                ↓
   Semgrep      Import Context   Shannon       Test/Demo        High-Confidence
   TruffleHog   Test Context     Entropy       Placeholders     Vulnerabilities
   CodeQL       File Path        Calculation   Fake Patterns    ASR Scoring
```

### Analysis Layers (7-Layer Security)
1. **Pattern Matching** - Static vulnerability patterns via Semgrep
2. **AST Analysis** - Code structure inspection and syntax analysis
3. **Secret Detection** - Entropy-based credential discovery via TruffleHog
4. **Taint Analysis** - Data flow vulnerability tracking
5. **Context Analysis** - Import/test/placeholder filtering
6. **ML Anomaly** - Behavioral pattern analysis
7. **Risk Scoring** - ASR calculation and priority assignment

## Key Architectural Patterns

### Adapter Pattern
- **SemgrepAdapter** - Normalizes Semgrep output to unified format
- **TruffleHogAdapter** - Processes secret detection results
- External tool integration without tight coupling

### Filter Chain Pattern
- **ImportFilter** - Removes development/test imports
- **TestContextFilter** - Identifies test file contexts
- **PlaceholderFilter** - Detects demo/example credentials
- **FalsePositiveFilter** - Master filter orchestration

### Strategy Pattern
- **HTMLReporter** - Interactive dashboard generation
- **SARIFReporter** - IDE and GitHub integration format
- **JSONReporter** - Machine-readable API output
- Pluggable output format selection

### Observer Pattern
- **ProgressReporter** - Real-time scan progress updates
- **MetricsCollector** - Performance and accuracy tracking
- Event-driven status reporting

## Data Flow Architecture

### Input Processing
1. **Repository Cloning** - Git repository acquisition and preparation
2. **File Discovery** - Language-specific file identification
3. **Exclusion Filtering** - Skip test files, dependencies, build artifacts

### Analysis Pipeline
1. **Multi-Tool Execution** - Parallel execution of security tools
2. **Result Normalization** - Unified vulnerability format
3. **Context Enrichment** - Add file path, import, and test context
4. **False Positive Filtering** - 7-stage filtering pipeline

### Output Generation
1. **Risk Scoring** - ASR calculation and severity assignment
2. **Report Generation** - Format-specific output creation
3. **Dashboard Creation** - Interactive HTML reports with Chart.js
4. **CI/CD Integration** - SARIF upload to security dashboards

## Scalability Architecture

### Performance Optimizations
- **Parallel Processing** - 16-32 worker threads for file analysis
- **Memory Management** - Efficient resource utilization (60% reduction)
- **Caching Strategy** - Result caching for incremental scans
- **Batch Processing** - Optimized for large codebases

### Enterprise Features
- **Configuration Management** - Environment-specific settings
- **Audit Logging** - Comprehensive scan history and metrics
- **API Integration** - RESTful endpoints for enterprise dashboards
- **Compliance Reporting** - Automated regulatory compliance reports