# MCP Sentinel Scanner - Visual Guide

This document provides visual representations of the scanner architecture, workflows, and results.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Sentinel Scanner v1.5                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │         Input Processing Layer          │
        │  • File Collection                      │
        │  • Path Filtering                       │
        │  • Exclusion Logic                      │
        └─────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │      Parallel Processing (4-8 workers)  │
        └─────────────────────────────────────────┘
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  Pattern   │ │  AST       │ │  Secret    │
        │  Matching  │ │  Analysis  │ │  Detection │
        │            │ │            │ │            │
        │  • SQL Inj │ │  • eval()  │ │  • Entropy │
        │  • Cmd Inj │ │  • exec()  │ │  • Regex   │
        │  • XSS     │ │  • import  │ │  • Context │
        └────────────┘ └────────────┘ └────────────┘
                 │            │            │
                 └────────────┼────────────┘
                              ▼
        ┌─────────────────────────────────────────┐
        │       Advanced Detection Layer          │
        │  • Taint Analysis                       │
        │  • Auth Bypass Detection                │
        │  • Crypto Misuse Detection              │
        │  • Complexity Metrics                   │
        └─────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │       Result Aggregation & Scoring      │
        │  • ASR Calculation                      │
        │  • Severity Distribution                │
        │  • Confidence Scoring                   │
        └─────────────────────────────────────────┘
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  Terminal  │ │   JSON     │ │  SARIF     │
        │  Output    │ │  Export    │ │  Export    │
        └────────────┘ └────────────┘ └────────────┘
                 ▼            ▼            ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  Markdown  │ │   HTML     │ │   IDE      │
        │  Report    │ │  Dashboard │ │  Integration│
        └────────────┘ └────────────┘ └────────────┘
```

---

## 🔄 Workflow Diagrams

### Local Scan Workflow

```
┌───────────┐
│   User    │
│  Terminal │
└─────┬─────┘
      │
      │ mcp-scan /path/to/code
      ▼
┌─────────────────┐
│  CLI Parser     │
│  • Parse args   │
│  • Load config  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Scanner Init   │
│  • Setup workers│
│  • Load patterns│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  File Scan      │
│  • Collect files│
│  • Filter/exclude│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Analyze        │
│  • Pattern match│
│  • AST parse    │
│  • Taint track  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Generate Report│
│  • Format output│
│  • Calculate ASR│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Display/Save   │
│  • Terminal out │
│  • File write   │
└─────────────────┘
```

### CI/CD Workflow

```
┌──────────────┐
│  Git Push    │
│  to main     │
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────┐
│  GitHub      │────▶│  Checkout    │
│  Actions     │     │  Code        │
└──────────────┘     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  Pull Docker │
                     │  Image       │
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  Run Scan    │
                     │  --format    │
                     │  sarif       │
                     └──────┬───────┘
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
         ┌──────────┐┌──────────┐┌──────────┐
         │ Upload   ││ Archive  ││ PR       │
         │ SARIF to ││ Artifacts││ Comment  │
         │ Security ││          ││          │
         └──────────┘└──────────┘└──────────┘
                │           │           │
                └───────────┼───────────┘
                            ▼
                     ┌──────────────┐
                     │  Check       │
                     │  Thresholds  │
                     └──────┬───────┘
                            │
                    ┌───────┴───────┐
                    ▼               ▼
             ┌──────────┐    ┌──────────┐
             │  Pass ✅  │    │  Fail ❌  │
             └──────────┘    └──────────┘
```

---

## 📊 Scan Results Visualization

### Sample Terminal Output

```
┌──────────────────────────────────────────────────────────┐
│          MCP Sentinel Scanner - Scan Results             │
└──────────────────────────────────────────────────────────┘

Files Scanned:    2,563
Total Lines:      125,487
Vulnerabilities:  652
ASR Score:        75.00%

Severity Distribution:

  ████████████████████████████████████████ CRITICAL  (8)
  ██████████████████████████████████████████████ HIGH (11)
  ████████████████ MEDIUM (2)
  ████ LOW (1)

Top Categories:

  path_traversal      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  400
  hardcoded_secret    ▓▓▓▓▓▓▓▓▓▓▓▓          252

┌──────────────────────────────────────────────────────────┐
│ Severity │ Category           │ File:Line    │ Conf.     │
├──────────┼────────────────────┼──────────────┼───────────┤
│ 🔴 CRITICAL│ dangerous_function│ app.py:36   │ 95%      │
│ 🔴 CRITICAL│ sql_injection     │ db.py:145   │ 85%      │
│ 🟠 HIGH    │ hardcoded_secret  │ config.py:12│ 74%      │
│ 🟡 MEDIUM  │ weak_crypto       │ utils.py:28 │ 70%      │
└──────────┴────────────────────┴──────────────┴───────────┘
```

### HTML Dashboard Preview

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                  🛡️ MCP SENTINEL SECURITY REPORT              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

┌───────────────┬───────────────┬───────────────┬───────────────┐
│ Files Scanned │ Total Lines   │Vulnerabilities│   ASR Score   │
│               │               │               │               │
│     2,563     │   125,487     │      652      │    75.00%     │
└───────────────┴───────────────┴───────────────┴───────────────┘

                    Severity Distribution

            ┌────────────────────────────────┐
            │                                │
            │    ███                         │
            │  █████         ██              │
            │ ███████      ████              │
            │█████████    ██████     ██  █   │
            │─────────────────────────────── │
            │CRITICAL  HIGH  MEDIUM  LOW     │
            └────────────────────────────────┘

                    Category Breakdown

            ┌────────────────────────────────┐
            │path_traversal     ███████████  │
            │hardcoded_secret   ████████     │
            │sql_injection      ███          │
            │command_injection  ██           │
            │weak_crypto        █            │
            └────────────────────────────────┘
```

---

## 🔍 Detection Flow

### Taint Analysis Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Source Code                          │
│  user_input = request.form['data']                      │
│  query = "SELECT * FROM users WHERE id=" + user_input   │
│  cursor.execute(query)                                  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│               Taint Analysis Engine                     │
└─────────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐┌──────────────┐┌──────────────┐
│   Source     ││   Variable   ││    Sink      │
│  Detection   ││   Tracking   ││  Detection   │
│              ││              ││              │
│ request.form ││  user_input  ││ execute()    │
│   ✓ Found    ││  ✓ Tainted   ││  ✓ Found    │
└──────────────┘└──────────────┘└──────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Taint Path Found!                      │
│                                                         │
│  Source: request.form (line 1)                          │
│     ↓                                                   │
│  Variable: user_input (tainted)                         │
│     ↓                                                   │
│  Sink: cursor.execute (line 3)                          │
│                                                         │
│  Vulnerability: SQL Injection                           │
│  Confidence: 90%                                        │
│  Severity: CRITICAL                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 📈 Progress Timeline

### Roadmap Visual

```
Phase 1: Foundation         Phase 2: Advanced         Phase 3: Intelligence
  (Months 1-3)               (Months 4-6)               (Months 7-9)
     ✅ DONE                   ⚡ PARTIAL                 ⚡ PARTIAL

  │                         │                          │
  ├─ CLI Fix ✅              ├─ Taint Analysis ✅       ├─ ML Detection ⏳
  ├─ CI/CD ✅                ├─ SARIF Export ✅         ├─ Attack Graphs ⏳
  ├─ Error Tests ✅          ├─ Multi-Lang AST ⏳       ├─ HTML Reports ✅
  ├─ Unit Tests ✅           ├─ Crypto Detection ⏳     ├─ GitHub Action ⏳
  └─ Config Fix ✅           └─ Pattern Expand ⏳       └─ Webhooks ⏳


  Phase 4: Enterprise
   (Months 10-12)
     📋 PLANNED

        │
        ├─ Remote Scan ⏳
        ├─ Sandbox ⏳
        ├─ LLM Analysis ⏳
        └─ Dashboard ⏳

Legend: ✅ Complete  ⚡ Partial  ⏳ Planned  📋 Future
```

---

## 🎯 Deployment Options Matrix

```
╔════════════════════════════════════════════════════════════════╗
║                    Deployment Matrix                           ║
╠════════════════════════════════════════════════════════════════╣
║  Method     │ Speed │ Easy │ CI/CD │ Isolation │ Production   ║
╠═════════════╪═══════╪══════╪═══════╪═══════════╪══════════════╣
║  Docker     │  ⭐⭐⭐ │ ⭐⭐⭐ │  ⭐⭐⭐  │   ⭐⭐⭐    │     ⭐⭐⭐     ║
║  pip        │  ⭐⭐   │ ⭐⭐⭐ │  ⭐⭐   │    ⭐      │     ⭐⭐      ║
║  Source     │  ⭐    │  ⭐⭐  │   ⭐   │    ⭐      │     ⭐       ║
║  Compose    │  ⭐⭐⭐ │ ⭐⭐⭐ │  ⭐⭐   │   ⭐⭐⭐    │     ⭐⭐⭐     ║
║  K8s        │  ⭐⭐   │  ⭐   │  ⭐⭐⭐  │   ⭐⭐⭐    │     ⭐⭐⭐     ║
╚═════════════╧═══════╧══════╧═══════╧═══════════╧══════════════╝
```

---

## 📊 Feature Comparison Chart

```
╔══════════════════════════════════════════════════════════════╗
║         Feature Availability by Version                      ║
╠══════════════════════════════════════════════════════════════╣
║  Feature                │  v1.0  │  v1.5  │  v2.0 (Planned)  ║
╠═════════════════════════╪════════╪════════╪══════════════════╣
║  Pattern Detection      │   ✅   │   ✅   │       ✅          ║
║  AST Analysis (Python)  │   ✅   │   ✅   │       ✅          ║
║  Secret Detection       │   ✅   │   ✅   │       ✅          ║
║  Terminal Output        │   ✅   │   ✅   │       ✅          ║
║  JSON Export            │   ✅   │   ✅   │       ✅          ║
║  Markdown Export        │   ✅   │   ✅   │       ✅          ║
║  ─────────────────────  │  ────  │  ────  │      ────        ║
║  SARIF Export           │   ❌   │   ✅   │       ✅          ║
║  HTML Reports           │   ❌   │   ✅   │       ✅          ║
║  Taint Analysis         │   ❌   │   ✅   │       ✅          ║
║  Standalone CLI         │   ❌   │   ✅   │       ✅          ║
║  Docker Production      │   ❌   │   ✅   │       ✅          ║
║  ─────────────────────  │  ────  │  ────  │      ────        ║
║  TypeScript AST         │   ❌   │   ❌   │       ✅          ║
║  ML Detection           │   ❌   │   ❌   │       ✅          ║
║  Attack Graphs          │   ❌   │   ❌   │       ✅          ║
║  GitHub Action          │   ❌   │   ❌   │       ✅          ║
╚═════════════════════════╧════════╧════════╧══════════════════╝
```

---

## 🎨 Sample Report Screenshots

### Terminal Output (Colorized)

```
╔══════════════════════════════════════════════════════════════╗
║  🔴 CRITICAL  dangerous_function  app.py:36    95%           ║
║  🔴 CRITICAL  sql_injection       db.py:145    85%           ║
║  🟠 HIGH      hardcoded_secret    config.py:12 74%           ║
║  🟡 MEDIUM    weak_crypto         utils.py:28  70%           ║
║  🟢 LOW       complexity          main.py:5    50%           ║
╚══════════════════════════════════════════════════════════════╝
```

### ASR Score Gauge

```
    Attack Success Rate (ASR)

        ┌─────────────────────┐
        │                     │
    0%  ├─────────────────────┤  100%
        │█████████████████░░░░│  75%
        │   Current Score     │
        └─────────────────────┘

    🟢 LOW      (0-40%)   │████░░░░░░│
    🟡 MEDIUM   (40-60%)  │░░░░██░░░░│
    🟠 HIGH     (60-80%)  │░░░░░░███░│ ← You are here
    🔴 CRITICAL (80-100%) │░░░░░░░░██│
```

---

## 🔄 Data Flow Diagram

```
┌────────────┐
│  File In   │
└─────┬──────┘
      │
      ▼
┌─────────────────────┐
│  Read & Parse       │
│  • UTF-8 decode     │
│  • Split lines      │
│  • Count stats      │
└─────────┬───────────┘
          │
          ├─────────────┬──────────────┐
          ▼             ▼              ▼
    ┌─────────┐  ┌──────────┐  ┌──────────┐
    │ Pattern │  │   AST    │  │  Secret  │
    │ Scanner │  │ Analyzer │  │ Detector │
    └────┬────┘  └─────┬────┘  └─────┬────┘
         │             │             │
         ▼             ▼             ▼
    ┌─────────────────────────────────────┐
    │      Finding Aggregator             │
    │  • Deduplicate                      │
    │  • Score confidence                 │
    │  • Classify severity                │
    └────────────┬────────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────────┐
    │     Advanced Analysis (Optional)    │
    │  • Taint tracking                   │
    │  • Control flow                     │
    │  • Data flow                        │
    └────────────┬────────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────────┐
    │       Result Formatter              │
    │  • Calculate ASR                    │
    │  • Group by severity                │
    │  • Format output                    │
    └────────────┬────────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────────┐
    │      Output (JSON/HTML/SARIF)       │
    └─────────────────────────────────────┘
```

---

## 📦 Docker Container Structure

```
┌─────────────────────────────────────────────────┐
│         Docker Container (scanner:1000)         │
│                                                 │
│  /app/                                          │
│  ├── src/                                       │
│  │   ├── mcp_sentinel_scanner.py               │
│  │   ├── advanced_detection.py                 │
│  │   ├── taint_analysis.py                     │
│  │   └── reporters/                            │
│  │       ├── sarif_reporter.py                 │
│  │       └── html_reporter.py                  │
│  ├── scripts/                                   │
│  │   └── sentinel_cli.py                       │
│  ├── configs/                                   │
│  │   └── default_config.json                   │
│  └── tests/                                     │
│                                                 │
│  Volumes:                                       │
│  ├── /scan (read-only)  ← Your code            │
│  └── /reports           ← Generated reports    │
│                                                 │
│  User: scanner:scanner (non-root)              │
│  Healthcheck: Every 30s                         │
└─────────────────────────────────────────────────┘
```

---

## 🎯 Quick Reference: Common Commands

```
┌──────────────────────────────────────────────────────────┐
│                    Common Commands                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Local Scan:                                             │
│  $ mcp-scan /path/to/code                               │
│                                                          │
│  Docker Scan:                                            │
│  $ docker run --rm -v $(pwd):/scan \                    │
│    ghcr.io/.../scanner:latest /scan                     │
│                                                          │
│  HTML Report:                                            │
│  $ mcp-scan /path --format html -o report.html          │
│                                                          │
│  SARIF for IDE:                                          │
│  $ mcp-scan /path --format sarif -o results.sarif       │
│                                                          │
│  With Exclusions:                                        │
│  $ mcp-scan /path --exclude "*.d.ts" "node_modules"     │
│                                                          │
│  CI/CD (Fail on Critical):                              │
│  $ mcp-scan /path --format json -o r.json               │
│  $ jq '.scan_summary.severity_distribution.CRITICAL'    │
│      r.json | [ $CRITICAL -gt 0 ] && exit 1            │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 📈 Performance Metrics Visualization

```
Scan Performance (2,500 files)

Files/Second:
├─────────────────────────────────────────────────┤
│███████████████████████████████████████████      │ 57
└─────────────────────────────────────────────────┘
0                    50                        100

Memory Usage:
├─────────────────────────────────────────────────┤
│██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 245MB
└─────────────────────────────────────────────────┘
0                   500MB                      1GB

CPU Usage (4 workers):
├─────────────────────────────────────────────────┤
│███████████████████████████████░░░░░░░░░░░░░░░░░│ 65%
└─────────────────────────────────────────────────┘
0%                  50%                        100%
```

---

**For more visual representations, see:**
- [docs/ARCHITECTURE_DIAGRAMS.md](docs/ARCHITECTURE_DIAGRAMS.md) - Mermaid diagrams
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) - Feature matrices
- [STATUS.md](STATUS.md) - Project health metrics
