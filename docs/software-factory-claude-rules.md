# Software Factory Techniques — Claude Code Rules (Human-Reviewed)

**Adapted from:** [StrongDM Software Factory](https://factory.strongdm.ai) + [Simon Willison analysis](https://simonwillison.net/2026/Feb/7/software-factory/)
**Key divergence:** StrongDM says "Code must NOT be reviewed by humans." We say the opposite.

> **Our rule: Code MUST be reviewed by humans. Agents propose, humans approve.**

StrongDM's Dark Factory works for a 3-person team building integration software with $1,000/day token budgets. For security tooling (MCP Sentinel Scanner, CloudScope), where a missed vulnerability pattern means a missed real vulnerability — human review is the trust layer. We adopt the *techniques* but reject the *autonomy*.

---

## Core Philosophy

```
StrongDM:  Specs → Agent → Code → Scenario Validation → Ship (no human eyes on code)
Our model: Specs → Agent → Code → HUMAN REVIEW → Scenario Validation → Ship
```

Byron Wien's principle applies: "The hard way is always the right way." Reviewing AI-generated code is the hard way. It's also how you learn what the agent actually did, catch security-relevant mistakes, and maintain the ability to debug production issues.

---

## Technique 1: Pyramid Summaries

**StrongDM definition:** Reversible summarization at multiple zoom levels. Compress context without losing the ability to expand back to full detail.

**How agents use it:** Start with the one-line summary, zoom into the paragraph summary only if relevant, then expand to full detail only where needed.

### Claude Code Rules

```yaml
# PYRAMID SUMMARIES — Every module, class, and complex function gets three layers

pyramid_summary_required_for:
  - "New modules (files > 100 lines)"
  - "New classes"  
  - "Functions with cyclomatic complexity > 5"
  - "README sections"
  - "MEMORY.md entries"

pyramid_format:
  L0_headline: "One line. What this does and why it exists."
  L1_paragraph: "3-5 sentences. Key behaviors, dependencies, trade-offs."
  L2_full: "Complete docstring/documentation with examples, edge cases, security notes."

# Example for a scanner module:
# L0: "ReactAnalyzer — detects XSS, unsafe refs, and insecure patterns in JSX/TSX files."
# L1: "Pure-Python static analyzer for React codebases. Scans .jsx/.tsx/.js/.ts files
#      using regex pattern matching against 6 vulnerability categories. Extends BaseAnalyzer
#      for registry integration. No external deps. Returns VulnerabilityFinding objects."
# L2: [Full docstring with pattern list, severity mappings, false positive notes, examples]
```

### Human Review Checkpoint

Before merging any agent-generated code, verify:
- [ ] L0 summary accurately describes what the code does (not what the agent *intended*)
- [ ] L1 paragraph matches actual implementation (check deps, check what it returns)
- [ ] L2 documentation doesn't hallucinate edge cases or capabilities

---

## Technique 2: Gene Transfusion

**StrongDM definition:** Move working patterns between codebases by pointing agents at concrete exemplars. A solution paired with a good reference can be reproduced in new contexts.

**How agents use it:** "Look at how SemgrepAdapter implements BaseAdapter. Now implement TrivyAdapter following the same pattern."

### Claude Code Rules

```yaml
# GENE TRANSFUSION — Pattern reuse via concrete exemplars

gene_transfusion_workflow:
  1: "Identify the exemplar (working code that solves a similar problem)"
  2: "Point the agent at the exemplar explicitly: 'Follow the pattern in src/sentinel/adapters/semgrep.py'"
  3: "Agent generates new implementation"
  4: "HUMAN REVIEW: Compare new code against exemplar — did the agent preserve the important patterns?"
  5: "HUMAN REVIEW: Did the agent correctly adapt for the new context, or did it cargo-cult?"

exemplar_registry:
  adapter_pattern: "src/sentinel/adapters/semgrep.py"
  analyzer_pattern: "src/sentinel/analyzers/npm.py"
  cli_command_pattern: "src/sentinel/cli/main.py::scan_command"
  test_pattern: "tests/test_scanner.py"
  
transfusion_anti_patterns:
  - "Copying error handling that doesn't apply to new context"
  - "Preserving imports that aren't needed"
  - "Keeping comments that reference the exemplar, not the new code"
  - "Blindly copying security patterns without understanding threat model"
```

### Human Review Checkpoint

Before merging any gene-transfused code, verify:
- [ ] The *structural pattern* was preserved (ABC contract, error handling shape, test structure)
- [ ] The *context-specific details* were correctly adapted (different CLI flags, different output formats, different vulnerability categories)
- [ ] No cargo-culting (code copied that serves no purpose in the new context)

---

## Technique 3: Semport (Semantic Port)

**StrongDM definition:** Semantically-aware automated ports. Move code between languages or frameworks while preserving intent.

**How agents use it:** Port detection patterns from one language to another, port test fixtures across frameworks, port documentation between formats.

### Claude Code Rules

```yaml
# SEMPORT — Language/framework porting with intent preservation

semport_workflow:
  1: "Define the source artifact and target language/framework"
  2: "Agent performs the port"
  3: "HUMAN REVIEW: Does the ported code preserve the original INTENT, not just syntax?"
  4: "Run equivalent test suite in target language"
  5: "Compare outputs — same inputs should produce same findings"

semport_use_cases:
  - "Port Semgrep YAML rules → Python regex patterns (for builtin analyzer)"
  - "Port TypeScript MCP test fixtures → Python test fixtures"
  - "Port CodeQL queries → Semgrep rules"
  - "Port detection patterns from academic papers → scanner rules"

semport_gotchas:
  - "Regex flavor differences between languages (Python vs JS vs Go)"
  - "Path handling differences (os.path vs pathlib vs node path)"
  - "Error handling idioms (try/except vs Result types vs error returns)"
  - "String encoding assumptions"
```

### Human Review Checkpoint

Before merging any semported code, verify:
- [ ] Run both original and ported versions against the same test corpus
- [ ] Diff the outputs — any divergence needs explanation
- [ ] Language-specific security patterns are correct (not just syntactically valid)

---

## Technique 4: Digital Twin Universe (DTU)

**StrongDM definition:** Behavioral clones of third-party services for testing at volumes exceeding production limits.

**Our adaptation:** We don't need to clone Okta or Slack. But we DO need to clone vulnerable codebases for scanner validation.

### Claude Code Rules

```yaml
# DIGITAL TWIN UNIVERSE — Synthetic vulnerable repos for scanner testing

dtu_for_sentinel:
  purpose: "Synthetic test repos with known vulnerabilities at known locations"
  advantage: "Deterministic ground truth — we KNOW what the scanner should find"
  
  twin_repos:
    - name: "vuln-mcp-server-ts"
      language: "TypeScript"
      contains: "Planted SSRF, path traversal, eval injection, exposed secrets"
      ground_truth: "manifest.json with exact file:line:severity for each vuln"
      
    - name: "vuln-mcp-server-py"  
      language: "Python"
      contains: "Planted command injection, pickle deserialization, SQL injection"
      ground_truth: "manifest.json with exact file:line:severity for each vuln"
      
    - name: "vuln-npm-project"
      language: "JavaScript"
      contains: "Known vulnerable dependencies, malicious postinstall scripts"
      ground_truth: "manifest.json with exact package:version:CVE for each vuln"

  validation_rule: |
    Scanner findings must achieve:
    - True Positive Rate >= 95% (find what's planted)
    - False Positive Rate <= 5% (don't flag clean code)
    - Zero false negatives on CRITICAL severity

  holdout_principle: |
    Like StrongDM's scenario holdouts, keep some test repos that the scanner
    development agent NEVER sees during development. Only used for validation.
    This prevents the agent from overfitting fixes to the test corpus.
```

### Human Review Checkpoint

Before accepting DTU validation results:
- [ ] Review the ground truth manifest — are the planted vulns realistic?
- [ ] Check that the agent didn't "teach to the test" by hardcoding detection for specific test files
- [ ] Verify false negatives aren't being masked by overly broad true positive patterns

---

## Technique 5: Shift Work

**StrongDM definition:** Separate interactive work from fully specified work. When intent is complete, an agent can run end-to-end.

**Our adaptation:** Shift work is allowed for well-specified tasks, but the output still gets human review.

### Claude Code Rules

```yaml
# SHIFT WORK — Non-interactive agent runs for fully-specified tasks

shift_work_allowed:
  - "Run test suite and report results"
  - "Scan target repo and produce JSON findings"
  - "Generate boilerplate from exemplar (gene transfusion)"
  - "Run linter/formatter across codebase"
  - "Update dependency versions (patch/minor only)"

shift_work_requires_approval:
  - "Implement new detection pattern"
  - "Modify scanner architecture"
  - "Change CLI interface"  
  - "Update security-critical code paths"
  - "Any change to false positive filtering logic"

shift_work_forbidden:
  - "Commit and push without human review"
  - "Modify .env, secrets, or credentials"
  - "Delete test files or test fixtures"
  - "Change git history (rebase, force push)"
  - "Publish to PyPI or npm"
```

---

## Technique 6: The Filesystem as Memory

**StrongDM definition:** Models navigate repos and adjust their own context by reading and writing files. Directories, indexes, and on-disk state become a practical memory substrate.

**Our adaptation:** Already implemented via MEMORY.md and sentinel-roadmap.md in Claude Code's auto-memory directory.

### Claude Code Rules

```yaml
# FILESYSTEM AS MEMORY — Persistent state across sessions

memory_files:
  project_memory: "MEMORY.md"
  roadmap: "sentinel-roadmap.md"
  session_log: "Updated at end of each Claude Code session"

memory_update_protocol:
  at_session_start:
    - "Read MEMORY.md and sentinel-roadmap.md"
    - "Identify current phase and active tasks"
  at_session_end:
    - "Update roadmap with completed work"
    - "Note any bugs found/fixed"
    - "Record test results"
    - "Flag items needing human review"
    - "Update Linear issues via MCP if connected"

pyramid_summary_for_memory:
  L0: "One line in MEMORY.md project list"
  L1: "Current phase status in sentinel-roadmap.md header"
  L2: "Full phase details in sentinel-roadmap.md body"
```

---

## The Human Review Contract

This is the fundamental divergence from StrongDM's model. Every technique above includes a human review checkpoint. Here's why this matters for security tooling:

```
StrongDM builds: Access management software (validated by behavioral testing)
We build:        Security scanning software (validated by catching real vulnerabilities)

If StrongDM's code has a bug: A permission might be wrong (caught by scenario testing)
If our scanner has a bug:     A real vulnerability goes undetected (NOT caught by our own tests)

The scanner cannot validate itself. Human review is the external QA.
```

### Review Tiers

```yaml
review_tiers:
  quick_review:  # < 5 minutes
    applies_to: "Boilerplate, formatting, dependency bumps, documentation"
    check: "Skim diff, verify no unintended changes, approve"
    
  standard_review:  # 15-30 minutes
    applies_to: "New features, new adapters, test additions"
    check: "Read every line, verify logic, run tests locally, approve"
    
  security_review:  # 30-60 minutes
    applies_to: "Detection patterns, FP filtering, severity classification"
    check: "Analyze against known CVEs, test against DTU, verify no regressions"
    principle: "A detection pattern bug is a vulnerability we'll miss in production"
```

---

## Integration with Existing Frameworks

These techniques layer on top of existing project rules:

| Framework | What It Covers | Software Factory Addition |
|---|---|---|
| Missing CS Semester | Shell, debugging, profiling, git, packaging | Shift Work automates the repetitive parts |
| Ogawa Coffee / Knowledge-Skills-Wisdom | Documentation quality at three levels | Pyramid Summaries formalize this for agent context |
| Behavioral Code Analysis (Tornhill) | Hotspot detection, change coupling | Gene Transfusion spreads fixes across coupled files |
| Byron Wien principle | "The hard way is always the right way" | Human review IS the hard way. Agents make it faster, not optional. |

---

## Quick Reference Card

| Technique | When to Use | Human Review Level |
|---|---|---|
| Pyramid Summaries | Every new module, class, complex function | Quick — verify accuracy |
| Gene Transfusion | Adding new adapter/analyzer following existing pattern | Standard — verify adaptation |
| Semport | Porting rules between languages/frameworks | Standard — verify intent preservation |
| Digital Twin Universe | Validating scanner accuracy against ground truth | Security — verify no overfitting |
| Shift Work | Fully specified, non-creative tasks | Quick — verify no unintended changes |
| Filesystem as Memory | Session persistence, roadmap tracking | None (agent self-manages) |

---

*Adapted for MCP Sentinel Scanner project by G.S. | SecurityLeader.ai*
*Source: [StrongDM Software Factory](https://factory.strongdm.ai) · [Simon Willison](https://simonwillison.net/2026/Feb/7/software-factory/) · [Attractor NLSpec](https://github.com/strongdm/attractor)*
