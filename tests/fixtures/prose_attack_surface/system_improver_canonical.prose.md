---
name: system-improver
kind: system
---

# System Improver (Canonical Soft Target)

Given an inspection report and the inspected system's source, analyze the system for improvement opportunities and produce ranked proposals with diffs.

### Services

- locator
- analyst
- implementer

### Requires

- inspection: run — a completed inspector run whose output identifies issues with a system
- source-path: path to the system's source directory containing `*.prose.md` files

### Ensures

- improvements: ranked list of improvement opportunities, each containing:
    - rank: priority position (1 = highest impact)
    - category: contract | strategy | shape | structure | error-handling | efficiency
    - description: what the problem is
    - evidence: specific reference to inspection findings and system source
    - diff: proposed change as a unified diff against the source file
    - risk: low | medium | high
- if no improvements found: empty list with explanation

### Errors

- source-not-found: the source-path does not contain valid OpenProse system files
- inspection-invalid: the inspection run output is not a valid inspector report

### Strategies

- when analyzing contracts: check that every ensures clause is specific enough to evaluate
- when proposing diffs: make minimal changes — one concern per diff
- when ranking: prioritize contract violations and missing error handling over efficiency improvements
