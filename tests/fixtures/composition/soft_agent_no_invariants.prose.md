---
name: inspection-runner
kind: eval
---

# Inspection Runner (Soft Agent — No Invariants)

Runs a structural inspection pass on a prose corpus and emits a run
artifact consumed by downstream evals. Has no ### Invariants block — this
is the soft-agent fixture for composition risk detection.

### Requires

- corpus-path: path — filesystem path to the prose corpus root.

### Provides

- inspection-output: run — structured run artifact containing per-file
  analysis results, flag counts, and section inventories. Consumed by
  downstream evals such as system-improver.

### Shape

Input: a directory path string.
Output: a run object with keys `files`, `flags`, `sections`.
