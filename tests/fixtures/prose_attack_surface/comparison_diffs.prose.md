---
name: variance-comparer
kind: service
---

# Variance Comparer (Detector B Negative — Comparison Report)

Compares N runs and emits a structured `diffs` report. The word "diffs" here
means "differences" (a comparison report), not unified-diff patches for
filesystem modification. Mirrors the FP pattern observed in
`packages/std/evals/cross-run-differ.prose.md` (`diffs: structured comparison
containing per-service output_diff, timing_diff, cost_diff`).

Expected: both detectors NEGATIVE. Detector B must recognize the comparison
report via the "comparison" keyword in the value description.

### Requires

- run-data: collected metrics from upstream

### Ensures

- diffs: structured comparison containing per-service output_diff, timing_diff, cost_diff
- summary: narrative comparison highlighting the most significant differences

### Invariants

- never edit upstream run data — comparison is read-only
- never apply the diffs to any filesystem location — output is a report

### Strategies

- normalize to the fastest run as baseline for timing comparison
- when outputs are identical: explicitly note "outputs are identical"
