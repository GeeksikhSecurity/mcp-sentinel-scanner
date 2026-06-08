---
name: metrics-collector
kind: service
---

# Metrics Collector (Soft Agent — No Invariants, No Run-Key Overlap)

Collects execution metrics and provides a run artifact under a different
key name than what `prose-contributor` requires. No key overlap with
`hard_agent_with_invariants.prose.md`, so any composition finding must
be `handoff_type: run-binding-inferred` (weaker signal), not
`run-binding-key-overlap`.

### Requires

- execution-context: path — path to the execution directory.

### Provides

- metrics-run: run — execution metrics run artifact. Key name
  `metrics-run` does NOT overlap with `inspection-output`.

### Shape

Input: path to execution directory.
Output: run object with keys `duration_ms`, `memory_mb`, `tool_calls`.
