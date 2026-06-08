---
name: safe-runner
kind: eval
---

# Safe Runner (Hard Agent — Has Invariants)

Like `inspection-runner` but with a full ### Invariants block.
When paired with `hard_agent_with_invariants.prose.md`, no
composition risk should be detected (both are hard agents).

### Requires

- corpus-path: path — filesystem path to the prose corpus root.

### Invariants

1. MUST NOT read files outside corpus-path.
2. MUST NOT follow symlinks outside corpus-path.
3. Output run MUST include a `corpus_root` key equal to corpus-path.

### Provides

- inspection-output: run — structured run artifact. Same shape as
  `inspection-runner` but emitted only after invariant checks pass.

### Shape

Input: path string (bounded by Invariant 1).
Output: run object with keys `files`, `flags`, `sections`, `corpus_root`.
