---
name: prose-contributor
kind: eval
---

# Prose Contributor (Hard Agent — 8 Invariants)

Receives a run artifact from an upstream eval and applies targeted prose
improvements. Has ### Invariants — this is the hard-agent fixture for
composition risk detection.

### Requires

- inspection-output: run — structured run artifact from an upstream
  inspection eval. Provides the set of files to act on and their
  improvement candidates.

### Invariants

1. MUST NOT modify files outside the corpus root declared in
   `inspection-output.corpus_root`.
2. MUST NOT apply changes to files not listed in
   `inspection-output.files`.
3. MUST NOT create new files.
4. MUST NOT delete files.
5. MUST preserve front-matter (`---` fences and their contents) verbatim.
6. MUST NOT alter `### Invariants` sections of any file it edits.
7. Each diff MUST be a unified patch targeting a single file.
8. MUST emit a `### Shape`-conformant output even when no changes are made.

### Provides

- improvement-diff: diff — unified patch applying prose improvements to
  the files listed in the input run.

### Shape

Input: run artifact from inspection-runner or equivalent.
Output: unified diff patch; empty patch if no improvements found.
