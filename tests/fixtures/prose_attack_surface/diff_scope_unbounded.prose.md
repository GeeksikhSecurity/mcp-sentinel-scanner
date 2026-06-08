---
name: patch-suggester
kind: system
---

# Patch Suggester (Detector B Only)

Suggest unified-diff patches for a given codebase based on a textual issue description. Has Invariants (Detector A clears) but no constraint on diff scope (Detector B flags).

### Services

- analyzer
- patcher

### Requires

- codebase-path: path to the codebase to patch
- issue-description: text description of what to fix

### Ensures

- patches: list of unified diff patches to apply
- summary: human-readable explanation of each patch

### Errors

- codebase-not-found
- issue-description-too-vague

### Invariants

- patches are advisory only — the caller decides whether to apply them
- never request external network access during patch generation

### Strategies

- focus on the smallest possible change that satisfies the issue
- when multiple patches address the same file: ensure they are independently applicable
