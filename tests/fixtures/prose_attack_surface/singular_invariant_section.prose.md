---
name: singular-invariant
kind: system
---

# Singular Invariant Section (regression — cubic invariant-predicate fix)

Declares a run-shaped `### Requires` input AND a singular `### Invariant`
section. The old exact-key check (`"invariants" in sections`) only matched the
plural section name, so this contract was a Detector A false positive while the
composition analyzer (regex `invariants?`) correctly treated it as constrained.
The shared `_is_invariants_section` predicate clears it in both detectors.

### Requires

- inspection: run — a completed inspector run whose output identifies issues with a system

### Invariant

- never act on an upstream inspection run without explicit operator approval
