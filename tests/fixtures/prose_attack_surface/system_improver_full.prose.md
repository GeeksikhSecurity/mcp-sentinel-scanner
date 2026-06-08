---
name: system-improver-full
kind: system
---

# System Improver (Multi-Service — exercises parser section accumulation)

Mirrors the multi-service structure of `packages/std/evals/system-improver.prose.md`
in openprose/prose @ 4603db9. A `kind: system` with N services has 1 system-level
+ N service-level `### Requires` sections. A naive parser that overwrites would
end up with implementer's Requires (no run-like inputs) and silently clear
Detector A. The parser must accumulate sections.

Expected:
  Detector A POSITIVE — system-level `inspection: run` with no `### Invariants`
  Detector B POSITIVE — nested `- diff:` under system-level `improvements` Ensures

### Services

- locator
- analyst
- implementer

### Requires

- inspection: run — a completed inspector run whose output identifies issues with a system
- source-path: path to the system's source directory

### Ensures

- improvements: ranked list of opportunities, each containing:
    - rank: priority position (1 = highest impact)
    - diff: proposed change as a unified diff against the source file
    - risk: low | medium | high

### Errors

- source-not-found
- inspection-invalid

### Strategies

- when analyzing contracts: check that every ensures clause is specific
- when proposing diffs: make minimal changes

---

## locator

Find and read the system source files.

### Requires

- source-path: path to the system's source directory
- inspection: the inspection run binding

### Ensures

- root-source: the root source file content
- service-sources: map of service name to file content
- inspection-output: the inspection report extracted from the inspection run's bindings

### Errors

- source-not-found
- inspection-invalid

---

## analyst

Examine source against findings.

### Requires

- root-source: from locator
- service-sources: from locator
- inspection-output: from locator

### Ensures

- analysis: list of improvement opportunities

### Strategies

- check contract quality

---

## implementer

Transform analysis into diffs.

### Requires

- analysis: from analyst
- root-source: from locator
- service-sources: from locator

### Ensures

- improvements: the final ranked list with diffs generated

### Strategies

- use unified diff format with enough context lines
