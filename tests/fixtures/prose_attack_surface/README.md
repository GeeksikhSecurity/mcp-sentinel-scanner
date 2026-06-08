# Prose Attack Surface Fixtures — SAY-281 Phase 2

Synthetic `*.prose.md` fixtures for the OpenProse attack-surface detectors. See `src/sentinel/analyzers/prose_attack_surface.py`.

Each fixture is labeled with the expected detector outcome:

| Fixture | Detector A (binding-poisoning) | Detector B (diff-scope) | Notes |
|---------|---|---|---|
| `system_improver_canonical.prose.md` | POSITIVE | POSITIVE | Canonical soft target — modeled on `packages/std/evals/system-improver.prose.md` in openprose/prose @ 4603db9. Run-shaped Requires, no Invariants, ensures diff with no scope binding. |
| `prose_contributor_canonical.prose.md` | NEGATIVE | NEGATIVE | Canonical hard target with real guardrails — modeled on `packages/std/evals/prose-contributor.prose.md`. Run-shaped Requires but 8 Invariants. Ensures PR not raw diff. |
| `clean_baseline.prose.md` | NEGATIVE | NEGATIVE | No run/binding inputs, no diff outputs. |
| `diff_scope_unbounded.prose.md` | NEGATIVE | POSITIVE | Has Invariants (Detector A clears) but no diff-scope constraint (Detector B flags). |
| `malicious_upstream_payload.prose.md` | NEGATIVE | NEGATIVE | Documentation only — the attacker payload demonstrating the Phase 1 poisoning surface. Detectors operate on the VICTIM, not the attacker. |
| `not_a_prose_contract.md` | NEGATIVE | NEGATIVE | Plain markdown without `.prose.md` extension — detector must skip. |

## Threat Model (Phase 1 derived)

OpenProse passes evidence between bounded VM runs via `bindings/` files declared in `### Ensures`. The host primitive `copy_binding` is honor-system per `README.md:316-331`. A malicious upstream run can therefore poison the input evidence to a downstream eval whose contract does not constrain trust.

`system-improver` is the canonical soft target:
- Treats `inspection-output` as ground truth (`packages/std/evals/system-improver.prose.md:71,83`)
- No `### Invariants` section
- `implementer` emits unified diffs with no filesystem-scope constraint (`:113-114`)

`prose-contributor` is the canonical defensively-shaped target:
- 8 invariants (`packages/std/evals/prose-contributor.prose.md:55-63`)
- Explicit `pr-approval` gate
- `scope` enum constrains affected files

The composition is the real risk: `system-improver.improvements → prose-contributor.subjects` hands a soft target's output to a hard target's input, and the hard target's invariants assume honest subject evidence.

## Cross-references

- Linear: SAY-281
- Notion: ArXiv Research Synthesis page (368596e0-6bd5-81f0-86ed-f1b8155b43f7)
- Source under review: openprose/prose @ 4603db9
