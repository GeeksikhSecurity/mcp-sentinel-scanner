"""OpenProse attack-surface analyzer — SAY-281 Phase 2.

Two structural detectors operating on `*.prose.md` Markdown contract files:

Detector A (`prose_binding_poisoning_risk`):
    Flags evals whose `### Requires` declares run/binding/evidence-shaped inputs
    but whose contract has no `### Invariants` section constraining input trust.
    Canonical positive: `packages/std/evals/system-improver.prose.md` in
    openprose/prose @ 4603db9. Canonical negative: `prose-contributor.prose.md`
    (which has 8 invariants).

Detector B (`prose_diff_scope_unbounded`):
    Flags evals whose `### Ensures` declares a `diff`-shaped output without
    any constraint binding the diff's filesystem scope to a declared `### Requires`
    path input. A poisoned input can otherwise direct the diff at arbitrary
    files (e.g., `.env`, `~/.ssh/`).

FP guardrails (validated against the OpenProse stdlib, 163 prose files,
0% FP rate):

1. Indicator words (`run`, `binding`, `diff`, …) match only as the WHOLE first
   word of a bullet's key/type-slot, or as the FIRST `-_`-separated prefix.
   `run-path` (compound type) matches; `green_evidence` (evidence as second
   component of a domain-specific name) does not; description text like "re-run
   before staging" does not.

2. Detector B suppresses bullets whose value description contains
   `comparison`/`variance`/`divergence`/`benchmark` keywords — `diffs:
   structured comparison containing per-service output_diff, …` is a comparison
   report, not a unified-diff patch (cf. `evals/cross-run-differ.prose.md`).

The parser ACCUMULATES section content across multiple `### X` declarations.
A `kind: system` file with N services has 1 system-level + N service-level
`### Requires` sections; the union is what the detector reasons about. A
run-like input declared at any level is a poisoning surface for the whole file.

Phase 1 derivation: openprose/prose @ 4603db9 read-only recon. See SAY-281
Linear comment 789a57db-fe34-4b0b-a4fa-b8c24eb9f95f and Notion page
368596e06bd581f086edf1b8155b43f7.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..core.types import VulnerabilityFinding
from .base import BaseAnalyzer


PROSE_EXTENSION_SUFFIX = ".prose.md"

SUPPORTED_KINDS = {"system", "service", "responsibility", "gateway"}

RUN_BINDING_INDICATORS = (
    "run",
    "runs",
    "binding",
    "bindings",
    "evidence",
    "subjects",
    "inspection",
    "receipt",
)

# Phase 3 alias — composition_analyzer and external callers reference this name.
RUN_INDICATORS = RUN_BINDING_INDICATORS

DIFF_INDICATORS = ("diff", "diffs", "patch", "patches")


@dataclass
class Finding:
    """Phase 3 canonical prose finding shape consumed by the SARIF emitter.

    Coexists with `VulnerabilityFinding`: the single-file `analyze()` path still
    returns VulnerabilityFinding objects for scanner integration. This dataclass
    is the structured carrier the SARIF emitter (`sentinel.sarif.prose_sarif`)
    operates on, with explicit prose-specific metadata that doesn't fit cleanly
    in the generic VulnerabilityFinding shape.
    """

    path: Path
    category: str
    severity: str
    message: str
    line_no: int
    prose_kind: str = ""
    binding_key: str = ""
    has_invariants: bool = False
    # Populated by the SARIF emitter at scan time when "unknown".
    fork_lineage: str = "unknown"

DIFF_SCOPE_CONSTRAINT_PATTERNS = (
    r"\bwithin\s+source-path\b",
    r"\bwithin\s+\w+[-_]path\b",
    r"\bscope[:\s]+source",
    r"\bdiff\s+(?:scope|path)\b",
    r"\bnever\s+modify\s+files\s+outside\b",
    r"\bpath[- ]prefix",
    r"\bconstrained\s+to\b.*\bpath\b",
    r"\bdiffs?\s+must\s+stay\s+within\b",
)

# Patterns indicating the `diff`-named bullet is a COMPARISON REPORT
# (semantic "differences"), not a unified-diff patch. Used by Detector B to
# suppress FPs like cross-run-differ's `diffs: structured comparison containing
# per-service output_diff, timing_diff, cost_diff`.
COMPARISON_REPORT_PATTERNS = (
    r"\bcomparison\b",
    r"\bcomparisons\b",
    r"\bdivergences?\b",
    r"\bvariance\b",
    r"\bbenchmark\b",
)

# Splits a value into (type_slot, description). The em-dash `—` is the
# canonical OpenProse separator; ` -- ` and ` - ` are ASCII fallbacks.
_TYPE_DESC_SPLIT = re.compile(r"\s+(?:—|--|-)\s+", flags=re.UNICODE)

# Canonical "has invariants" predicate, SHARED by Detector A here and by the
# composition analyzer. A section counts as an invariants section if its name
# contains "invariant"/"invariants" (case-insensitive) — so `### Invariants`,
# `### Invariant` (singular), and `### Trust Invariants` all qualify. Defined
# in this base module (composition_analyzer imports it) so the two detectors
# can never disagree on whether a contract is constrained. (cubic P3, SAY-281.)
_INVARIANTS_RE = re.compile(r"invariants?", re.IGNORECASE)


def _is_invariants_section(name: str) -> bool:
    """True iff `name` denotes an `### Invariants` section (any inflection/qualifier)."""
    return bool(_INVARIANTS_RE.search(name))


class ProseAttackSurfaceAnalyzer(BaseAnalyzer):
    """Detects two structural attack-surface patterns in OpenProse contracts."""

    name = "prose_attack_surface"
    supported_extensions = [".md"]  # narrowed further by `supports_file`

    def supports_file(self, file_path: Path) -> bool:
        return file_path.name.endswith(PROSE_EXTENSION_SUFFIX)

    def analyze(self, target: Path) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if target.is_file():
            if self.supports_file(target):
                findings.extend(self._analyze_file(target))
            return findings
        if target.is_dir():
            for path in sorted(target.rglob(f"*{PROSE_EXTENSION_SUFFIX}")):
                findings.extend(self._analyze_file(path))
        return findings

    def _analyze_file(self, file_path: Path) -> List[VulnerabilityFinding]:
        spec = _parse_prose_md(file_path)
        if spec is None:
            return []

        kind = spec["frontmatter"].get("kind", "").strip().lower()
        if kind not in SUPPORTED_KINDS:
            return []

        findings: List[VulnerabilityFinding] = []
        finding_a = self._detect_a_binding_poisoning(file_path, spec)
        if finding_a is not None:
            findings.append(finding_a)
        finding_b = self._detect_b_diff_scope(file_path, spec)
        if finding_b is not None:
            findings.append(finding_b)
        return findings

    def _detect_a_binding_poisoning(
        self,
        file_path: Path,
        spec: Dict,
    ) -> Optional[VulnerabilityFinding]:
        sections = spec["sections"]
        requires = sections.get("requires")
        if requires is None:
            return None

        run_like_line_no: Optional[int] = None
        for line_no, line in requires["content_with_lines"]:
            kv = _bullet_kv(line)
            if kv is None:
                continue
            key, _value, type_slot = kv
            if _matches_first_token(key, RUN_BINDING_INDICATORS) or _matches_first_token(type_slot, RUN_BINDING_INDICATORS):
                run_like_line_no = line_no
                break

        if run_like_line_no is None:
            return None

        # Use the shared predicate (substring/inflection-aware), not an exact
        # "invariants" key match — otherwise `### Invariant` (singular) or
        # `### Trust Invariants` would be a false positive here while the
        # composition analyzer correctly treats the same contract as constrained.
        if any(_is_invariants_section(name) for name in sections):
            return None

        snippet_start = max(0, run_like_line_no - 2)
        snippet_end = min(len(spec["lines"]), run_like_line_no + 4)
        snippet = "\n".join(spec["lines"][snippet_start:snippet_end])

        return VulnerabilityFinding(
            severity="HIGH",
            category="prose_binding_poisoning_risk",
            description=(
                "OpenProse contract declares run/binding-shaped inputs in `### Requires` "
                "but has no `### Invariants` section to constrain input trust. A "
                "malicious upstream run can poison the consumed evidence. "
                "(SAY-281 Detector A — binding-poisoning)"
            ),
            file_path=str(file_path),
            line_number=run_like_line_no,
            code_snippet=snippet,
            recommendation=(
                "Add an `### Invariants` section declaring trust posture for the "
                "consumed run/binding inputs. Reference `prose-contributor.prose.md` "
                "in openprose/prose as the canonical shape: explicit approval gates, "
                "scope constraints, never-push-to-base, dirty-worktree-stop. At "
                "minimum, declare the kinds of upstream content the contract refuses "
                "to act on without external confirmation."
            ),
            cwe_id="CWE-20",
            confidence=0.85,
            source="prose_attack_surface",
        )

    def _detect_b_diff_scope(
        self,
        file_path: Path,
        spec: Dict,
    ) -> Optional[VulnerabilityFinding]:
        sections = spec["sections"]
        ensures = sections.get("ensures")
        if ensures is None:
            return None

        diff_line_no: Optional[int] = None
        for line_no, line in ensures["content_with_lines"]:
            kv = _bullet_kv(line)
            if kv is None:
                continue
            key, value, type_slot = kv
            if _matches_first_token(key, DIFF_INDICATORS) or _matches_first_token(type_slot, DIFF_INDICATORS):
                # FP guard: suppress comparison-report bullets where "diff(s)"
                # means "differences", not "unified-diff patches" (cf. cross-run-differ).
                if _matches_pattern(value, COMPARISON_REPORT_PATTERNS):
                    continue
                diff_line_no = line_no
                break

        if diff_line_no is None:
            return None

        constraint_text_lines: List[str] = []
        for sect_name in ("ensures", "invariants", "strategies"):
            sect = sections.get(sect_name)
            if sect is None:
                continue
            constraint_text_lines.extend(line for _ln, line in sect["content_with_lines"])
        combined_constraint_text = "\n".join(constraint_text_lines).lower()

        for pattern in DIFF_SCOPE_CONSTRAINT_PATTERNS:
            if re.search(pattern, combined_constraint_text):
                return None

        snippet_start = max(0, diff_line_no - 2)
        snippet_end = min(len(spec["lines"]), diff_line_no + 4)
        snippet = "\n".join(spec["lines"][snippet_start:snippet_end])

        return VulnerabilityFinding(
            severity="MEDIUM",
            category="prose_diff_scope_unbounded",
            description=(
                "OpenProse contract produces a `diff`-shaped output in `### Ensures` "
                "with no constraint binding the diff's filesystem scope to a declared "
                "`### Requires` path input. A poisoned input can therefore direct the "
                "diff at arbitrary files (e.g., `.env`, `~/.ssh/`, `~/.aws/credentials`). "
                "(SAY-281 Detector B — diff-scope unbounded)"
            ),
            file_path=str(file_path),
            line_number=diff_line_no,
            code_snippet=snippet,
            recommendation=(
                "Constrain the diff's filesystem scope. Either add an `### Invariants` "
                "clause naming the bound (e.g., `never modify files outside source-path`), "
                "or rename the diff output to a scoped form (e.g., `diffs_within_source_path: "
                "diff[]`). Both make the constraint visible to static review and to the "
                "runtime LLM."
            ),
            cwe_id="CWE-22",
            confidence=0.65,
            source="prose_attack_surface",
        )


def _split_front_matter(lines: List[str]) -> Tuple[Dict[str, str], int]:
    """Parse the `---`-fenced front-matter.

    Returns `(frontmatter, body_start)` where `body_start` is the 0-based index
    of the first line AFTER the closing `---`, or 0 when there is no valid
    front-matter (no opening fence, or no closing fence). The `---` fence is
    matched with `.rstrip()` (trailing whitespace tolerated, leading whitespace
    significant) — ONE convention, shared by every parser below, so the three
    callers can never drift on the fence check. (cubic P3 — was rstrip vs strip.)
    """
    if not lines or lines[0].rstrip() != "---":
        return {}, 0
    fm_end: Optional[int] = None
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            fm_end = i
            break
    if fm_end is None:
        return {}, 0
    frontmatter: Dict[str, str] = {}
    for line in lines[1:fm_end]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        frontmatter[key.strip()] = value.strip()
    return frontmatter, fm_end + 1


def _accumulate_sections(lines: List[str], start: int) -> Dict[str, Dict]:
    """Parse `### X` sections from `lines[start:]`, accumulating repeats.

    Returns `{name_lower: {"first_line": int (1-based), "content_with_lines":
    [(line_no, text), ...]}}`. The single source of truth for section parsing —
    a `kind: system` file with N services has N+1 `### Requires` sections whose
    content is unioned under one `requires` key. Both the line-number-aware
    caller (`_parse_prose_md`) and the plain-string caller (`_parse_sections`,
    used by the composition analyzer) derive from this one implementation.
    """
    sections: Dict[str, Dict] = {}
    current_name: Optional[str] = None
    current_section_start: Optional[int] = None
    current_content: List[Tuple[int, str]] = []

    def _close_section() -> None:
        if current_name is None or current_section_start is None:
            return
        existing = sections.get(current_name)
        if existing is None:
            sections[current_name] = {
                "first_line": current_section_start,
                "content_with_lines": list(current_content),
            }
        else:
            existing["content_with_lines"].extend(current_content)

    for i in range(start, len(lines)):
        line = lines[i]
        line_no = i + 1  # 1-based
        if line.startswith("### "):
            _close_section()
            current_name = line[4:].strip().lower()
            current_section_start = line_no
            current_content = []
        elif line.startswith("## ") or line.startswith("# ") or line.rstrip() == "---":
            _close_section()
            current_name = None
            current_section_start = None
            current_content = []
        else:
            if current_name is not None:
                current_content.append((line_no, line))

    _close_section()
    return sections


def _parse_prose_md(file_path: Path) -> Optional[Dict]:
    """Parse a `*.prose.md` file's frontmatter and `### X` section structure.

    Returns None when the file is not a Prose contract (no front-matter fence).
    Returns a dict otherwise:

        {
            "frontmatter": {key: value, ...},
            "sections": {
                "requires": {
                    "first_line": int,               # 1-based line of first occurrence
                    "content_with_lines": [(line_no, line_text), ...],
                },
                ...
            },
            "lines": [str, ...],
        }
    """
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    lines = text.splitlines()
    frontmatter, body_start = _split_front_matter(lines)
    if body_start == 0:
        # No front-matter fence → not a Prose contract.
        return None

    return {
        "frontmatter": frontmatter,
        "sections": _accumulate_sections(lines, body_start),
        "lines": lines,
    }


def _parse_front_matter(lines: List[str]) -> Dict[str, str]:
    """Extract YAML-ish front-matter between `---` fences (composition analyzer).

    Thin wrapper over the shared `_split_front_matter`. Returns an empty dict
    when no front-matter is present.
    """
    frontmatter, _ = _split_front_matter(lines)
    return frontmatter


def _parse_sections(lines: List[str]) -> Dict[str, List[str]]:
    """Parse `### X` sections as plain string lists (composition analyzer).

    Thin wrapper over the shared `_accumulate_sections`, dropping the line
    numbers the composition analyzer doesn't need. Same accumulation and fence
    semantics as `_parse_prose_md` — there is now exactly one parser.
    """
    _, body_start = _split_front_matter(lines)
    raw = _accumulate_sections(lines, body_start)
    return {
        name: [text for _ln, text in sect["content_with_lines"]]
        for name, sect in raw.items()
    }


def _bullet_kv(line: str) -> Optional[Tuple[str, str, str]]:
    """Extract `(key, full_value, type_slot)` from a `- key: value` bullet, lower-cased.

    The `type_slot` is the portion of the value before the em-dash or ` - `
    description separator. For `- inspection: run — a completed inspector run`
    this returns `("inspection", "run — a completed inspector run", "run")`.
    Returns None for nested bullet content (no `:`) or non-bullet lines.
    """
    stripped = line.strip()
    if not stripped.startswith("-"):
        return None
    after_dash = stripped[1:].lstrip()
    if ":" not in after_dash:
        return None
    key_raw, _, value_raw = after_dash.partition(":")
    key = key_raw.strip().lower()
    value = value_raw.strip().lower()
    type_slot = _TYPE_DESC_SPLIT.split(value, maxsplit=1)[0].strip()
    return (key, value, type_slot)


def _first_token_components(text: str) -> Set[str]:
    """Extract candidate indicator tokens from `text`'s first space-separated word.

    Returns `{whole_first_word, first_dash_or_underscore_prefix}`, both
    lower-cased with array notation and surrounding punctuation stripped.

    Examples:
        `run-path`               → {'run-path', 'run'}
        `run[]`                  → {'run'}
        `green_evidence`         → {'green_evidence', 'green'}
        `a set of N responses…`  → {'a'}
        `from implement-tdd, …`  → {'from'}

    The first-prefix rule matches OpenProse type-qualifier conventions:
    `run-path` is "path scoped to a run" — the `run` semantics dominate.
    `green_evidence` is "evidence of the green-loop phase" — the `green`
    prefix dominates, so it does NOT match the `evidence` indicator. This
    refinement was validated against the OpenProse stdlib to drive the FP
    rate to zero on the production corpus.
    """
    if not text:
        return set()
    tokens = text.split()
    if not tokens:
        return set()
    first = re.sub(r"[^a-z0-9_-]", "", tokens[0].lower())
    if not first:
        return set()
    prefix = re.split(r"[-_]", first, maxsplit=1)[0]
    return {first, prefix}


def _matches_first_token(text: str, indicators: Tuple[str, ...]) -> bool:
    """True iff any indicator equals the first whole word or first prefix of `text`."""
    components = _first_token_components(text)
    return any(indicator in components for indicator in indicators)


def _matches_pattern(text: str, patterns: Tuple[str, ...]) -> bool:
    """True iff `text` matches any of the given regex patterns."""
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False
