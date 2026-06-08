"""Multi-file prose composition risk analyzer (SAY-281 Phase 3).

Detects dangerous soft→hard agent handoffs where:
  - Agent A (soft): no ### Invariants section, provides run-typed output
  - Agent B (hard): has ### Invariants section, requires run-typed input

Single-file scanners cannot detect this class of risk. This analyzer requires
a corpus of prose files and builds a handoff graph across all of them.

Design note — over-approximation:
  Phase 3 intentionally over-approximates (high recall, medium precision).
  Not all soft→hard pairs in a corpus are actually composed at runtime.
  Phase 3b will add system-contract graph resolution to filter to confirmed
  handoffs. The SARIF rule `PROSE_COMPOSITION_RISK` is marked precision:medium
  to signal this explicitly to consumers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from .prose_attack_surface import (
    RUN_INDICATORS,
    _bullet_kv,
    _is_invariants_section,
    _matches_first_token,
    _parse_front_matter,
    _parse_sections,
)


@dataclass
class ProseContractProfile:
    """Extracted profile of a single prose contract for composition analysis."""

    path: Path
    name: str
    kind: str
    has_invariants: bool
    invariant_count: int
    provides_run_keys: List[str]
    requires_run_keys: List[str]
    line_count: int


@dataclass
class CompositionFinding:
    """A dangerous soft→hard composition pair detected across two prose contracts.

    Primary subject: `soft_agent` (the fix target — add ### Invariants or a
    pre-handoff validation step). Related subject: `hard_agent` (receives the
    handoff; already constrained but cannot retroactively sanitize poisoned
    input).
    """

    soft_agent: ProseContractProfile
    hard_agent: ProseContractProfile
    handoff_key: str
    handoff_type: str
    message: str
    severity: str = "HIGH"
    category: str = "prose_composition_risk"


# `_is_invariants_section` is imported from prose_attack_surface (the shared
# base module) so Detector A and this analyzer use ONE predicate. provides/
# requires are composition-only and stay local.
_PROVIDES_RE = re.compile(r"provides?", re.IGNORECASE)
_REQUIRES_RE = re.compile(r"requires?", re.IGNORECASE)


def _is_provides_section(name: str) -> bool:
    return bool(_PROVIDES_RE.search(name))


def _is_requires_section(name: str) -> bool:
    return bool(_REQUIRES_RE.search(name))


class ProseCompositionAnalyzer:
    """Multi-file analyzer for dangerous soft→hard prose agent handoffs.

    A file is skipped (returns None from `profile_file`) when:
      - It has no YAML front-matter with a `kind:` field
      - Its `kind:` is not one of EVAL_KINDS
      - It is empty or cannot be read

    Handoff detection:
      1. Soft agents: has_invariants=False AND provides_run_keys is non-empty
      2. Hard agents: has_invariants=True  AND requires_run_keys is non-empty
      3. A soft→hard pair is flagged when the run-key sets intersect
         (`run-binding-key-overlap`). If both sides have non-empty run-key
         sets but no overlap, flag as `run-binding-inferred` (weaker signal).
      4. Same file never paired with itself.
    """

    EVAL_KINDS = {"eval", "system", "service"}

    def profile_file(self, path: Path) -> Optional[ProseContractProfile]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            return None

        if not lines:
            return None

        front_matter = _parse_front_matter(lines)
        kind = front_matter.get("kind", "").lower().strip()
        name = front_matter.get("name", path.stem)

        if kind not in self.EVAL_KINDS:
            return None

        sections = _parse_sections(lines)

        invariant_count = 0
        provides_run_keys: List[str] = []
        requires_run_keys: List[str] = []

        for section_name, section_lines in sections.items():
            if _is_invariants_section(section_name):
                invariant_count += 1
                continue
            if _is_provides_section(section_name):
                for line in section_lines:
                    kv = _bullet_kv(line)
                    if kv is None:
                        continue
                    key, _value, type_slot = kv
                    if _matches_first_token(key, RUN_INDICATORS) or _matches_first_token(
                        type_slot, RUN_INDICATORS
                    ):
                        provides_run_keys.append(key)
                continue
            if _is_requires_section(section_name):
                for line in section_lines:
                    kv = _bullet_kv(line)
                    if kv is None:
                        continue
                    key, _value, type_slot = kv
                    if _matches_first_token(key, RUN_INDICATORS) or _matches_first_token(
                        type_slot, RUN_INDICATORS
                    ):
                        requires_run_keys.append(key)

        return ProseContractProfile(
            path=path,
            name=name,
            kind=kind,
            has_invariants=(invariant_count > 0),
            invariant_count=invariant_count,
            provides_run_keys=provides_run_keys,
            requires_run_keys=requires_run_keys,
            line_count=len(lines),
        )

    def analyze_corpus(self, paths: Sequence[Path]) -> List[CompositionFinding]:
        profiles: List[ProseContractProfile] = []
        for p in paths:
            profile = self.profile_file(p)
            if profile is not None:
                profiles.append(profile)

        soft_agents = [
            p for p in profiles if not p.has_invariants and p.provides_run_keys
        ]
        hard_agents = [p for p in profiles if p.has_invariants and p.requires_run_keys]

        findings: List[CompositionFinding] = []
        seen: set[tuple[Path, Path]] = set()

        for soft in sorted(soft_agents, key=lambda p: p.path):
            for hard in sorted(hard_agents, key=lambda p: p.path):
                if soft.path == hard.path:
                    continue
                pair_key = (soft.path, hard.path)
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                overlap = sorted(
                    set(soft.provides_run_keys) & set(hard.requires_run_keys)
                )
                if overlap:
                    handoff_key = overlap[0]
                    handoff_type = "run-binding-key-overlap"
                else:
                    handoff_key = "(untyped run binding)"
                    handoff_type = "run-binding-inferred"

                message = (
                    f"Dangerous composition: '{soft.name}' (soft — "
                    f"{soft.invariant_count} invariant(s)) hands off to "
                    f"'{hard.name}' (hard — {hard.invariant_count} invariant(s)) "
                    f"via unvalidated run binding '{handoff_key}'. "
                    f"Agent B's invariants cannot retroactively sanitize "
                    f"Agent A's output if the handoff is poisoned."
                )

                findings.append(
                    CompositionFinding(
                        soft_agent=soft,
                        hard_agent=hard,
                        handoff_key=handoff_key,
                        handoff_type=handoff_type,
                        message=message,
                    )
                )

        return findings
