"""
tests/test_composition_analyzer.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test suite for sentinel.analyzers.composition_analyzer.

Coverage:
  - profile_file(): kind filtering, invariants detection, run-key extraction
  - analyze_corpus(): soft/hard pairing, key-overlap vs inferred handoff,
    same-file exclusion, both-hard exclusion, deduplication
  - CompositionFinding field values
"""

import pytest
from pathlib import Path

from sentinel.analyzers.composition_analyzer import (
    ProseCompositionAnalyzer,
    ProseContractProfile,
    CompositionFinding,
)

FIXTURES = Path(__file__).parent / "fixtures" / "composition"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _profile(filename: str) -> ProseContractProfile | None:
    return ProseCompositionAnalyzer().profile_file(FIXTURES / filename)


def _findings(*filenames: str) -> list[CompositionFinding]:
    paths = [FIXTURES / f for f in filenames]
    return ProseCompositionAnalyzer().analyze_corpus(paths)


# ─────────────────────────────────────────────────────────────────────────────
# profile_file() — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestProfileFile:

    def test_soft_agent_returns_profile(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert p is not None

    def test_soft_agent_has_no_invariants(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert p.has_invariants is False
        assert p.invariant_count == 0

    def test_soft_agent_provides_run_key(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert "inspection-output" in p.provides_run_keys

    def test_soft_agent_kind(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert p.kind == "eval"

    def test_soft_agent_name(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert p.name == "inspection-runner"

    def test_hard_agent_has_invariants(self):
        p = _profile("hard_agent_with_invariants.prose.md")
        assert p.has_invariants is True
        assert p.invariant_count == 1

    def test_hard_agent_requires_run_key(self):
        p = _profile("hard_agent_with_invariants.prose.md")
        assert "inspection-output" in p.requires_run_keys

    def test_both_hard_agent_has_invariants(self):
        p = _profile("both_hard_no_finding.prose.md")
        assert p.has_invariants is True

    def test_both_hard_provides_run_key(self):
        p = _profile("both_hard_no_finding.prose.md")
        assert "inspection-output" in p.provides_run_keys

    def test_no_key_overlap_soft_provides_run(self):
        p = _profile("soft_no_key_overlap.prose.md")
        assert "metrics-run" in p.provides_run_keys
        assert p.has_invariants is False

    def test_nonexistent_file_returns_none(self):
        p = ProseCompositionAnalyzer().profile_file(FIXTURES / "does_not_exist.prose.md")
        assert p is None

    def test_non_prose_kind_returns_none(self, tmp_path):
        """Files without a recognized kind: field are skipped."""
        f = tmp_path / "not_a_contract.md"
        f.write_text("---\nname: widget\nkind: widget\n---\n# Widget\n")
        assert ProseCompositionAnalyzer().profile_file(f) is None

    def test_no_front_matter_returns_none(self, tmp_path):
        f = tmp_path / "no_fm.md"
        f.write_text("# Just a markdown file\nNo front matter here.\n")
        assert ProseCompositionAnalyzer().profile_file(f) is None

    def test_empty_file_returns_none(self, tmp_path):
        f = tmp_path / "empty.prose.md"
        f.write_text("")
        assert ProseCompositionAnalyzer().profile_file(f) is None

    def test_line_count_populated(self):
        p = _profile("soft_agent_no_invariants.prose.md")
        assert p.line_count > 0


# ─────────────────────────────────────────────────────────────────────────────
# analyze_corpus() — core pairing logic
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeCorpus:

    def test_soft_hard_pair_produces_finding(self):
        """Canonical case: soft provides run, hard requires same run key → finding."""
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert len(findings) == 1

    def test_finding_identifies_correct_agents(self):
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        f = findings[0]
        assert f.soft_agent.name == "inspection-runner"
        assert f.hard_agent.name == "prose-contributor"

    def test_finding_handoff_key_overlap(self):
        """Key 'inspection-output' appears in both provides and requires."""
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert findings[0].handoff_key == "inspection-output"
        assert findings[0].handoff_type == "run-binding-key-overlap"

    def test_finding_severity_is_high(self):
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert findings[0].severity == "HIGH"

    def test_finding_category(self):
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert findings[0].category == "prose_composition_risk"

    def test_both_hard_produces_no_finding(self):
        """Two hard agents — neither is soft — no composition finding."""
        findings = _findings(
            "both_hard_no_finding.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert findings == []

    def test_single_soft_agent_alone_produces_no_finding(self):
        """A soft agent with no hard counterpart in corpus → no finding."""
        findings = _findings("soft_agent_no_invariants.prose.md")
        assert findings == []

    def test_single_hard_agent_alone_produces_no_finding(self):
        findings = _findings("hard_agent_with_invariants.prose.md")
        assert findings == []

    def test_empty_corpus_produces_no_finding(self):
        findings = ProseCompositionAnalyzer().analyze_corpus([])
        assert findings == []

    def test_no_key_overlap_produces_inferred_finding(self):
        """Soft provides 'metrics-run', hard requires 'inspection-output' — no overlap.
        Should still fire with handoff_type=run-binding-inferred."""
        findings = _findings(
            "soft_no_key_overlap.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        assert len(findings) == 1
        assert findings[0].handoff_type == "run-binding-inferred"
        assert findings[0].handoff_key == "(untyped run binding)"

    def test_deduplication(self):
        """Same path listed twice should not produce duplicate findings."""
        soft = FIXTURES / "soft_agent_no_invariants.prose.md"
        hard = FIXTURES / "hard_agent_with_invariants.prose.md"
        findings = ProseCompositionAnalyzer().analyze_corpus([soft, hard, soft, hard])
        assert len(findings) == 1

    def test_message_includes_both_agent_names(self):
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        msg = findings[0].message
        assert "inspection-runner" in msg
        assert "prose-contributor" in msg

    def test_message_includes_invariant_counts(self):
        findings = _findings(
            "soft_agent_no_invariants.prose.md",
            "hard_agent_with_invariants.prose.md",
        )
        msg = findings[0].message
        # soft: 0 invariants, hard: 1
        assert "0 invariant" in msg
        assert "1 invariant" in msg

    def test_results_sorted_deterministically(self):
        """Multiple calls return the same ordering."""
        paths = [
            FIXTURES / "soft_agent_no_invariants.prose.md",
            FIXTURES / "hard_agent_with_invariants.prose.md",
            FIXTURES / "soft_no_key_overlap.prose.md",
        ]
        a = ProseCompositionAnalyzer().analyze_corpus(paths)
        b = ProseCompositionAnalyzer().analyze_corpus(list(reversed(paths)))
        assert [f.soft_agent.name for f in a] == [f.soft_agent.name for f in b]
        assert [f.hard_agent.name for f in a] == [f.hard_agent.name for f in b]


# ─────────────────────────────────────────────────────────────────────────────
# Parametrized oracle — all fixtures, expected finding counts
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "filenames, expected_count",
    [
        # Canonical dangerous pair
        (
            ["soft_agent_no_invariants.prose.md", "hard_agent_with_invariants.prose.md"],
            1,
        ),
        # Two hard agents — safe
        (
            ["both_hard_no_finding.prose.md", "hard_agent_with_invariants.prose.md"],
            0,
        ),
        # Soft alone — no finding
        (
            ["soft_agent_no_invariants.prose.md"],
            0,
        ),
        # Hard alone — no finding
        (
            ["hard_agent_with_invariants.prose.md"],
            0,
        ),
        # No overlap → inferred finding
        (
            ["soft_no_key_overlap.prose.md", "hard_agent_with_invariants.prose.md"],
            1,
        ),
        # Full corpus — 2 soft × 1 hard
        (
            [
                "soft_agent_no_invariants.prose.md",
                "soft_no_key_overlap.prose.md",
                "hard_agent_with_invariants.prose.md",
            ],
            2,
        ),
        # Full corpus with both_hard added — still 2
        (
            [
                "soft_agent_no_invariants.prose.md",
                "soft_no_key_overlap.prose.md",
                "hard_agent_with_invariants.prose.md",
                "both_hard_no_finding.prose.md",
            ],
            2,
        ),
    ],
)
def test_oracle(filenames: list[str], expected_count: int):
    findings = _findings(*filenames)
    assert len(findings) == expected_count, (
        f"Expected {expected_count} finding(s) for {filenames}, "
        f"got {len(findings)}: {[f.message for f in findings]}"
    )
