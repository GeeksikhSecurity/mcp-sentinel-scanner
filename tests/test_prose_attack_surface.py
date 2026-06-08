"""Tests for the OpenProse attack-surface analyzer (SAY-281 Phase 2)."""

from pathlib import Path

import pytest

from src.sentinel.analyzers.prose_attack_surface import (
    ProseAttackSurfaceAnalyzer,
    _parse_prose_md,
)

FIXTURES = Path(__file__).parent / "fixtures" / "prose_attack_surface"


def _categories(findings):
    return {f.category for f in findings}


class TestDetectorA:
    """`prose_binding_poisoning_risk` — run/binding inputs without Invariants."""

    def test_flags_system_improver_canonical(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "system_improver_canonical.prose.md")
        assert "prose_binding_poisoning_risk" in _categories(findings)

    def test_flags_system_improver_full_multi_service(self):
        """Parser must accumulate sections across services."""
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "system_improver_full.prose.md")
        assert "prose_binding_poisoning_risk" in _categories(findings)

    def test_clears_prose_contributor_canonical(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "prose_contributor_canonical.prose.md")
        assert "prose_binding_poisoning_risk" not in _categories(findings)

    def test_clears_clean_baseline(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "clean_baseline.prose.md")
        assert "prose_binding_poisoning_risk" not in _categories(findings)

    def test_clears_diff_scope_unbounded(self):
        """diff_scope_unbounded has Invariants → Detector A clears."""
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "diff_scope_unbounded.prose.md")
        assert "prose_binding_poisoning_risk" not in _categories(findings)

    def test_clears_singular_invariant_section(self):
        """Regression (cubic): `### Invariant` (singular) must clear Detector A.

        The old exact-key check (`"invariants" in sections`) missed the singular
        and decorated forms, false-positiving on a constrained contract. The
        shared `_is_invariants_section` predicate — also used by the composition
        analyzer — clears them consistently across both detectors.
        """
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "singular_invariant_section.prose.md")
        assert "prose_binding_poisoning_risk" not in _categories(findings)

    def test_clears_attacker_payload_fixture(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "malicious_upstream_payload.prose.md")
        assert "prose_binding_poisoning_risk" not in _categories(findings)

    def test_finding_metadata(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "system_improver_canonical.prose.md")
        a_findings = [f for f in findings if f.category == "prose_binding_poisoning_risk"]
        assert len(a_findings) == 1
        finding = a_findings[0]
        assert finding.severity == "HIGH"
        assert finding.cwe_id == "CWE-20"
        assert finding.source == "prose_attack_surface"
        assert finding.line_number > 0
        assert "SAY-281" in finding.description


class TestDetectorB:
    """`prose_diff_scope_unbounded` — diff outputs without scope constraints."""

    def test_flags_system_improver_canonical(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "system_improver_canonical.prose.md")
        assert "prose_diff_scope_unbounded" in _categories(findings)

    def test_flags_diff_scope_unbounded(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "diff_scope_unbounded.prose.md")
        assert "prose_diff_scope_unbounded" in _categories(findings)

    def test_clears_prose_contributor_canonical(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "prose_contributor_canonical.prose.md")
        assert "prose_diff_scope_unbounded" not in _categories(findings)

    def test_clears_clean_baseline(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "clean_baseline.prose.md")
        assert "prose_diff_scope_unbounded" not in _categories(findings)

    def test_clears_attacker_payload_fixture(self):
        """Word 'diff' appears only in description text, not key/type-slot. Detector B clears."""
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "malicious_upstream_payload.prose.md")
        assert "prose_diff_scope_unbounded" not in _categories(findings)

    def test_clears_comparison_report(self):
        """`diffs: structured comparison …` is a comparison report, not a unified diff."""
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "comparison_diffs.prose.md")
        assert "prose_diff_scope_unbounded" not in _categories(findings)

    def test_finding_metadata(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "diff_scope_unbounded.prose.md")
        b_findings = [f for f in findings if f.category == "prose_diff_scope_unbounded"]
        assert len(b_findings) == 1
        finding = b_findings[0]
        assert finding.severity == "MEDIUM"
        assert finding.cwe_id == "CWE-22"
        assert finding.source == "prose_attack_surface"
        assert "SAY-281" in finding.description


class TestFileFilter:
    """The detector only inspects `*.prose.md` files."""

    def test_skips_non_prose_md(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES / "not_a_prose_contract.md")
        assert findings == []

    def test_skips_unrelated_extension(self, tmp_path):
        (tmp_path / "thing.py").write_text("print('hello')\n")
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path / "thing.py")
        assert findings == []


class TestDirectoryWalk:
    """`analyze(dir)` walks recursively and aggregates findings."""

    def test_walks_fixtures_dir(self):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(FIXTURES)
        cats = _categories(findings)
        assert "prose_binding_poisoning_risk" in cats
        assert "prose_diff_scope_unbounded" in cats

    def test_walks_empty_dir(self, tmp_path):
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path)
        assert findings == []

    def test_walks_nested_dir(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        (nested / "deep.prose.md").write_text(
            "---\nname: deep\nkind: system\n---\n\n"
            "### Requires\n\n- evidence: run — upstream evidence\n\n"
            "### Ensures\n\n- summary: text\n"
        )
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path)
        assert "prose_binding_poisoning_risk" in _categories(findings)


class TestKindFilter:
    """Only `kind: system | service | responsibility | gateway` are scanned."""

    def test_skips_kind_test(self, tmp_path):
        (tmp_path / "x.prose.md").write_text(
            "---\nname: x\nkind: test\n---\n\n"
            "### Requires\n\n- evidence: run\n"
        )
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path / "x.prose.md")
        assert findings == []

    def test_skips_kind_pattern(self, tmp_path):
        (tmp_path / "x.prose.md").write_text(
            "---\nname: x\nkind: pattern\n---\n\n"
            "### Requires\n\n- evidence: run\n"
        )
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path / "x.prose.md")
        assert findings == []

    def test_flags_kind_responsibility(self, tmp_path):
        (tmp_path / "x.prose.md").write_text(
            "---\nname: x\nkind: responsibility\nid: x.responsibility\n---\n\n"
            "### Requires\n\n- evidence: run — upstream\n\n"
            "### Ensures\n\n- summary: text\n"
        )
        analyzer = ProseAttackSurfaceAnalyzer()
        findings = analyzer.analyze(tmp_path / "x.prose.md")
        assert "prose_binding_poisoning_risk" in _categories(findings)


class TestParser:
    """Spot-check the `_parse_prose_md` helper."""

    def test_parses_kind_from_frontmatter(self):
        spec = _parse_prose_md(FIXTURES / "system_improver_canonical.prose.md")
        assert spec is not None
        assert spec["frontmatter"]["kind"] == "system"

    def test_extracts_sections(self):
        spec = _parse_prose_md(FIXTURES / "system_improver_canonical.prose.md")
        assert spec is not None
        assert "requires" in spec["sections"]
        assert "ensures" in spec["sections"]
        assert "invariants" not in spec["sections"]

    def test_returns_none_for_missing_frontmatter(self, tmp_path):
        p = tmp_path / "no_frontmatter.prose.md"
        p.write_text("# Just a Title\n\nNo frontmatter at all.\n")
        assert _parse_prose_md(p) is None

    def test_returns_none_for_unclosed_frontmatter(self, tmp_path):
        p = tmp_path / "unclosed.prose.md"
        p.write_text("---\nname: x\nkind: system\nnever closed\n")
        assert _parse_prose_md(p) is None

    def test_accumulates_multi_service_sections(self):
        """Multi-service systems must union their `### Requires` content lists."""
        spec = _parse_prose_md(FIXTURES / "system_improver_full.prose.md")
        assert spec is not None
        req_content = spec["sections"]["requires"]["content_with_lines"]
        text = "\n".join(line for _ln, line in req_content).lower()
        # System-level Requires: `inspection: run`
        assert "inspection: run" in text
        # Implementer-level Requires: `analysis:`
        assert "analysis:" in text


@pytest.mark.parametrize(
    "fixture,expected_categories",
    [
        ("system_improver_canonical.prose.md", {"prose_binding_poisoning_risk", "prose_diff_scope_unbounded"}),
        ("system_improver_full.prose.md", {"prose_binding_poisoning_risk", "prose_diff_scope_unbounded"}),
        ("prose_contributor_canonical.prose.md", set()),
        ("clean_baseline.prose.md", set()),
        ("diff_scope_unbounded.prose.md", {"prose_diff_scope_unbounded"}),
        ("comparison_diffs.prose.md", set()),
        ("malicious_upstream_payload.prose.md", set()),
        ("not_a_prose_contract.md", set()),
    ],
)
def test_fixture_oracle(fixture, expected_categories):
    """Each fixture's expected detector outcome matches what the analyzer produces."""
    analyzer = ProseAttackSurfaceAnalyzer()
    findings = analyzer.analyze(FIXTURES / fixture)
    assert _categories(findings) == expected_categories
