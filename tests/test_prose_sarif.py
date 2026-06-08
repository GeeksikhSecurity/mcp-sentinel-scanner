"""
tests/test_prose_sarif.py
~~~~~~~~~~~~~~~~~~~~~~~~~

Test suite for sentinel.sarif.prose_sarif.

Coverage:
  - Tool driver structure (name, version, rules)
  - Rule ID mapping: Finding.category → SARIF ruleId
  - Level mapping: Finding.severity → SARIF level
  - Single-file finding → SARIF result (ruleId, level, location, properties)
  - Composition finding → SARIF result with relatedLocations
  - Artifact index (deduplication, sorting)
  - Round-trip: build() returns a valid JSON-serializable dict
  - Edge cases: empty inputs, unknown severity fallback
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from sentinel.analyzers.prose_attack_surface import Finding
from sentinel.analyzers.composition_analyzer import (
    CompositionFinding,
    ProseContractProfile,
)
from sentinel.sarif.prose_sarif import (
    ProseSarifEmitter,
    findings_to_sarif,
    composition_findings_to_sarif,
    CATEGORY_TO_RULE_ID,
    SEVERITY_TO_LEVEL,
)

FIXTURES = Path(__file__).parent / "fixtures"

# ─────────────────────────────────────────────────────────────────────────────
# Factories
# ─────────────────────────────────────────────────────────────────────────────

def _finding(
    path: str = "evals/system-improver.prose.md",
    category: str = "prose_binding_poisoning_risk",
    severity: str = "HIGH",
    message: str = "Test finding.",
    line_no: int = 14,
    prose_kind: str = "eval",
    binding_key: str = "inspection-output",
    has_invariants: bool = False,
    fork_lineage: str = "unknown",
) -> Finding:
    return Finding(
        path=Path(path),
        category=category,
        severity=severity,
        message=message,
        line_no=line_no,
        prose_kind=prose_kind,
        binding_key=binding_key,
        has_invariants=has_invariants,
        fork_lineage=fork_lineage,
    )


def _soft_profile(name: str = "soft-agent", path: str = "evals/soft.prose.md") -> ProseContractProfile:
    return ProseContractProfile(
        path=Path(path),
        name=name,
        kind="eval",
        has_invariants=False,
        invariant_count=0,
        provides_run_keys=["inspection-output"],
        requires_run_keys=[],
        line_count=20,
    )


def _hard_profile(name: str = "prose-contributor", path: str = "packages/std/hard.prose.md") -> ProseContractProfile:
    return ProseContractProfile(
        path=Path(path),
        name=name,
        kind="eval",
        has_invariants=True,
        invariant_count=8,
        provides_run_keys=[],
        requires_run_keys=["inspection-output"],
        line_count=40,
    )


def _comp_finding(
    soft: ProseContractProfile | None = None,
    hard: ProseContractProfile | None = None,
) -> CompositionFinding:
    soft = soft or _soft_profile()
    hard = hard or _hard_profile()
    return CompositionFinding(
        soft_agent=soft,
        hard_agent=hard,
        handoff_key="inspection-output",
        handoff_type="run-binding-key-overlap",
        message=(
            f"Dangerous composition: '{soft.name}' (soft — 0 invariants) "
            f"hands off to '{hard.name}' (hard — 8 invariants)."
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Emitter with git stubbed out
# ─────────────────────────────────────────────────────────────────────────────

def _emitter(tmp_path: Path) -> ProseSarifEmitter:
    """Returns an emitter with fork_lineage stubbed to avoid real git calls."""
    emitter = ProseSarifEmitter(repo_root=tmp_path)
    emitter.fork_lineage = "test-owner/test-repo@main"
    return emitter


# ─────────────────────────────────────────────────────────────────────────────
# Tool driver structure
# ─────────────────────────────────────────────────────────────────────────────

class TestToolDriver:

    def test_sarif_version(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert sarif["version"] == "2.1.0"

    def test_schema_field(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert "json.schemastore.org" in sarif["$schema"]

    def test_driver_name(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "mcp-sentinel-scanner"

    def test_driver_version(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.3.0"

    def test_three_rules_present(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {
            "PROSE_EVAL_POISONING_RISK",
            "PROSE_SHAPE_VIOLATION",
            "PROSE_COMPOSITION_RISK",
        }

    def test_eval_poisoning_level_is_error(self, tmp_path):
        sarif  = _emitter(tmp_path).build()
        rules  = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["PROSE_EVAL_POISONING_RISK"]["defaultConfiguration"]["level"] == "error"

    def test_shape_violation_level_is_warning(self, tmp_path):
        sarif  = _emitter(tmp_path).build()
        rules  = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["PROSE_SHAPE_VIOLATION"]["defaultConfiguration"]["level"] == "warning"

    def test_composition_risk_level_is_error(self, tmp_path):
        sarif  = _emitter(tmp_path).build()
        rules  = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["PROSE_COMPOSITION_RISK"]["defaultConfiguration"]["level"] == "error"

    def test_composition_risk_precision_medium(self, tmp_path):
        sarif  = _emitter(tmp_path).build()
        rules  = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["PROSE_COMPOSITION_RISK"]["properties"]["precision"] == "medium"

    def test_eval_poisoning_precision_high(self, tmp_path):
        sarif  = _emitter(tmp_path).build()
        rules  = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["PROSE_EVAL_POISONING_RISK"]["properties"]["precision"] == "high"


# ─────────────────────────────────────────────────────────────────────────────
# Single-file finding → SARIF result
# ─────────────────────────────────────────────────────────────────────────────

class TestSingleFindingResult:

    def test_binding_poisoning_maps_to_correct_rule(self, tmp_path):
        f    = _finding(category="prose_binding_poisoning_risk")
        sarif = _emitter(tmp_path).build(single_findings=[f])
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "PROSE_EVAL_POISONING_RISK"

    def test_diff_scope_maps_to_correct_rule(self, tmp_path):
        f     = _finding(category="prose_diff_scope_unbounded", severity="MEDIUM")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "PROSE_SHAPE_VIOLATION"

    def test_high_severity_maps_to_error(self, tmp_path):
        f     = _finding(severity="HIGH")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self, tmp_path):
        f     = _finding(severity="MEDIUM")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_severity_maps_to_note(self, tmp_path):
        f     = _finding(severity="LOW")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_unknown_severity_falls_back_to_warning(self, tmp_path):
        f          = _finding()
        f.severity = "UNKNOWN"
        sarif       = _emitter(tmp_path).build(single_findings=[f])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_message_preserved(self, tmp_path):
        msg   = "Unique test message 12345."
        f     = _finding(message=msg)
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        assert sarif["runs"][0]["results"][0]["message"]["text"] == msg

    def test_location_line_number(self, tmp_path):
        f     = _finding(line_no=42)
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42

    def test_line_zero_clamped_to_one(self, tmp_path):
        f     = _finding(line_no=0)
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1

    def test_uri_base_id(self, tmp_path):
        f     = _finding()
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        art   = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert art["uriBaseId"] == "%SRCROOT%"

    def test_properties_prose_kind(self, tmp_path):
        f     = _finding(prose_kind="eval")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.kind"] == "eval"

    def test_properties_binding_key(self, tmp_path):
        f     = _finding(binding_key="inspection-output")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.binding_key"] == "inspection-output"

    def test_properties_has_invariants_false(self, tmp_path):
        f     = _finding(has_invariants=False)
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.has_invariants"] is False

    def test_fork_lineage_from_finding(self, tmp_path):
        f             = _finding(fork_lineage="owner/repo@feature")
        sarif          = _emitter(tmp_path).build(single_findings=[f])
        props          = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.fork_lineage"] == "owner/repo@feature"

    def test_fork_lineage_falls_back_to_emitter(self, tmp_path):
        """When finding.fork_lineage is 'unknown', emitter's fork_lineage is used."""
        f              = _finding(fork_lineage="unknown")
        emitter        = _emitter(tmp_path)
        emitter.fork_lineage = "emitter-owner/repo@main"
        sarif           = emitter.build(single_findings=[f])
        props           = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.fork_lineage"] == "emitter-owner/repo@main"


# ─────────────────────────────────────────────────────────────────────────────
# Composition finding → SARIF result with relatedLocations
# ─────────────────────────────────────────────────────────────────────────────

class TestCompositionResult:

    def test_composition_rule_id(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        assert sarif["runs"][0]["results"][0]["ruleId"] == "PROSE_COMPOSITION_RISK"

    def test_composition_level_is_error(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_primary_location_is_soft_agent(self, tmp_path):
        soft  = _soft_profile(path="evals/soft.prose.md")
        cf    = _comp_finding(soft=soft)
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        result = sarif["runs"][0]["results"][0]
        uri   = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "soft" in uri

    def test_related_location_is_hard_agent(self, tmp_path):
        hard  = _hard_profile(path="packages/std/hard.prose.md")
        cf    = _comp_finding(hard=hard)
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        result = sarif["runs"][0]["results"][0]
        assert "relatedLocations" in result
        assert len(result["relatedLocations"]) == 1
        uri   = result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "hard" in uri

    def test_related_location_has_id_1(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        related = sarif["runs"][0]["results"][0]["relatedLocations"][0]
        assert related["id"] == 1

    def test_related_location_message_mentions_hard_agent(self, tmp_path):
        hard  = _hard_profile(name="prose-contributor")
        cf    = _comp_finding(hard=hard)
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        msg   = sarif["runs"][0]["results"][0]["relatedLocations"][0]["message"]["text"]
        assert "prose-contributor" in msg

    def test_properties_soft_agent_name(self, tmp_path):
        soft  = _soft_profile(name="inspection-runner")
        cf    = _comp_finding(soft=soft)
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.composition.soft_agent"] == "inspection-runner"

    def test_properties_hard_agent_name(self, tmp_path):
        hard  = _hard_profile(name="prose-contributor")
        cf    = _comp_finding(hard=hard)
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.composition.hard_agent"] == "prose-contributor"

    def test_properties_invariant_counts(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.composition.soft_invariant_count"] == 0
        assert props["prose.composition.hard_invariant_count"] == 8

    def test_properties_handoff_key(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.composition.handoff_key"] == "inspection-output"

    def test_properties_handoff_type(self, tmp_path):
        cf    = _comp_finding()
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        props  = sarif["runs"][0]["results"][0]["properties"]
        assert props["prose.composition.handoff_type"] == "run-binding-key-overlap"


# ─────────────────────────────────────────────────────────────────────────────
# Artifact index
# ─────────────────────────────────────────────────────────────────────────────

class TestArtifacts:

    def test_single_finding_produces_one_artifact(self, tmp_path):
        f     = _finding(path="evals/foo.prose.md")
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        assert len(sarif["runs"][0]["artifacts"]) == 1

    def test_two_findings_same_path_deduplicates(self, tmp_path):
        f1    = _finding(path="evals/foo.prose.md")
        f2    = _finding(path="evals/foo.prose.md", line_no=30)
        sarif  = _emitter(tmp_path).build(single_findings=[f1, f2])
        assert len(sarif["runs"][0]["artifacts"]) == 1

    def test_composition_finding_produces_two_artifacts(self, tmp_path):
        cf    = _comp_finding(
            soft=_soft_profile(path="evals/soft.prose.md"),
            hard=_hard_profile(path="packages/std/hard.prose.md"),
        )
        sarif  = _emitter(tmp_path).build(comp_findings=[cf])
        assert len(sarif["runs"][0]["artifacts"]) == 2

    def test_artifacts_have_uri_base_id(self, tmp_path):
        f     = _finding()
        sarif  = _emitter(tmp_path).build(single_findings=[f])
        art   = sarif["runs"][0]["artifacts"][0]["location"]
        assert art["uriBaseId"] == "%SRCROOT%"

    def test_empty_build_has_no_artifacts(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert sarif["runs"][0]["artifacts"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Empty / edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_build_is_valid_sarif(self, tmp_path):
        sarif = _emitter(tmp_path).build()
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []

    def test_build_is_json_serializable(self, tmp_path):
        f  = _finding()
        cf = _comp_finding()
        sarif = _emitter(tmp_path).build(single_findings=[f], comp_findings=[cf])
        # Should not raise
        json.dumps(sarif)

    def test_mixed_findings_ordered_single_then_composition(self, tmp_path):
        """Single-file findings appear before composition findings."""
        f  = _finding()
        cf = _comp_finding()
        sarif = _emitter(tmp_path).build(single_findings=[f], comp_findings=[cf])
        results = sarif["runs"][0]["results"]
        assert results[0]["ruleId"] in {"PROSE_EVAL_POISONING_RISK", "PROSE_SHAPE_VIOLATION"}
        assert results[1]["ruleId"] == "PROSE_COMPOSITION_RISK"

    def test_write_creates_file(self, tmp_path):
        out   = tmp_path / "test.sarif"
        emitter = _emitter(tmp_path)
        emitter.write(out, single_findings=[_finding()])
        assert out.exists()
        data  = json.loads(out.read_text())
        assert data["version"] == "2.1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function wrappers
# ─────────────────────────────────────────────────────────────────────────────

class TestConvenienceFunctions:

    def test_findings_to_sarif_returns_valid_structure(self, tmp_path):
        sarif = findings_to_sarif([_finding()], repo_root=tmp_path)
        assert "runs" in sarif
        assert sarif["runs"][0]["results"][0]["ruleId"] == "PROSE_EVAL_POISONING_RISK"

    def test_composition_findings_to_sarif_returns_valid_structure(self, tmp_path):
        sarif = composition_findings_to_sarif([_comp_finding()], repo_root=tmp_path)
        assert sarif["runs"][0]["results"][0]["ruleId"] == "PROSE_COMPOSITION_RISK"


# ─────────────────────────────────────────────────────────────────────────────
# Mapping constants (fast, no I/O)
# ─────────────────────────────────────────────────────────────────────────────

def test_category_to_rule_id_mapping():
    assert CATEGORY_TO_RULE_ID["prose_binding_poisoning_risk"] == "PROSE_EVAL_POISONING_RISK"
    assert CATEGORY_TO_RULE_ID["prose_diff_scope_unbounded"]   == "PROSE_SHAPE_VIOLATION"
    assert CATEGORY_TO_RULE_ID["prose_composition_risk"]       == "PROSE_COMPOSITION_RISK"


def test_severity_to_level_mapping():
    assert SEVERITY_TO_LEVEL["HIGH"]   == "error"
    assert SEVERITY_TO_LEVEL["MEDIUM"] == "warning"
    assert SEVERITY_TO_LEVEL["LOW"]    == "note"
