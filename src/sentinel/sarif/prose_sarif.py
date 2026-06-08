"""SARIF 2.1.0 serializer for prose attack-surface findings (SAY-281 Phase 3).

Handles three rule types:
  PROSE_EVAL_POISONING_RISK  — Detector A single-file findings
  PROSE_SHAPE_VIOLATION      — Detector B single-file findings
  PROSE_COMPOSITION_RISK     — Composition analyzer multi-file findings
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence

from ..analyzers.composition_analyzer import CompositionFinding
from ..analyzers.prose_attack_surface import Finding


SCANNER_NAME = "mcp-sentinel-scanner"
SCANNER_VERSION = "0.3.0"
SCANNER_URI = "https://github.com/GeeksikhSecurity/mcp-sentinel-scanner"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULE_DEFINITIONS = [
    {
        "id": "PROSE_EVAL_POISONING_RISK",
        "name": "ProseEvalPoisoningRisk",
        "shortDescription": {
            "text": "Eval consumes run-shaped input without invariant constraints."
        },
        "fullDescription": {
            "text": (
                "A prose contract with kind:eval or kind:system declares a run-typed "
                "input (or binding-inherited run) in its ### Requires section but has "
                "no ### Invariants block. Without invariants, a poisoned upstream run "
                "output can direct execution (file paths, tool calls, diff targets) "
                "without constraint. Corresponds to Phase 1 Findings #1 and #2."
            )
        },
        "helpUri": "https://securityleader.ai/prose-attack-surface#eval-poisoning",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "prose", "eval", "injection"],
            "precision": "high",
            "problem.severity": "error",
            "security-severity": "8.0",
        },
    },
    {
        "id": "PROSE_SHAPE_VIOLATION",
        "name": "ProseShapeViolation",
        "shortDescription": {
            "text": "Prose contract declares a diff-typed output without scope constraint."
        },
        "fullDescription": {
            "text": (
                "A prose contract declares a diff- or patch-typed output (or consumes "
                "one as input) without a ### Invariants block bounding the diff target "
                "path. An unbounded diff scope allows attacker-controlled input to "
                "redirect writes to sensitive paths (e.g., .env, ~/.ssh/). Does not "
                "fire on comparison-report bullets (value contains comparison/variance/"
                "divergence/benchmark)."
            )
        },
        "helpUri": "https://securityleader.ai/prose-attack-surface#diff-scope",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["security", "prose", "diff-scope", "path-traversal"],
            "precision": "high",
            "problem.severity": "warning",
            "security-severity": "6.5",
        },
    },
    {
        "id": "PROSE_COMPOSITION_RISK",
        "name": "ProseCompositionRisk",
        "shortDescription": {
            "text": (
                "Soft-constrained agent hands off to hard-constrained agent "
                "without boundary enforcement."
            )
        },
        "fullDescription": {
            "text": (
                "Two prose contracts are composed at runtime where Agent A has no "
                "### Invariants (soft) and Agent B has invariants (hard). The "
                "dangerous boundary is the handoff: Agent A can produce output that "
                "Agent B's invariants cannot retroactively sanitize if the binding is "
                "untyped or run-inherited. Results always include relatedLocations "
                "referencing both the soft and hard contract. Requires multi-file "
                "corpus analysis; single-file scan cannot detect this. Corresponds "
                "to Phase 1 Finding #3."
            )
        },
        "helpUri": "https://securityleader.ai/prose-attack-surface#composition-risk",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "prose", "composition", "agent-handoff"],
            "precision": "medium",
            "problem.severity": "error",
            "security-severity": "8.5",
        },
    },
]

CATEGORY_TO_RULE_ID: dict[str, str] = {
    "prose_binding_poisoning_risk": "PROSE_EVAL_POISONING_RISK",
    "prose_diff_scope_unbounded": "PROSE_SHAPE_VIOLATION",
    "prose_composition_risk": "PROSE_COMPOSITION_RISK",
}

SEVERITY_TO_LEVEL: dict[str, str] = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _resolve_fork_lineage(repo_root: Path) -> str:
    """Derive `{owner}/{repo}@{branch}` from the git remote at `repo_root`.

    Returns "unknown" when git is unavailable, the path is not in a repo, or
    the remote URL can't be parsed.
    """
    try:
        remote_url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"

    match = re.search(r"[:/]([^/]+/[^/]+?)(?:\.git)?$", remote_url)
    if not match:
        return "unknown"
    return f"{match.group(1)}@{branch}"


def _artifact_uri(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _physical_location(path: Path, repo_root: Path, line_no: int = 1) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": _artifact_uri(path, repo_root),
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": max(line_no, 1),
                "startColumn": 1,
            },
        }
    }


def _logical_location(name: str, kind: str = "function") -> dict:
    return {
        "logicalLocations": [
            {
                "name": name,
                "kind": kind,
                "decoratedName": name,
            }
        ]
    }


def _single_finding_to_result(finding: Finding, repo_root: Path, fork_lineage: str) -> dict:
    rule_id = CATEGORY_TO_RULE_ID.get(finding.category, finding.category.upper())
    level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")

    location = {
        **_physical_location(finding.path, repo_root, finding.line_no),
        **_logical_location(finding.path.stem),
    }

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [location],
        "properties": {
            "prose.kind": finding.prose_kind,
            "prose.binding_key": finding.binding_key,
            "prose.has_invariants": finding.has_invariants,
            "prose.fork_lineage": (
                finding.fork_lineage if finding.fork_lineage != "unknown" else fork_lineage
            ),
        },
    }


def _composition_finding_to_result(
    cf: CompositionFinding,
    repo_root: Path,
    fork_lineage: str,
) -> dict:
    """Build a SARIF result for a CompositionFinding.

    Primary location = soft agent (the fix target). relatedLocations carries
    the hard agent so consumers can navigate both sides of the handoff.
    """
    soft = cf.soft_agent
    hard = cf.hard_agent

    primary_location = {
        **_physical_location(soft.path, repo_root, line_no=1),
        **_logical_location(soft.name, kind="function"),
    }

    related_location = {
        "id": 1,
        "message": {
            "text": (
                f"Hard-constrained agent '{hard.name}' receiving the handoff. "
                f"{hard.invariant_count} invariant(s) present but cannot protect "
                f"against poisoned input from the upstream soft agent '{soft.name}'."
            )
        },
        **_physical_location(hard.path, repo_root, line_no=1),
        **_logical_location(hard.name, kind="function"),
    }

    return {
        "ruleId": "PROSE_COMPOSITION_RISK",
        "level": "error",
        "message": {"text": cf.message},
        "locations": [primary_location],
        "relatedLocations": [related_location],
        "properties": {
            "prose.composition.soft_agent": soft.name,
            "prose.composition.hard_agent": hard.name,
            "prose.composition.soft_agent_path": _artifact_uri(soft.path, repo_root),
            "prose.composition.hard_agent_path": _artifact_uri(hard.path, repo_root),
            "prose.composition.soft_invariant_count": soft.invariant_count,
            "prose.composition.hard_invariant_count": hard.invariant_count,
            "prose.composition.handoff_key": cf.handoff_key,
            "prose.composition.handoff_type": cf.handoff_type,
            "prose.fork_lineage": fork_lineage,
        },
    }


def _build_artifacts(
    single_findings: Sequence[Finding],
    comp_findings: Sequence[CompositionFinding],
    repo_root: Path,
) -> List[dict]:
    paths: set[Path] = set()
    for f in single_findings:
        paths.add(f.path)
    for cf in comp_findings:
        paths.add(cf.soft_agent.path)
        paths.add(cf.hard_agent.path)

    return [
        {
            "location": {
                "uri": _artifact_uri(p, repo_root),
                "uriBaseId": "%SRCROOT%",
            }
        }
        for p in sorted(paths)
    ]


def _build_vcs_provenance(repo_root: Path, fork_lineage: str) -> List[dict]:
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        rev = ""
        branch = ""

    owner_repo = fork_lineage.split("@")[0] if "@" in fork_lineage else fork_lineage
    repo_uri = f"https://github.com/{owner_repo}" if owner_repo != "unknown" else ""

    return [
        {
            "repositoryUri": repo_uri,
            "revisionId": rev,
            "branch": branch,
            "mappedTo": {"uriBaseId": "%SRCROOT%"},
            "properties": {
                "prose.fork_origin": owner_repo,
                "prose.fork_scan_target": "local-fork",
                "prose.fork_divergence_check": "pending-phase3b",
            },
        }
    ]


class ProseSarifEmitter:
    """Builds a complete SARIF 2.1.0 document from prose analyzer findings."""

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = (repo_root or Path(".")).resolve()
        self.fork_lineage = _resolve_fork_lineage(self.repo_root)

    def build(
        self,
        single_findings: Sequence[Finding] = (),
        comp_findings: Sequence[CompositionFinding] = (),
    ) -> dict:
        results: List[dict] = []
        for f in single_findings:
            results.append(_single_finding_to_result(f, self.repo_root, self.fork_lineage))
        for cf in comp_findings:
            results.append(
                _composition_finding_to_result(cf, self.repo_root, self.fork_lineage)
            )

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": SCANNER_NAME,
                            "informationUri": SCANNER_URI,
                            "semanticVersion": SCANNER_VERSION,
                            "rules": RULE_DEFINITIONS,
                        }
                    },
                    "results": results,
                    "artifacts": _build_artifacts(
                        single_findings, comp_findings, self.repo_root
                    ),
                    "versionControlProvenance": _build_vcs_provenance(
                        self.repo_root, self.fork_lineage
                    ),
                }
            ],
        }

    def write(
        self,
        path: Path,
        single_findings: Sequence[Finding] = (),
        comp_findings: Sequence[CompositionFinding] = (),
    ) -> None:
        sarif = self.build(single_findings, comp_findings)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)


def findings_to_sarif(
    single_findings: Sequence[Finding],
    repo_root: Optional[Path] = None,
) -> dict:
    return ProseSarifEmitter(repo_root).build(single_findings=single_findings)


def composition_findings_to_sarif(
    comp_findings: Sequence[CompositionFinding],
    repo_root: Optional[Path] = None,
) -> dict:
    return ProseSarifEmitter(repo_root).build(comp_findings=comp_findings)
