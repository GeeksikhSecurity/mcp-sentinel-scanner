"""Scan pipeline orchestrator.

Replaces unified_scanner.py with a configurable, registry-based pipeline:
  detect project -> select scanners -> parallel run -> deduplicate -> FP filter -> score -> report
"""

from pathlib import Path
from typing import Dict, List, Optional, Set
import hashlib
import logging
import time

from .types import VulnerabilityFinding, ScanResult, ScanSummary
from .registry import ScannerRegistry

logger = logging.getLogger(__name__)


def detect_project_type(target: Path) -> Dict[str, bool]:
    """Auto-detect what kind of project lives at the target path."""
    indicators = {
        "nodejs": (target / "package.json").exists(),
        "python": (
            (target / "pyproject.toml").exists()
            or (target / "setup.py").exists()
            or (target / "requirements.txt").exists()
        ),
        "go": (target / "go.mod").exists(),
        "rust": (target / "Cargo.toml").exists(),
        "docker": (target / "Dockerfile").exists() or (target / "docker-compose.yml").exists(),
        "terraform": any(target.glob("*.tf")),
    }
    return {k: v for k, v in indicators.items() if v}


def deduplicate_findings(
    findings: List[VulnerabilityFinding],
) -> List[VulnerabilityFinding]:
    """Remove duplicate findings reported by multiple tools.

    Uses file path + line number + vulnerability category as the dedup key.
    When duplicates exist, keep the one with the highest severity.
    """
    seen: Dict[str, VulnerabilityFinding] = {}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    for finding in findings:
        key = _finding_key(finding)
        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            existing_rank = severity_rank.get(
                getattr(existing, "severity", "LOW"), 1
            )
            new_rank = severity_rank.get(
                getattr(finding, "severity", "LOW"), 1
            )
            if new_rank > existing_rank:
                seen[key] = finding

    deduped = list(seen.values())
    removed = len(findings) - len(deduped)
    if removed > 0:
        logger.info(f"Deduplication: removed {removed} duplicate findings")
    return deduped


def _finding_key(finding: VulnerabilityFinding) -> str:
    """Generate a stable dedup key for a finding."""
    parts = [
        getattr(finding, "file_path", ""),
        str(getattr(finding, "line_number", 0)),
        getattr(finding, "category", getattr(finding, "vulnerability_type", "")),
    ]
    raw = "|".join(str(p) for p in parts)
    return hashlib.md5(raw.encode()).hexdigest()


class ScanPipeline:
    """Orchestrates the full scan workflow.

    Usage:
        registry = ScannerRegistry()
        # ... register analyzers ...
        pipeline = ScanPipeline(registry)
        result = pipeline.run(Path("/path/to/project"))
    """

    def __init__(
        self,
        registry: ScannerRegistry,
        fp_filters: Optional[List] = None,
        parallel: int = 4,
        severity_threshold: str = "LOW",
    ) -> None:
        self.registry = registry
        self.fp_filters = fp_filters or []
        self.parallel = parallel
        self.severity_threshold = severity_threshold
        self._severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def run(
        self,
        target: Path,
        tools: Optional[List[str]] = None,
    ) -> ScanResult:
        """Execute the full scan pipeline.

        Steps:
            1. Detect project type
            2. Run all scanners in parallel
            3. Deduplicate findings
            4. Apply FP reduction filters
            5. Filter by severity threshold
            6. Build ScanResult
        """
        start = time.time()
        target = target.resolve()

        # Step 1: Detect project
        project_types = detect_project_type(target)
        logger.info(f"Project types detected: {project_types}")

        # Step 2: Run scanners
        raw_findings = self.registry.run_all(
            target, parallel=self.parallel, tools=tools
        )

        # Step 3: Deduplicate
        deduped = deduplicate_findings(raw_findings)

        # Step 4: FP reduction
        filtered = deduped
        for fp_filter in self.fp_filters:
            before = len(filtered)
            if hasattr(fp_filter, "filter_findings"):
                filtered = fp_filter.filter_findings(filtered)
            elif callable(fp_filter):
                filtered = fp_filter(filtered)
            removed = before - len(filtered)
            if removed > 0:
                filter_name = getattr(fp_filter, "__name__", type(fp_filter).__name__)
                logger.info(f"FP filter '{filter_name}': removed {removed}")

        # Step 5: Severity threshold
        threshold_rank = self._severity_rank.get(self.severity_threshold.upper(), 1)
        findings = [
            f for f in filtered
            if self._severity_rank.get(
                getattr(f, "severity", "LOW"), 1
            ) >= threshold_rank
        ]

        elapsed = time.time() - start

        # Step 6: Build result
        summary = ScanSummary(
            total_findings=len(findings),
            critical=sum(1 for f in findings if getattr(f, "severity", "") == "CRITICAL"),
            high=sum(1 for f in findings if getattr(f, "severity", "") == "HIGH"),
            medium=sum(1 for f in findings if getattr(f, "severity", "") == "MEDIUM"),
            low=sum(1 for f in findings if getattr(f, "severity", "") == "LOW"),
            files_scanned=len({getattr(f, "file_path", "") for f in raw_findings}),
            scan_duration=elapsed,
        )

        return ScanResult(
            target=str(target),
            findings=findings,
            summary=summary,
            raw_count=len(raw_findings),
            deduped_count=len(deduped),
            project_types=project_types,
        )
