"""Core type definitions for Sentinel Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VulnerabilityFinding:
    """Represents a single vulnerability finding."""

    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: float = 0.5
    source: str = "builtin"  # which scanner found this


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    files_scanned: int = 0
    scan_duration: float = 0.0
    # Legacy fields for backward compat
    total_lines: int = 0
    scan_time: float = 0.0
    vulnerabilities_found: int = 0
    asr_score: float = 0.0
    severity_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan result with findings and summary."""

    target: str = ""
    summary: ScanSummary = field(default_factory=ScanSummary)
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    advanced_findings: List[Any] = field(default_factory=list)
    raw_count: int = 0
    deduped_count: int = 0
    project_types: Dict[str, bool] = field(default_factory=dict)


@dataclass
class ComplianceRequirement:
    """A single compliance framework requirement."""

    framework: str
    requirement_id: str
    title: str
    description: str
    status: str  # COMPLIANT | NON_COMPLIANT | PARTIAL | NOT_APPLICABLE
    evidence: List[str] = field(default_factory=list)
    findings: List[VulnerabilityFinding] = field(default_factory=list)


@dataclass
class ComplianceResult:
    """Result of a compliance evaluation against a framework."""

    framework: str
    version: str
    score: float  # 0.0 - 1.0
    requirements: List[ComplianceRequirement] = field(default_factory=list)
    summary: str = ""
