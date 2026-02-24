"""Core type definitions for MCP Sentinel Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from .advanced_detection import AdvancedFinding


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


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    files_scanned: int
    total_lines: int
    scan_time: float
    vulnerabilities_found: int
    asr_score: float
    severity_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan result with findings and summary."""

    summary: ScanSummary
    findings: List[VulnerabilityFinding]
    advanced_findings: List["AdvancedFinding"]
