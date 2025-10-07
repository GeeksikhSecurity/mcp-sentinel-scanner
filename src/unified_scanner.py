"""Unified security scanner orchestrating multiple tools."""
import concurrent.futures
import time
from pathlib import Path
from typing import Dict, List, Optional

from .adapters import TruffleHogAdapter, SemgrepAdapter
from .analyzers import ReactAnalyzer, NpmAnalyzer
from .fp_reducer import ContextAnalyzer, MLClassifier
from .mcp_sentinel_scanner import MCPSentinelScanner, ScanResult, ScanSummary, VulnerabilityFinding


class UnifiedScanner:
    """Unified security scanner orchestrating multiple tools."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # Initialize tools
        self.mcp_scanner = MCPSentinelScanner(
            config, parallel_workers=self.config.get("parallel_workers", 4)
        )
        self.trufflehog = TruffleHogAdapter(self.config.get("tools", {}).get("truffleHog", {}))
        self.semgrep = SemgrepAdapter(self.config.get("tools", {}).get("semgrep", {}))

        # Initialize analyzers
        self.react_analyzer = ReactAnalyzer()
        self.npm_analyzer = NpmAnalyzer()

        # Initialize false positive reducers
        self.context_analyzer = ContextAnalyzer()
        self.ml_classifier = MLClassifier()

    def scan(self, target: str | Path) -> ScanResult:
        """Run unified scan with all tools."""
        start_time = time.perf_counter()
        target_path = Path(target)

        # Run all scanners in parallel
        all_findings = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._run_mcp_scanner, target_path): "mcp",
                executor.submit(self._run_trufflehog, target_path): "trufflehog",
                executor.submit(self._run_semgrep, target_path): "semgrep",
                executor.submit(self._run_react_analyzer, target_path): "react",
                executor.submit(self._run_npm_analyzer, target_path): "npm",
            }

            for future in concurrent.futures.as_completed(futures):
                tool_name = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    # Log error but continue with other tools
                    print(f"Warning: {tool_name} scanner failed: {e}")

        # Apply false positive reduction
        filtered_findings = self._reduce_false_positives(all_findings)

        # Calculate summary
        scan_time = time.perf_counter() - start_time
        summary = self._create_summary(target_path, filtered_findings, scan_time)

        return ScanResult(
            summary=summary,
            findings=filtered_findings,
            advanced_findings=[],  # Advanced findings integrated into main findings
        )

    def _run_mcp_scanner(self, target: Path) -> List[VulnerabilityFinding]:
        """Run MCP scanner."""
        try:
            result = self.mcp_scanner.scan(target)
            return result.findings
        except Exception:
            return []

    def _run_trufflehog(self, target: Path) -> List[VulnerabilityFinding]:
        """Run TruffleHog scanner."""
        return self.trufflehog.run(target)

    def _run_semgrep(self, target: Path) -> List[VulnerabilityFinding]:
        """Run Semgrep scanner."""
        return self.semgrep.run(target)

    def _run_react_analyzer(self, target: Path) -> List[VulnerabilityFinding]:
        """Run React analyzer."""
        return self.react_analyzer.analyze(target)

    def _run_npm_analyzer(self, target: Path) -> List[VulnerabilityFinding]:
        """Run npm analyzer."""
        return self.npm_analyzer.analyze(target)

    def _reduce_false_positives(
        self, findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """Apply false positive reduction."""
        # Only apply FP reduction if explicitly enabled
        if not self.config.get("falsePositives", {}).get("enabled", False):
            return findings

        # First pass: context-based filtering
        filtered = self.context_analyzer.filter_findings(findings)

        # Second pass: ML-based filtering
        if self.config.get("falsePositives", {}).get("mlModel", {}).get("enabled", False):
            filtered = self.ml_classifier.filter_findings(filtered)

        return filtered

    def _create_summary(
        self, target: Path, findings: List[VulnerabilityFinding], scan_time: float
    ) -> ScanSummary:
        """Create scan summary."""
        severity_distribution = {}
        for finding in findings:
            severity_distribution[finding.severity] = (
                severity_distribution.get(finding.severity, 0) + 1
            )

        # Count files (approximate)
        files_scanned = len(list(target.rglob("*"))) if target.is_dir() else 1

        # Calculate ASR score
        severity_weights = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
        numerator = sum(
            severity_weights.get(sev, 0.25) * count for sev, count in severity_distribution.items()
        )
        denominator = sum(severity_distribution.values()) or 1
        asr_score = min(1.0, numerator / denominator)

        return ScanSummary(
            files_scanned=files_scanned,
            total_lines=0,  # Not calculated for performance
            scan_time=scan_time,
            vulnerabilities_found=len(findings),
            asr_score=asr_score,
            severity_distribution=severity_distribution,
        )

    # Delegate output methods to MCP scanner
    def to_json(self, result: ScanResult) -> str:
        return self.mcp_scanner.to_json(result)

    def to_sarif(self, result: ScanResult, source_root: str = ".") -> str:
        return self.mcp_scanner.to_sarif(result, source_root)

    def to_html(self, result: ScanResult, title: str = "Unified Security Report") -> str:
        return self.mcp_scanner.to_html(result, title)

    def to_markdown(self, result: ScanResult) -> str:
        return self.mcp_scanner.to_markdown(result)
