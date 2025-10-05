"""Core scanning engine for the MCP Sentinel Scanner."""
from __future__ import annotations

import ast
import json
import math
import os
import queue
import re
import statistics
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .advanced_detection import AdvancedDetectionEngine, AdvancedFinding


SUPPORTED_EXTENSIONS: Set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".sh",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
}


SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
}


@dataclass
class VulnerabilityFinding:
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
    files_scanned: int
    total_lines: int
    scan_time: float
    vulnerabilities_found: int
    asr_score: float
    severity_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    summary: ScanSummary
    findings: List[VulnerabilityFinding]
    advanced_findings: List[AdvancedFinding]


class MCPSentinelScanner:
    """Main scanner orchestrating pattern, AST, and advanced analyses."""

    def __init__(
        self,
        config: Optional[Dict[str, object]] = None,
        parallel_workers: int = 4,
    ) -> None:
        self.config = config or {}
        self.parallel_workers = max(1, parallel_workers)
        self.advanced_engine = AdvancedDetectionEngine(self.config)
        self.patterns = self._load_default_patterns()
        self.secret_regex = re.compile(r"(api|secret|token|password|key)[\s:=]+['\"]?([A-Za-z0-9/+=_-]{12,})", re.IGNORECASE)

    # region public API
    def scan(self, target: str | Path) -> ScanResult:
        start_time = time.perf_counter()
        paths = self._collect_files(target)
        findings: List[VulnerabilityFinding] = []
        line_count = 0

        if not paths:
            raise FileNotFoundError(f"No scannable files found in {target}")

        work_queue: "queue.Queue[Path]" = queue.Queue()
        for path in paths:
            work_queue.put(path)

        findings_lock = threading.Lock()

        def worker() -> None:
            while True:
                try:
                    file_path = work_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    local_findings, lines = self._scan_file(file_path)
                except Exception as exc:  # pragma: no cover - defensive logging
                    local_findings = [
                        VulnerabilityFinding(
                            severity="LOW",
                            category="scanner_error",
                            description=f"Failed to scan file: {exc}",
                            file_path=str(file_path),
                            line_number=1,
                            code_snippet="",
                            recommendation="Review file manually.",
                            confidence=0.1,
                        )
                    ]
                    lines = 0

                with findings_lock:
                    findings.extend(local_findings)
                    nonlocal line_count
                    line_count += lines
                work_queue.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.parallel_workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        advanced_findings = self.advanced_engine.analyse(findings)
        scan_time = time.perf_counter() - start_time
        severity_distribution = self._severity_distribution(findings)
        asr_score = self._calculate_asr(severity_distribution)

        summary = ScanSummary(
            files_scanned=len(paths),
            total_lines=line_count,
            scan_time=scan_time,
            vulnerabilities_found=len(findings),
            asr_score=asr_score,
            severity_distribution=severity_distribution,
        )
        return ScanResult(summary=summary, findings=findings, advanced_findings=advanced_findings)

    # endregion

    # region outputs
    def to_json(self, result: ScanResult) -> str:
        payload = {
            "scan_summary": {
                "files_scanned": result.summary.files_scanned,
                "total_lines": result.summary.total_lines,
                "scan_time": result.summary.scan_time,
                "vulnerabilities_found": result.summary.vulnerabilities_found,
                "asr_score": result.summary.asr_score,
                "severity_distribution": result.summary.severity_distribution,
            },
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                    "cwe_id": f.cwe_id,
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
            "advanced_findings": [finding.to_dict() for finding in result.advanced_findings],
        }
        return json.dumps(payload, indent=2)

    def to_sarif(self, result: ScanResult, source_root: str = ".") -> str:
        """Generate SARIF format output."""
        try:
            from .reporters.sarif_reporter import SARIFReporter
            return SARIFReporter.generate(result, source_root)
        except ImportError:
            raise ImportError("SARIF reporter not available")

    def to_html(self, result: ScanResult, title: str = "MCP Sentinel Security Report") -> str:
        """Generate HTML format output."""
        try:
            from .reporters.html_reporter import HTMLReporter
            return HTMLReporter.generate(result, title)
        except ImportError:
            raise ImportError("HTML reporter not available")

    def to_markdown(self, result: ScanResult) -> str:
        lines = [
            "# MCP Sentinel Scanner Report",
            "",
            "## Summary",
            f"* Files scanned: {result.summary.files_scanned}",
            f"* Total lines: {result.summary.total_lines}",
            f"* Vulnerabilities: {result.summary.vulnerabilities_found}",
            f"* ASR Score: {result.summary.asr_score:.2%}",
            "",
            "## Severity Distribution",
        ]
        for severity, count in sorted(result.summary.severity_distribution.items(), reverse=True):
            lines.append(f"* {severity.title()}: {count}")
        lines.append("\n## Findings")
        if not result.findings:
            lines.append("No findings detected.")
        for finding in result.findings:
            lines.extend(
                [
                    "",
                    f"### {finding.severity} · {finding.category}",
                    f"* File: `{finding.file_path}` @ line {finding.line_number}",
                    f"* Description: {finding.description}",
                    f"* Recommendation: {finding.recommendation}",
                    f"* CWE: {finding.cwe_id or 'N/A'}",
                    f"* Confidence: {finding.confidence:.0%}",
                    "",
                    "```",
                    finding.code_snippet.strip() or "<no snippet>",
                    "```",
                ]
            )
        if result.advanced_findings:
            lines.append("\n## Advanced Analysis")
            for finding in result.advanced_findings:
                lines.append(f"* {finding.severity} · {finding.category} · {finding.description}")
        return "\n".join(lines)

    # endregion

    # region internals
    def _collect_files(self, target: str | Path) -> List[Path]:
        target_path = Path(target).expanduser().resolve()
        if target_path.is_file():
            return [target_path] if target_path.suffix.lower() in SUPPORTED_EXTENSIONS else []

        paths: List[Path] = []
        for root, _, files in os.walk(target_path):
            if self._is_excluded(root):
                continue
            for file_name in files:
                path = Path(root) / file_name
                # Check both file extension and exclusion patterns
                if path.suffix.lower() in SUPPORTED_EXTENSIONS and not self._is_excluded(str(path)):
                    paths.append(path)
        return paths

    def _is_excluded(self, path: str) -> bool:
        exclusions = self.config.get("exclude", [])
        return any(excl in path for excl in exclusions)

    def _scan_file(self, file_path: Path) -> Tuple[List[VulnerabilityFinding], int]:
        try:
            text = file_path.read_text(errors="ignore")
        except UnicodeDecodeError:
            text = file_path.read_bytes().decode("utf-8", errors="ignore")
        findings: List[VulnerabilityFinding] = []
        lines = text.splitlines()

        findings.extend(self._pattern_scan(file_path, lines))
        findings.extend(self._secret_scan(file_path, lines))
        if file_path.suffix.lower() == ".py":
            findings.extend(self._ast_scan(file_path, text))
        return findings, len(lines)

    def _pattern_scan(self, file_path: Path, lines: Sequence[str]) -> List[VulnerabilityFinding]:
        local_findings: List[VulnerabilityFinding] = []
        for idx, line in enumerate(lines, start=1):
            for pattern in self.patterns:
                if pattern["regex"].search(line):
                    local_findings.append(
                        VulnerabilityFinding(
                            severity=pattern["severity"],
                            category=pattern["category"],
                            description=pattern["description"],
                            file_path=str(file_path),
                            line_number=idx,
                            code_snippet=line.strip(),
                            recommendation=pattern["recommendation"],
                            cwe_id=pattern.get("cwe"),
                            confidence=pattern.get("confidence", 0.5),
                        )
                    )
        return local_findings

    def _secret_scan(self, file_path: Path, lines: Sequence[str]) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        for idx, line in enumerate(lines, start=1):
            match = self.secret_regex.search(line)
            if not match:
                continue
            entropy = self._shannon_entropy(match.group(2))
            if entropy < 3.5:
                continue
            findings.append(
                VulnerabilityFinding(
                    severity="HIGH",
                    category="hardcoded_secret",
                    description=f"Potential secret detected (entropy={entropy:.2f})",
                    file_path=str(file_path),
                    line_number=idx,
                    code_snippet=line.strip(),
                    recommendation="Move secrets to environment variables or a secret manager.",
                    cwe_id="CWE-798",
                    confidence=min(0.9, entropy / 6),
                )
            )
        return findings

    def _ast_scan(self, file_path: Path, text: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings

        class DangerousCallVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.calls: List[Tuple[int, str]] = []

            def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
                callee = self._resolve_name(node.func)
                if callee in {"eval", "exec", "compile", "os.system", "subprocess.Popen", "subprocess.call"}:
                    self.calls.append((node.lineno, callee))
                self.generic_visit(node)

            def _resolve_name(self, node: ast.expr) -> str:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    return f"{self._resolve_name(node.value)}.{node.attr}".strip(".")
                return ""

        visitor = DangerousCallVisitor()
        visitor.visit(tree)

        for lineno, callee in visitor.calls:
            findings.append(
                VulnerabilityFinding(
                    severity="CRITICAL" if callee in {"eval", "exec"} else "HIGH",
                    category="dangerous_function",
                    description=f"Use of dangerous function: {callee}",
                    file_path=str(file_path),
                    line_number=lineno,
                    code_snippet=self._extract_line(text, lineno),
                    recommendation="Avoid dangerous dynamic execution functions or validate inputs.",
                    cwe_id="CWE-95",
                    confidence=0.95,
                )
            )
        return findings

    def _load_default_patterns(self) -> List[Dict[str, object]]:
        patterns: List[Dict[str, object]] = [
            {
                "category": "sql_injection",
                "regex": re.compile(r"SELECT .* WHERE .*['\"]\s*\+"),
                "severity": "CRITICAL",
                "description": "Potential SQL string concatenation",
                "recommendation": "Use parameterized queries.",
                "cwe": "CWE-89",
                "confidence": 0.75,
            },
            {
                "category": "command_injection",
                "regex": re.compile(r"subprocess\.(call|run|Popen)\(.*shell=True"),
                "severity": "CRITICAL",
                "description": "Shell execution with user input",
                "recommendation": "Avoid shell=True or sanitize input.",
                "cwe": "CWE-78",
                "confidence": 0.8,
            },
            {
                "category": "path_traversal",
                "regex": re.compile(r"\.\./"),
                "severity": "HIGH",
                "description": "Relative path traversal detected",
                "recommendation": "Normalise and validate file paths.",
                "cwe": "CWE-22",
                "confidence": 0.6,
            },
            {
                "category": "weak_crypto",
                "regex": re.compile(r"hashlib\.(md5|sha1)"),
                "severity": "MEDIUM",
                "description": "Weak cryptographic hash function",
                "recommendation": "Replace with SHA-256 or stronger.",
                "cwe": "CWE-327",
                "confidence": 0.7,
            },
            {
                "category": "xxe",
                "regex": re.compile(r"resolve_entities\s*=\s*True"),
                "severity": "HIGH",
                "description": "External entity resolution enabled",
                "recommendation": "Disable entity resolution in XML parsers.",
                "cwe": "CWE-611",
                "confidence": 0.65,
            },
            {
                "category": "insecure_deserialization",
                "regex": re.compile(r"pickle\.loads|yaml\.load\(.*Loader=None\)"),
                "severity": "CRITICAL",
                "description": "Potential insecure deserialization",
                "recommendation": "Use safe loaders or avoid loading untrusted data.",
                "cwe": "CWE-502",
                "confidence": 0.7,
            },
        ]
        return patterns

    def _extract_line(self, text: str, lineno: int, context: int = 1) -> str:
        lines = text.splitlines()
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        snippet = lines[start:end]
        return "\n".join(snippet)

    def _severity_distribution(self, findings: Sequence[VulnerabilityFinding]) -> Dict[str, int]:
        distribution: Dict[str, int] = {key: 0 for key in SEVERITY_WEIGHTS}
        for finding in findings:
            distribution[finding.severity] = distribution.get(finding.severity, 0) + 1
        # Remove severities with zero counts to keep output tidy
        return {k: v for k, v in distribution.items() if v}

    def _calculate_asr(self, distribution: Dict[str, int]) -> float:
        if not distribution:
            return 0.0
        numerator = sum(SEVERITY_WEIGHTS.get(sev, 0.25) * count for sev, count in distribution.items())
        denominator = sum(distribution.values())
        return min(1.0, numerator / max(1, denominator))

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        probabilities = [value.count(char) / len(value) for char in set(value)]
        return -sum(p * math.log2(p) for p in probabilities)

    # endregion


__all__ = [
    "MCPSentinelScanner",
    "VulnerabilityFinding",
    "ScanResult",
    "ScanSummary",
]
