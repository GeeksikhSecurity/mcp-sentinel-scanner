"""Core scanning engine for the MCP Sentinel Scanner."""

from __future__ import annotations

import ast
import fnmatch
import json
import math
import os
import queue
import re
import threading
import time
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Set, Tuple

from .advanced_detection import AdvancedDetectionEngine, AdvancedFinding
from .filters.false_positive_filter import apply_false_positive_filter
from .types import ScanResult, ScanSummary, VulnerabilityFinding

if TYPE_CHECKING:
    from .fp_reducer.context_analyzer import ContextAnalyzer

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

# Per-character Shannon entropy is bounded by log2(distinct chars). Real secrets
# top out near ~4.75 bits (a Stripe key) and effectively never exceed ~5.0; a
# 64-char all-distinct hex string only reaches 4.0. A floor above this ceiling
# silently disables hardcoded_secret (CWE-798) detection — the regression that
# the automated triage loop drove the config to 6.0. Used as a fail-loud guard.
_SECRET_ENTROPY_REACHABLE_MAX = 5.0


class MCPSentinelScanner:
    """Main scanner orchestrating pattern, AST, and advanced analyses."""

    # Class-level constants -- compiled once, shared across all instances.
    _FP_INDICATORS: frozenset = frozenset([
        # Variable/type patterns
        "accesstoken", "refreshtoken", "apikey", "secretkey", "authkey",
        "tokenvalue", "keyvalue", "secretvalue", "passwordvalue",
        # Common SDK patterns
        "sdkaccesstoken", "sdktoken", "_sdk", "gettoken", "getkey",
        # Function/method patterns
        "def ", "async def ", "class ", "import ", "from ",
        # Type annotation patterns
        ": str", ": string", ": optional", "| none", "-> ",
        # Assignment to variable/function
        "= get", "= fetch", "= load", "= read", "= retrieve",
        "= none", "= null", "= undefined",
    ])

    _PLACEHOLDER_RE = re.compile(
        r"(your[_-]|example[_-]|test[_-]|demo[_-]|sample[_-]|"
        r"replace[_-]|insert[_-]|put[_-]|enter[_-]|change[_-]|"
        r"xxx+|placeholder|dummy|fake|mock)",
        re.IGNORECASE,
    )

    _SECRET_RE = re.compile(
        r"(api[_-]?key|secret|token|password|auth[_-]?key|client[_-]?secret|"
        r"private[_-]?key|access[_-]?token|refresh[_-]?token|bearer)"
        r"[\s]*[:=][\s]*['\"]([A-Za-z0-9/+=_\-]{12,})['\"]",
        re.IGNORECASE,
    )

    def __init__(
        self,
        config: Optional[Dict[str, object]] = None,
        parallel_workers: int = 4,
    ) -> None:
        self.config = config or {}
        self._secret_entropy_min = 3.5
        self.advanced_engine = AdvancedDetectionEngine(self.config)
        self.patterns = self._load_default_patterns()
        self._extend_patterns_from_custom_rules_file()
        self._apply_scanner_tuning_overrides(parallel_workers)

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

        threads = [
            threading.Thread(target=worker, daemon=True) for _ in range(self.parallel_workers)
        ]
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
        """
        Check whether a path should be excluded.

        Supports:
        - Directory names (e.g., "node_modules") -> excludes if any path component matches
        - Globs on basenames (e.g., "*.d.ts")
        - Globs on paths (e.g., "dist/**", "**/*.min.js")
        """
        exclusions = self.config.get("exclude", []) or []
        if not exclusions:
            return False

        p = Path(path)
        parts_lower = [part.lower() for part in p.parts]
        path_posix_lower = p.as_posix().lower()
        basename_lower = p.name.lower()

        for raw in exclusions:
            if not raw:
                continue
            pattern = str(raw).strip()
            if not pattern:
                continue

            pattern_lower = pattern.lower()

            # Simple directory/file token (no glob chars, no separators): match any component
            if not any(ch in pattern for ch in ["*", "?", "["]) and ("/" not in pattern) and (
                os.sep not in pattern
            ):
                if pattern_lower in parts_lower:
                    return True
                continue

            # Path globs: match against full posix path
            if "/" in pattern or os.sep in pattern:
                normalized = pattern.replace(os.sep, "/")
                if fnmatch.fnmatch(path_posix_lower, normalized.lower()):
                    return True
                continue

            # Basename globs: match file name only
            if fnmatch.fnmatch(basename_lower, pattern_lower):
                return True

        return False

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

        # Apply false positive reduction by default.  Disable explicitly via config
        # {"falsePositives": {"enabled": false}}.
        if self.config.get("falsePositives", {}).get("enabled", True):
            # 1) Context-based filtering (safe for all categories)
            # Lazy import to avoid circular dependency
            from .fp_reducer.context_analyzer import ContextAnalyzer

            context_analyzer = ContextAnalyzer()
            findings = context_analyzer.filter_findings(findings)

            # 2) Credential-focused filter: apply ONLY to hardcoded secrets
            secret_findings = [f for f in findings if f.category == "hardcoded_secret"]
            other_findings = [f for f in findings if f.category != "hardcoded_secret"]

            if secret_findings:
                secret_dicts = [
                    {
                        "code_snippet": f.code_snippet,
                        "vulnerability_type": f.category,
                        "file_path": f.file_path,
                        "context": f.description,
                        "severity": f.severity,
                        "line_number": f.line_number,
                        "recommendation": f.recommendation,
                        "cwe_id": f.cwe_id,
                        "confidence": f.confidence,
                    }
                    for f in secret_findings
                ]
                filtered_secret_dicts = apply_false_positive_filter(secret_dicts)

                filtered_secrets = [
                    VulnerabilityFinding(
                        severity=item.get("severity", "LOW"),
                        category=item.get("vulnerability_type", "hardcoded_secret"),
                        description=item.get("context", ""),
                        file_path=item.get("file_path", str(file_path)),
                        line_number=int(item.get("line_number", 1)),
                        code_snippet=item.get("code_snippet", ""),
                        recommendation=item.get("recommendation", ""),
                        cwe_id=item.get("cwe_id"),
                        confidence=float(item.get("confidence_score", item.get("confidence", 0.5))),
                    )
                    for item in filtered_secret_dicts
                ]
                findings = other_findings + filtered_secrets

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
            line_lower = line.lower()

            # Skip lines with false positive indicators
            if any(fp in line_lower for fp in self._FP_INDICATORS):
                continue

            # Primary regex: explicit key=value patterns in quotes
            match = self._SECRET_RE.search(line)
            if match:
                secret_value = match.group(2)
                entropy = self._shannon_entropy(secret_value)

                # Skip low entropy (repetitive/simple patterns); floor from ``scanner_tuning`` in
                # ``configs/security_rules.json`` (default 3.5).
                if entropy < self._secret_entropy_min:
                    continue

                # Skip if it looks like a placeholder
                if self._PLACEHOLDER_RE.search(secret_value):
                    continue

                # Skip if it looks like a variable/function name (has underscores and lowercase)
                if self._looks_like_identifier(secret_value):
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

    def _looks_like_identifier(self, value: str) -> bool:
        """Check if value looks like a variable/function name rather than a secret."""
        # Identifiers typically: start with letter/underscore, have underscores, mostly lowercase
        if not value:
            return False

        # If it starts with underscore or lowercase letter and has underscores, likely identifier
        if value[0] in ("_",) or (value[0].islower() and "_" in value):
            # Count pattern: lowercase_with_underscores
            parts = value.split("_")
            lowercase_parts = sum(1 for p in parts if p.islower() or p == "")
            if lowercase_parts > len(parts) * 0.6:
                return True

        # If it looks like a function call pattern (ends with parenthesis content)
        if "(" in value or ")" in value:
            return True

        # If it's a type annotation pattern
        if value.startswith(("Optional", "List", "Dict", "Set", "Tuple", "str", "int", "bool")):
            return True

        return False

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
                if callee in {
                    "eval",
                    "exec",
                    "compile",
                    "os.system",
                    "subprocess.Popen",
                    "subprocess.call",
                }:
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
                    recommendation="Avoid dangerous dynamic execution functions or validate inputs.",  # noqa: E501
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
            {
                # Detect accidental committing of system prompt text / guardrails into source code.
                # This is a common operational risk for AI/MCP systems (prompt leakage / prompt injection surface).
                "category": "prompt_leakage",
                "regex": re.compile(r"NEVER\s+REVEAL\s+THIS\s+PROMPT", re.IGNORECASE),
                "severity": "MEDIUM",
                "description": "System prompt / guardrail text detected in source code (potential prompt leakage risk)",
                "recommendation": "Avoid committing system prompts/guardrails to source; store securely, minimize exposure, and treat prompts as sensitive configuration.",
                "confidence": 0.6,
            },
        ]
        return patterns

    def _extend_patterns_from_custom_rules_file(self) -> None:
        """Append regex patterns from ``configs/security_rules.json`` (or ``custom_rules_file``)."""
        raw_path = self.config.get("custom_rules_file")
        if not raw_path:
            return
        path = Path(str(raw_path)).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        tuning = payload.get("scanner_tuning") or {}
        self._secret_entropy_min = float(tuning.get("secret_shannon_entropy_min", self._secret_entropy_min))
        if "parallel_workers" in tuning:
            self.config["parallel_workers"] = int(tuning["parallel_workers"])
        disabled_ids = set(str(x) for x in (self.config.get("disabled_custom_rule_ids") or []))
        for rule in payload.get("custom_rules", []):
            if rule.get("enabled") is False:
                continue
            if str(rule.get("id", "")) in disabled_ids:
                continue
            pattern_str = str(rule.get("pattern", "")).strip()
            if not pattern_str:
                continue
            try:
                compiled = re.compile(pattern_str)
            except re.error:
                continue
            self.patterns.append(
                {
                    "category": str(rule.get("category") or rule.get("id") or "custom"),
                    "regex": compiled,
                    "severity": str(rule.get("severity", "MEDIUM")),
                    "description": str(rule.get("description", "Custom rule match")),
                    "recommendation": str(rule.get("recommendation", "Review and fix.")),
                    "cwe": rule.get("cwe"),
                    "confidence": float(rule.get("confidence", 0.75)),
                }
            )

    def _apply_scanner_tuning_overrides(self, parallel_workers: int) -> None:
        """Apply ``config['scanner_tuning']`` after file load (CLI / parent config wins over file)."""
        ov = self.config.get("scanner_tuning") or {}
        if "secret_shannon_entropy_min" in ov:
            self._secret_entropy_min = float(ov["secret_shannon_entropy_min"])
        if "parallel_workers" in ov:
            self.config["parallel_workers"] = int(ov["parallel_workers"])
        self.parallel_workers = max(1, int(self.config.get("parallel_workers", parallel_workers)))

        # Fail loud on an entropy floor that cannot be reached by real secrets —
        # otherwise hardcoded-secret detection is silently dead (see constant).
        if self._secret_entropy_min > _SECRET_ENTROPY_REACHABLE_MAX:
            warnings.warn(
                f"secret_shannon_entropy_min={self._secret_entropy_min} exceeds the "
                f"reachable range for real secrets (~{_SECRET_ENTROPY_REACHABLE_MAX} bits); "
                f"hardcoded-secret (CWE-798) detection is effectively disabled. "
                f"Lower it (code default 3.5) to restore coverage.",
                stacklevel=2,
            )

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
        numerator = sum(
            SEVERITY_WEIGHTS.get(sev, 0.25) * count for sev, count in distribution.items()
        )
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
