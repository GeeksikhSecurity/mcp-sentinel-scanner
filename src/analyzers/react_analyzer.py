"""React-specific vulnerability analyzer."""

import re
from pathlib import Path
from typing import List

from ..mcp_sentinel_scanner import VulnerabilityFinding


class ReactAnalyzer:
    """Analyzer for React-specific vulnerabilities."""

    REACT_PATTERNS = [
        {
            "category": "react_xss",
            "regex": re.compile(r"dangerouslySetInnerHTML.*\{.*\}"),
            "severity": "HIGH",
            "description": "Potential XSS via dangerouslySetInnerHTML",
            "recommendation": "Use DOMPurify to sanitize HTML content",
            "cwe": "CWE-79",
        },
        {
            "category": "hardcoded_api_key",
            "regex": re.compile(
                r"REACT_APP_[A-Z_]*(?:KEY|SECRET|TOKEN)\s*=\s*['\"]?([^'\"\s]{10,})"
            ),
            "severity": "CRITICAL",
            "description": "Hardcoded API key in React environment variable",
            "recommendation": "Use build-time environment variables",
            "cwe": "CWE-798",
        },
        {
            "category": "insecure_storage",
            "regex": re.compile(r"localStorage\.setItem\(['\"](?:token|jwt|auth|key)['\"]"),
            "severity": "MEDIUM",
            "description": "Sensitive data stored in localStorage",
            "recommendation": "Use secure storage or httpOnly cookies",
            "cwe": "CWE-922",
        },
    ]

    def analyze(self, target: Path) -> List[VulnerabilityFinding]:
        """Analyze React files for vulnerabilities."""
        findings = []

        for file_path in self._find_react_files(target):
            try:
                content = file_path.read_text(errors="ignore")
                findings.extend(self._scan_file(file_path, content))
            except (PermissionError, OSError):
                continue

        return findings

    def _find_react_files(self, target: Path) -> List[Path]:
        """Find React/JSX files and .env files."""
        extensions = {".jsx", ".tsx", ".js", ".ts"}
        files = []

        if target.is_file():
            if target.suffix in extensions or target.name.startswith(".env"):
                files.append(target)
        else:
            for ext in extensions:
                files.extend(target.rglob(f"*{ext}"))
            # Also include .env files
            files.extend(target.rglob(".env*"))

        return files

    def _scan_file(self, file_path: Path, content: str) -> List[VulnerabilityFinding]:
        """Scan single file for React vulnerabilities."""
        findings = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            for pattern in self.REACT_PATTERNS:
                if pattern["regex"].search(line):
                    findings.append(
                        VulnerabilityFinding(
                            severity=pattern["severity"],
                            category=pattern["category"],
                            description=pattern["description"],
                            file_path=str(file_path),
                            line_number=idx,
                            code_snippet=line.strip(),
                            recommendation=pattern["recommendation"],
                            cwe_id=pattern["cwe"],
                            confidence=0.85,
                        )
                    )

        return findings
