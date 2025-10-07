"""Context-aware false positive analysis."""

import re
from pathlib import Path
from typing import List, Optional

from ..mcp_sentinel_scanner import VulnerabilityFinding


class ContextAnalyzer:
    """Analyzes context to identify false positives."""

    TEST_PATTERNS = [
        re.compile(r"\b(test|spec|mock|fixture|example|sample)\b", re.IGNORECASE),
        re.compile(r"describe\s*\(|it\s*\(|expect\s*\("),
        re.compile(r"jest\.|vitest\.|mocha\.|chai\."),
    ]

    TEST_PREFIXES = ["MOCK_", "TEST_", "EXAMPLE_", "SAMPLE_", "FIXTURE_", "DEMO_"]

    def is_likely_false_positive(
        self, finding: VulnerabilityFinding, file_content: Optional[str] = None
    ) -> bool:
        """Check if finding is likely a false positive."""
        # Check file path patterns
        if self._is_test_file(finding.file_path):
            return True

        # Check variable naming patterns
        if self._has_test_prefix(finding.code_snippet):
            return True

        # Check surrounding context if available
        if file_content and self._is_test_context(finding, file_content):
            return True

        # Check for nosec comments
        if "nosec" in finding.code_snippet.lower():
            return True

        return False

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file."""
        path = Path(file_path)

        # Check file name patterns
        test_indicators = [
            ".test.",
            ".spec.",
            "_test.",
            "_spec.",
            "__tests__",
            "__mocks__",
            "test/",
            "tests/",
            ".stories.",
            "storybook/",
        ]

        return any(indicator in str(path).lower() for indicator in test_indicators)

    def _has_test_prefix(self, code_snippet: str) -> bool:
        """Check if code has test-related prefixes."""
        return any(prefix in code_snippet for prefix in self.TEST_PREFIXES)

    def _is_test_context(self, finding: VulnerabilityFinding, file_content: str) -> bool:
        """Check if finding is in test context."""
        lines = file_content.splitlines()

        # Get surrounding lines (5 before and after)
        start_line = max(0, finding.line_number - 6)
        end_line = min(len(lines), finding.line_number + 5)
        context = "\n".join(lines[start_line:end_line])

        # Check for test patterns in context
        return any(pattern.search(context) for pattern in self.TEST_PATTERNS)

    def filter_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Filter out likely false positives."""
        filtered = []

        for finding in findings:
            try:
                # Try to read file content for context analysis
                file_content = None
                if Path(finding.file_path).exists():
                    file_content = Path(finding.file_path).read_text(errors="ignore")

                if not self.is_likely_false_positive(finding, file_content):
                    filtered.append(finding)
            except (OSError, PermissionError):
                # If we can't read the file, keep the finding
                filtered.append(finding)

        return filtered
