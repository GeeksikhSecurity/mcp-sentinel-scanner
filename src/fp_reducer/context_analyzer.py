"""Context-aware false positive analysis."""

import re
from pathlib import Path
from typing import List, Optional

from ..mcp_sentinel_scanner import VulnerabilityFinding


class ContextAnalyzer:
    """Analyzes context to identify false positives."""

    TEST_PATTERNS = [
        re.compile(r"\b(test|spec|mock|fixture|example|sample)\b", re.IGNORECASE),
        re.compile(r"describe\s*\(|it\s*\(|test\s*\(|expect\s*\("),
        re.compile(r"jest\.|vitest\.|mocha\.|chai\."),
        re.compile(r"toBe\(|toEqual\(|toMatch\(|toThrow\("),  # Jest matchers
        re.compile(r"beforeEach\(|afterEach\(|beforeAll\(|afterAll\("),  # Test hooks
    ]

    TEST_PREFIXES = ["MOCK_", "TEST_", "EXAMPLE_", "SAMPLE_", "FIXTURE_", "DEMO_"]

    _IMPORT_PATTERNS = [
        re.compile(r"^\s*(import|from|require|#include)"),
        re.compile(r"^\s*import\s+.*from\s+['\"].*['\"]"),
    ]

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

        # Check for import statements (common false positive for path traversal)
        if self._is_import_statement(finding.code_snippet):
            return True
        
        # Skip path traversal in non-dangerous contexts
        if finding.category == "path_traversal" and not self._is_dangerous_path_context(finding.code_snippet):
            return True

        # Check surrounding context if available.
        #
        # Important: this heuristic is most reliable for secrets/credentials where tests frequently embed
        # dummy values. Applying it broadly can suppress legitimate findings (e.g., package.json often
        # contains the word "test").
        if (
            file_content
            and finding.category == "hardcoded_secret"
            and self._is_test_context(finding, file_content)
        ):
            return True

        # Check for nosec comments
        if "nosec" in finding.code_snippet.lower():
            return True
        
        # Check for placeholder/example values
        if finding.category == "hardcoded_secret" and self._is_placeholder_value(finding.code_snippet):
            return True

        return False

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file."""
        path = Path(file_path)
        name_lower = path.name.lower()
        parts_lower = [part.lower() for part in path.parts]

        # Directory-based signals (match exact path components, not substrings).
        # This avoids treating pytest temp directories like "test_react_project_scan0" as tests.
        test_dirs = {
            "test",
            "tests",
            "__tests__",
            "__mocks__",
            "spec",
            "specs",
            "fixtures",
            "examples",
            "demo",
            "storybook",
            "stories",
            "testing",
        }
        if any(part in test_dirs for part in parts_lower):
            return True

        # Filename-based signals.
        file_markers = (
            ".test.",
            ".spec.",
            ".stories.",
            "_test.",
            "_spec.",
        )
        if any(marker in name_lower for marker in file_markers):
            return True

        # Common Python test naming conventions.
        if name_lower.startswith("test_") and name_lower.endswith(".py"):
            return True
        if name_lower.endswith("_test.py"):
            return True

        return False

    def _has_test_prefix(self, code_snippet: str) -> bool:
        """Check if code has test-related prefixes."""
        return any(prefix in code_snippet for prefix in self.TEST_PREFIXES)

    def _is_import_statement(self, code_snippet: str) -> bool:
        """Check if code snippet is an import statement."""
        return any(pattern.match(code_snippet.strip()) for pattern in self._IMPORT_PATTERNS)
    
    def _is_dangerous_path_context(self, code_snippet: str) -> bool:
        """Check if path traversal is in a dangerous context."""
        dangerous_contexts = [
            "open(", "readFile", "writeFile", "file(", "File(",
            "path.join(", "os.path.join", "filepath.Join",
            "exec(", "system(", "popen(", "subprocess"
        ]
        return any(ctx in code_snippet for ctx in dangerous_contexts)
    
    def _is_placeholder_value(self, code_snippet: str) -> bool:
        """Check if secret is a placeholder/example value."""
        placeholder_patterns = [
            r"your_.*_key_here",
            r"your_.*_token_here", 
            r"your_.*_secret_here",
            r"your.*api.*key.*here",
            r"example_.*_key",
            r"sample_.*_key",
            r"placeholder",
            r"xxx{3,}",
            r"aaa{3,}",
            r"123{3,}",
            r"test.*key",
            r"demo.*key",
            r"fake.*key",
            r"sk-123{3,}",
            r".*key.*here$",
            r".*token.*here$"
        ]
        code_lower = code_snippet.lower()
        return any(re.search(pattern, code_lower) for pattern in placeholder_patterns)

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
