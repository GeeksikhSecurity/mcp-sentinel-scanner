"""Built-in scanner wrapper — exposes MCPSentinelScanner as a BaseAnalyzer."""

from pathlib import Path
from typing import List, Optional

from ..core.types import VulnerabilityFinding
from .base import BaseAnalyzer


class BuiltinAnalyzer(BaseAnalyzer):
    """Wraps the core MCPSentinelScanner engine as a registry-compatible analyzer.

    This is the default scanner that runs with zero external dependencies.
    It uses pattern matching, AST analysis, entropy detection, and taint tracking.
    """

    name = "builtin"
    supported_extensions = [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
        ".rb", ".php", ".sh", ".c", ".cpp", ".h", ".cs",
    ]

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self._scanner = None

    def _get_scanner(self):
        """Lazy-load the scanner to avoid circular imports."""
        if self._scanner is None:
            from ..core.scanner import MCPSentinelScanner
            self._scanner = MCPSentinelScanner()
        return self._scanner

    def analyze(self, target: Path) -> List[VulnerabilityFinding]:
        """Run the built-in scanner and return findings."""
        scanner = self._get_scanner()
        result = scanner.scan(target)
        return result.findings
