"""Base analyzer class for built-in code analyzers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
import logging

from ..core.types import VulnerabilityFinding

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for built-in code analyzers.

    Unlike adapters (which wrap external tools), analyzers are pure Python
    and have no external dependencies. They run pattern matching, AST analysis,
    or other inspection directly on source files.
    """

    name: str = "base"
    supported_extensions: List[str] = []

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    @abstractmethod
    def analyze(self, target: Path) -> List[VulnerabilityFinding]:
        """Analyze the target path and return findings."""
        ...

    def supports_file(self, file_path: Path) -> bool:
        """Check if this analyzer supports the given file type."""
        if not self.supported_extensions:
            return True
        return file_path.suffix in self.supported_extensions

    def check_or_skip(self, target: Path) -> List[VulnerabilityFinding]:
        """Run if enabled, otherwise return empty list."""
        if not self.enabled:
            logger.debug(f"{self.name}: disabled by config")
            return []
        try:
            return self.analyze(target)
        except Exception as e:
            logger.warning(f"{self.name}: analysis failed: {e}")
            return []

    def __repr__(self) -> str:
        enabled = "enabled" if self.enabled else "disabled"
        return f"<{self.__class__.__name__} [{enabled}]>"
