"""Base adapter class for external tool integrations."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
import shutil
import logging

from ..core.types import VulnerabilityFinding

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """Base class for external tool adapters.

    Subclasses wrap external scanning tools (Semgrep, TruffleHog, Trivy, CodeQL)
    and normalize their output into VulnerabilityFinding objects.

    External tools are optional — if not installed, the adapter skips gracefully.
    """

    name: str = "base"
    tool_command: str = ""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    @abstractmethod
    def run(self, target: Path) -> List[VulnerabilityFinding]:
        """Run the external tool and return normalized findings."""
        ...

    def is_available(self) -> bool:
        """Check if the external tool is installed and accessible."""
        if not self.tool_command:
            return False
        return shutil.which(self.tool_command) is not None

    def check_or_skip(self, target: Path) -> List[VulnerabilityFinding]:
        """Run if available and enabled, otherwise return empty list."""
        if not self.enabled:
            logger.debug(f"{self.name}: disabled by config")
            return []
        if not self.is_available():
            logger.debug(f"{self.name}: {self.tool_command} not found, skipping")
            return []
        try:
            return self.run(target)
        except Exception as e:
            logger.warning(f"{self.name}: scan failed: {e}")
            return []

    def __repr__(self) -> str:
        available = "available" if self.is_available() else "not found"
        enabled = "enabled" if self.enabled else "disabled"
        return f"<{self.__class__.__name__} [{available}, {enabled}]>"
