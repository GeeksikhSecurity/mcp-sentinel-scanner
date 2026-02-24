"""Base reporter class for output formatters."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
import logging

from ..core.types import ScanResult

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """Base class for scan result reporters.

    Reporters format ScanResult objects into different output formats
    (terminal, JSON, SARIF, HTML, Markdown, client reports).
    """

    name: str = "base"
    file_extension: str = ""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render the scan result to a string."""
        ...

    def write(self, result: ScanResult, output_path: Path) -> None:
        """Render and write to a file."""
        content = self.render(result)
        output_path.write_text(content, encoding="utf-8")
        logger.info(f"{self.name}: wrote report to {output_path}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.name}]>"
