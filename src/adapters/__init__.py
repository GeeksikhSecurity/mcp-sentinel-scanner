"""Tool adapters for external security scanners."""

from .semgrep_adapter import SemgrepAdapter
from .trufflehog_adapter import TruffleHogAdapter

__all__ = ["TruffleHogAdapter", "SemgrepAdapter"]
