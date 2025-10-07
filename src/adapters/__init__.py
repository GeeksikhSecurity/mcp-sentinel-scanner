"""Tool adapters for external security scanners."""
from .trufflehog_adapter import TruffleHogAdapter
from .semgrep_adapter import SemgrepAdapter

__all__ = ["TruffleHogAdapter", "SemgrepAdapter"]
