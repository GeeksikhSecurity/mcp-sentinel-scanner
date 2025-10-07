"""Specialized analyzers for different technologies."""

from .npm_analyzer import NpmAnalyzer
from .react_analyzer import ReactAnalyzer

__all__ = ["ReactAnalyzer", "NpmAnalyzer"]
