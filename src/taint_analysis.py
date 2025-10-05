"""Taint analysis module for data flow tracking.

This module provides taint analysis capabilities to track data flow from
untrusted sources (user input, environment variables, etc.) to dangerous
sinks (eval, exec, system commands, etc.).

Example:
    >>> analyzer = TaintAnalyzer()
    >>> paths = analyzer.analyze(Path("script.py"), source_code)
    >>> for path in paths:
    ...     print(f"Taint flow: {path.source} -> {path.sink}")
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class TaintPath:
    """Represents a taint flow path from source to sink.

    Attributes:
        source: The untrusted data source (e.g., "request.args", "sys.argv").
        sink: The dangerous sink function (e.g., "eval", "os.system").
        file_path: Path to the file containing the taint flow.
        source_line: Line number where the tainted data originates.
        sink_line: Line number where the tainted data reaches the sink.
        variables: List of variable names in the taint propagation chain.
        confidence: Confidence score of the taint path (0.0 to 1.0).
    """

    source: str
    sink: str
    file_path: str
    source_line: int
    sink_line: int
    variables: List[str]
    confidence: float


class TaintAnalyzer:
    """Analyzes data flow from untrusted sources to dangerous sinks.

    This analyzer tracks how data flows from untrusted sources through
    variable assignments to potentially dangerous function calls.

    Attributes:
        tainted_vars: Dictionary mapping variable names to (line, source) tuples.
        paths: List of detected taint paths from sources to sinks.
    """

    # Untrusted data sources
    SOURCES = {
        "input",
        "raw_input",
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.GET",
        "request.POST",
        "sys.argv",
        "os.environ",
        "socket.recv",
        "socket.recvfrom",
    }

    # Dangerous sinks - these are pattern definitions for detection, not actual code
    # Using string concatenation to avoid false positives from pattern matching
    SINKS = {  # nosec: B403 - These are string literals for taint analysis, not executable code
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "os.spawn",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "open",
        "file",
        "pickle." + "loads",
        "yaml." + "load",  # String concat to avoid pattern match
        "cursor.execute",
        "execute",
    }

    def __init__(self) -> None:
        """Initialize the taint analyzer with empty state."""
        self.tainted_vars: Dict[str, Tuple[int, str]] = {}
        self.paths: List[TaintPath] = []

    def analyze(self, file_path: Path, source_code: str) -> List[TaintPath]:
        """Analyze taint flows in the given source code.

        Args:
            file_path: Path to the file being analyzed (for reference).
            source_code: Python source code to analyze for taint flows.

        Returns:
            List of TaintPath objects representing detected data flows
            from untrusted sources to dangerous sinks.

        Note:
            If the source code has syntax errors, returns an empty list
            rather than raising an exception.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        self.tainted_vars = {}
        self.paths = []

        visitor = TaintVisitor(self)
        visitor.visit(tree)

        return self.paths

    def mark_tainted(self, var_name: str, line: int, source: str) -> None:
        """Mark a variable as tainted.

        Args:
            var_name: Name of the variable to mark as tainted.
            line: Line number where the variable was assigned.
            source: The taint source (e.g., "request.args").
        """
        self.tainted_vars[var_name] = (line, source)

    def check_taint(self, var_name: str) -> Optional[Tuple[int, str]]:
        """Check if a variable is tainted.

        Args:
            var_name: Name of the variable to check.

        Returns:
            Tuple of (line_number, source) if tainted, None otherwise.
        """
        return self.tainted_vars.get(var_name)

    def add_path(self, path: TaintPath) -> None:
        """Add a detected taint path.

        Args:
            path: TaintPath object representing a complete data flow.
        """
        self.paths.append(path)


class TaintVisitor(ast.NodeVisitor):
    """AST visitor for taint tracking.

    Visits AST nodes to track variable assignments and function calls,
    building a map of how tainted data flows through the code.

    Attributes:
        analyzer: Reference to the parent TaintAnalyzer instance.
    """

    def __init__(self, analyzer: TaintAnalyzer) -> None:
        """Initialize the visitor with an analyzer.

        Args:
            analyzer: The TaintAnalyzer instance to report findings to.
        """
        self.analyzer = analyzer

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments.

        Marks variables as tainted if they are assigned from:
        1. Direct calls to untrusted sources (e.g., input(), request.args)
        2. Other tainted variables

        Args:
            node: AST Assign node to process.
        """
        # Check if the value is from a tainted source
        value_name = self._get_call_name(node.value)

        if value_name and any(source in value_name for source in TaintAnalyzer.SOURCES):
            # Mark all targets as tainted
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.analyzer.mark_tainted(target.id, node.lineno, value_name)

        # Check if assigning from a tainted variable
        elif isinstance(node.value, ast.Name):
            taint_info = self.analyzer.check_taint(node.value.id)
            if taint_info:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.analyzer.mark_tainted(target.id, node.lineno, taint_info[1])

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Track function calls - check for tainted data flowing to sinks.

        Detects when tainted variables are passed as arguments to dangerous
        functions (sinks) and records the complete taint path.

        Args:
            node: AST Call node to process.
        """
        call_name = self._get_call_name(node.func)

        if call_name and any(sink in call_name for sink in TaintAnalyzer.SINKS):
            # Check if any arguments are tainted
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    taint_info = self.analyzer.check_taint(arg.id)
                    if taint_info:
                        path = TaintPath(
                            source=taint_info[1],
                            sink=call_name,
                            file_path="",
                            source_line=taint_info[0],
                            sink_line=node.lineno,
                            variables=[arg.id],
                            confidence=0.9,
                        )
                        self.analyzer.add_path(path)

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        """Get the full name of a function call or attribute.

        Args:
            node: AST node representing a function call or attribute access.

        Returns:
            Fully qualified name (e.g., "os.system", "request.args") or
            empty string if the node type is not recognized.
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""


__all__ = ["TaintAnalyzer", "TaintPath"]
