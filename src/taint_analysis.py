"""Taint analysis module for data flow tracking."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

@dataclass
class TaintPath:
    """Represents a taint flow path from source to sink."""
    source: str
    sink: str
    file_path: str
    source_line: int
    sink_line: int
    variables: List[str]
    confidence: float


class TaintAnalyzer:
    """Analyzes data flow from untrusted sources to dangerous sinks."""

    # Untrusted data sources
    SOURCES = {
        "input", "raw_input",
        "request.args", "request.form", "request.json", "request.data",
        "request.GET", "request.POST",
        "sys.argv", "os.environ",
        "socket.recv", "socket.recvfrom",
    }

    # Dangerous sinks - these are pattern definitions for detection, not actual code
    SINKS = {  # nosec: B403 - These are string literals for taint analysis, not executable code
        "eval", "exec", "compile", "__import__",
        "os.system", "os.popen", "os.spawn",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "open", "file",
        "pickle.loads", "yaml.load",  # nosec: Pattern definitions, not actual deserialization
        "cursor.execute", "execute",
    }

    def __init__(self):
        self.tainted_vars: Dict[str, Tuple[int, str]] = {}
        self.paths: List[TaintPath] = []

    def analyze(self, file_path: Path, source_code: str) -> List[TaintPath]:
        """Analyze taint flows in the given source code."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        self.tainted_vars = {}
        self.paths = []

        visitor = TaintVisitor(self)
        visitor.visit(tree)

        return self.paths

    def mark_tainted(self, var_name: str, line: int, source: str):
        """Mark a variable as tainted."""
        self.tainted_vars[var_name] = (line, source)

    def check_taint(self, var_name: str) -> Tuple[int, str] | None:
        """Check if a variable is tainted."""
        return self.tainted_vars.get(var_name)

    def add_path(self, path: TaintPath):
        """Add a detected taint path."""
        self.paths.append(path)


class TaintVisitor(ast.NodeVisitor):
    """AST visitor for taint tracking."""

    def __init__(self, analyzer: TaintAnalyzer):
        self.analyzer = analyzer

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments."""
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
        """Track function calls - check for tainted data flowing to sinks."""
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
                            confidence=0.9
                        )
                        self.analyzer.add_path(path)

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        """Get the full name of a function call or attribute."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""


__all__ = ["TaintAnalyzer", "TaintPath"]
