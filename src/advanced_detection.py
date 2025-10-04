"""Advanced analysis modules for the MCP Sentinel Scanner."""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

@dataclass
class AdvancedFinding:
    severity: str
    category: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    metadata: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "metadata": self.metadata or {},
        }


class AdvancedDetectionEngine:
    """Runs additional semantic checks to enrich findings."""

    def __init__(self, config: Optional[Dict[str, object]] = None) -> None:
        self.config = config or {}

    def analyse(self, findings: Iterable[object]) -> List[AdvancedFinding]:
        path_index = {}
        for finding in findings:
            file_path = getattr(finding, "file_path", None)
            if not file_path:
                continue
            path_index.setdefault(file_path, 0)
            path_index[file_path] += 1

        advanced_findings: List[AdvancedFinding] = []
        for file_path in path_index:
            path = Path(file_path)
            if not path.exists() or path.suffix != ".py":
                continue
            source = path.read_text(errors="ignore")
            advanced_findings.extend(self._run_semantic_checks(path, source))
        return advanced_findings

    def _run_semantic_checks(self, path: Path, source: str) -> List[AdvancedFinding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings: List[AdvancedFinding] = []
        findings.extend(self._auth_bypass_checks(path, tree))
        findings.extend(self._crypto_misuse_checks(path, tree))
        findings.extend(self._complexity_metrics(path, tree))
        return findings

    def _auth_bypass_checks(self, path: Path, tree: ast.AST) -> List[AdvancedFinding]:
        findings: List[AdvancedFinding] = []

        class AlwaysTrueVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.matches: List[int] = []

            def visit_If(self, node: ast.If) -> None:  # type: ignore[override]
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    self.matches.append(node.lineno)
                self.generic_visit(node)

        visitor = AlwaysTrueVisitor()
        visitor.visit(tree)
        for lineno in visitor.matches:
            findings.append(
                AdvancedFinding(
                    severity="CRITICAL",
                    category="auth_bypass",
                    description="Condition always true; potential authentication bypass.",
                    file_path=str(path),
                    line_number=lineno,
                )
            )
        return findings

    def _crypto_misuse_checks(self, path: Path, tree: ast.AST) -> List[AdvancedFinding]:
        findings: List[AdvancedFinding] = []

        class CryptoVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.matches: List[tuple[int, str]] = []

            def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
                name = self._resolve(node.func)
                if name in {"random.random", "random.randrange", "random.randint"}:
                    self.matches.append((node.lineno, "weak_random"))
                if name in {"hashlib.md5", "hashlib.sha1"}:
                    self.matches.append((node.lineno, "weak_hash"))
                self.generic_visit(node)

            def _resolve(self, node: ast.AST) -> str:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    base = self._resolve(node.value)
                    return f"{base}.{node.attr}" if base else node.attr
                return ""

        visitor = CryptoVisitor()
        visitor.visit(tree)
        for lineno, label in visitor.matches:
            if label == "weak_random":
                findings.append(
                    AdvancedFinding(
                        severity="HIGH",
                        category="crypto_misuse",
                        description="Weak randomness used for security-sensitive context.",
                        file_path=str(path),
                        line_number=lineno,
                    )
                )
            if label == "weak_hash":
                findings.append(
                    AdvancedFinding(
                        severity="MEDIUM",
                        category="crypto_misuse",
                        description="Legacy hash function detected.",
                        file_path=str(path),
                        line_number=lineno,
                    )
                )
        return findings

    def _complexity_metrics(self, path: Path, tree: ast.AST) -> List[AdvancedFinding]:
        findings: List[AdvancedFinding] = []
        complexity = self._cyclomatic_complexity(tree)
        if complexity >= 10:
            severity = "HIGH"
        elif complexity >= 6:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        findings.append(
            AdvancedFinding(
                severity=severity,
                category="complexity",
                description="Cyclomatic complexity assessment.",
                file_path=str(path),
                metadata={"cyclomatic_complexity": complexity},
            )
        )
        return findings

    def _cyclomatic_complexity(self, tree: ast.AST) -> int:
        complexity = 1

        class ComplexityVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.score = 0

            VISIT_NODES = (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.With,
                ast.AsyncWith,
                ast.Try,
                ast.BoolOp,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            )

            def generic_visit(self, node: ast.AST) -> None:  # type: ignore[override]
                if isinstance(node, self.VISIT_NODES):
                    self.score += 1
                super().generic_visit(node)

        visitor = ComplexityVisitor()
        visitor.visit(tree)
        complexity += visitor.score
        return complexity


__all__ = ["AdvancedDetectionEngine", "AdvancedFinding"]
