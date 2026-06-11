"""Scanner plugin registry for managing built-in analyzers.

External-tool adapters (semgrep/trufflehog/codeql) were removed (issue #8 — in
external-corpus testing they silently contributed nothing, returning [] on
timeout/error with no warning). Run those tools dedicated; this registry now
manages only the precise built-in analyzers.
"""

from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time

from .types import VulnerabilityFinding
from ..analyzers.base import BaseAnalyzer

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Registry for built-in analyzer plugins.

    Manages analyzer registration, discovery, and parallel execution.
    """

    def __init__(self) -> None:
        self._analyzers: Dict[str, BaseAnalyzer] = {}

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Register a built-in code analyzer."""
        self._analyzers[analyzer.name] = analyzer
        logger.debug(f"Registered analyzer: {analyzer}")

    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        return self._analyzers.get(name)

    @property
    def analyzers(self) -> Dict[str, BaseAnalyzer]:
        return dict(self._analyzers)

    def discover_available(self) -> Dict[str, bool]:
        """Built-in analyzers are always available."""
        return {name: True for name in self._analyzers}

    def run_all(
        self,
        target: Path,
        parallel: int = 4,
        tools: Optional[List[str]] = None,
    ) -> List[VulnerabilityFinding]:
        """Run all registered analyzers and collect findings.

        Args:
            target: Path to scan.
            parallel: Max concurrent workers.
            tools: If specified, only run these analyzers. Otherwise run all.
        """
        tasks = [
            (name, analyzer)
            for name, analyzer in self._analyzers.items()
            if not tools or name in tools
        ]

        if not tasks:
            logger.warning("No scanners to run")
            return []

        logger.info(f"Running {len(tasks)} scanner(s) with {parallel} workers")
        start = time.time()
        all_findings: List[VulnerabilityFinding] = []

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {
                executor.submit(scanner.check_or_skip, target): name
                for name, scanner in tasks
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    findings = future.result()
                    logger.info(f"{name}: {len(findings)} finding(s)")
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"{name}: failed: {e}")

        elapsed = time.time() - start
        logger.info(
            f"Scan complete: {len(all_findings)} total findings "
            f"from {len(tasks)} scanners in {elapsed:.1f}s"
        )
        return all_findings

    def doctor(self) -> Dict[str, Dict[str, str]]:
        """Report availability for all registered analyzers."""
        report: Dict[str, Dict[str, str]] = {}
        for name, analyzer in self._analyzers.items():
            report[name] = {
                "type": "analyzer",
                "command": "built-in",
                "available": "True",
                "enabled": str(analyzer.enabled),
            }
        return report
