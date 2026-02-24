"""Scanner plugin registry for managing adapters and analyzers."""

from pathlib import Path
from typing import Dict, List, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time

from .types import VulnerabilityFinding
from ..adapters.base import BaseAdapter
from ..analyzers.base import BaseAnalyzer

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Registry for scanner plugins.

    Manages adapter and analyzer registration, discovery, and parallel execution.
    All external tools are optional — if not installed, they're skipped gracefully.
    """

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseAdapter] = {}
        self._analyzers: Dict[str, BaseAnalyzer] = {}

    def register_adapter(self, adapter: BaseAdapter) -> None:
        """Register an external tool adapter."""
        self._adapters[adapter.name] = adapter
        logger.debug(f"Registered adapter: {adapter}")

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Register a built-in code analyzer."""
        self._analyzers[analyzer.name] = analyzer
        logger.debug(f"Registered analyzer: {analyzer}")

    def get_adapter(self, name: str) -> Optional[BaseAdapter]:
        return self._adapters.get(name)

    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        return self._analyzers.get(name)

    @property
    def adapters(self) -> Dict[str, BaseAdapter]:
        return dict(self._adapters)

    @property
    def analyzers(self) -> Dict[str, BaseAnalyzer]:
        return dict(self._analyzers)

    def discover_available(self) -> Dict[str, bool]:
        """Check which external tools are installed and available."""
        status: Dict[str, bool] = {}
        for name, adapter in self._adapters.items():
            status[name] = adapter.is_available()
        for name, analyzer in self._analyzers.items():
            status[name] = True  # built-in analyzers are always available
        return status

    def run_all(
        self,
        target: Path,
        parallel: int = 4,
        tools: Optional[List[str]] = None,
    ) -> List[VulnerabilityFinding]:
        """Run all registered scanners and collect findings.

        Args:
            target: Path to scan.
            parallel: Max concurrent workers.
            tools: If specified, only run these tools. Otherwise run all.

        Returns:
            Combined list of findings from all scanners.
        """
        all_findings: List[VulnerabilityFinding] = []
        tasks = []

        # Collect enabled scanners
        for name, adapter in self._adapters.items():
            if tools and name not in tools:
                continue
            tasks.append(("adapter", name, adapter))

        for name, analyzer in self._analyzers.items():
            if tools and name not in tools:
                continue
            tasks.append(("analyzer", name, analyzer))

        if not tasks:
            logger.warning("No scanners to run")
            return []

        logger.info(f"Running {len(tasks)} scanner(s) with {parallel} workers")
        start = time.time()

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {}
            for kind, name, scanner in tasks:
                if kind == "adapter":
                    futures[executor.submit(scanner.check_or_skip, target)] = name
                else:
                    futures[executor.submit(scanner.check_or_skip, target)] = name

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
        """Report availability and version info for all registered tools.

        Returns dict like:
            {"semgrep": {"available": True, "command": "semgrep"}, ...}
        """
        report: Dict[str, Dict[str, str]] = {}
        for name, adapter in self._adapters.items():
            report[name] = {
                "type": "adapter",
                "command": adapter.tool_command,
                "available": str(adapter.is_available()),
                "enabled": str(adapter.enabled),
            }
        for name, analyzer in self._analyzers.items():
            report[name] = {
                "type": "analyzer",
                "command": "built-in",
                "available": "True",
                "enabled": str(analyzer.enabled),
            }
        return report
