"""Semgrep adapter for pattern-based detection."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..core.types import VulnerabilityFinding
from .base import BaseAdapter


class SemgrepAdapter(BaseAdapter):
    """Adapter for Semgrep pattern scanner."""

    name = "semgrep"
    tool_command = "semgrep"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.rules = self.config.get("rules", ["auto"])

    def run(self, target: Path) -> List[VulnerabilityFinding]:
        """Run Semgrep on target path."""
        if not self.enabled:
            return []

        try:
            cmd = ["semgrep", "--json", "--config=auto", str(target)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode not in [0, 1]:  # 1 = findings found
                return []

            data = json.loads(result.stdout)
            findings = []

            for result_item in data.get("results", []):
                finding = self._convert_finding(result_item)
                if finding:
                    findings.append(finding)

            return findings
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return []

    def _convert_finding(self, data: dict) -> Optional[VulnerabilityFinding]:
        """Convert Semgrep finding to VulnerabilityFinding."""
        severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

        check_id = data.get("check_id", "")
        severity = severity_map.get(data.get("extra", {}).get("severity", "INFO"), "LOW")

        return VulnerabilityFinding(
            severity=severity,
            category=self._categorize_rule(check_id),
            description=data.get("extra", {}).get("message", "Semgrep finding"),
            file_path=data.get("path", ""),
            line_number=data.get("start", {}).get("line", 1),
            code_snippet=data.get("extra", {}).get("lines", ""),
            recommendation="Review and fix the identified issue",
            cwe_id=self._extract_cwe(data),
            confidence=0.8,
        )

    def _categorize_rule(self, check_id: str) -> str:
        """Categorize Semgrep rule by check ID."""
        if "sql" in check_id.lower():
            return "sql_injection"
        elif "xss" in check_id.lower():
            return "xss"
        elif "command" in check_id.lower():
            return "command_injection"
        elif "crypto" in check_id.lower():
            return "weak_crypto"
        else:
            return "security_issue"

    def _extract_cwe(self, data: dict) -> Optional[str]:
        """Extract CWE ID from Semgrep metadata."""
        metadata = data.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe")
        return f"CWE-{cwe}" if cwe else None
