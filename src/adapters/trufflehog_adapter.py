"""TruffleHog adapter for secret detection."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..mcp_sentinel_scanner import VulnerabilityFinding


class TruffleHogAdapter:
    """Adapter for TruffleHog secret scanner."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    def run(self, target: Path) -> List[VulnerabilityFinding]:
        """Run TruffleHog on target path."""
        if not self.enabled:
            return []

        try:
            cmd = ["trufflehog", "filesystem", str(target), "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                return []

            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = self._convert_finding(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue

            return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _convert_finding(self, data: dict) -> Optional[VulnerabilityFinding]:
        """Convert TruffleHog finding to VulnerabilityFinding."""
        if not data.get("Verified", False):
            return None

        source_metadata = data.get("SourceMetadata", {})
        file_path = source_metadata.get("Data", {}).get("Filesystem", {}).get("file", "")
        line_number = source_metadata.get("Data", {}).get("Filesystem", {}).get("line", 1)

        return VulnerabilityFinding(
            severity="CRITICAL",
            category="hardcoded_secret",
            description=f"Verified secret detected: {data.get('DetectorName', 'unknown')}",
            file_path=file_path,
            line_number=line_number,
            code_snippet=data.get("Raw", "")[:100],
            recommendation="Remove hardcoded secret and use environment variables",
            cwe_id="CWE-798",
            confidence=0.95,
        )
