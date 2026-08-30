"""TruffleHog adapter for secret detection."""

import json
import logging
import subprocess
from pathlib import Path
from typing import List, Optional

from ..mcp_sentinel_scanner import VulnerabilityFinding

logger = logging.getLogger(__name__)


class TruffleHogScanError(RuntimeError):
    """Raised when TruffleHog itself fails, as opposed to finding nothing."""


class TruffleHogAdapter:
    """Adapter for TruffleHog secret scanner."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    def run(self, target: Path) -> List[VulnerabilityFinding]:
        """Run TruffleHog on target path.

        Raises TruffleHogScanError if the scan itself fails, rather than
        returning an empty list — a tool crash or unexpected exit code must
        never be reported as "0 verified secrets found" in a secrets
        scanner. Callers that want a best-effort scan should catch this and
        surface it as a warning/failed-tool finding instead of silently
        treating it as a clean result.
        """
        if not self.enabled:
            return []

        try:
            cmd = ["trufflehog", "filesystem", str(target), "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired as e:
            raise TruffleHogScanError(f"TruffleHog timed out scanning {target}") from e
        except FileNotFoundError as e:
            raise TruffleHogScanError("TruffleHog binary not found on PATH") from e

        # `trufflehog filesystem --json` (without --fail) exits 0 whether or
        # not it found anything; a non-zero exit means the scan itself broke
        # (e.g. the "error chunking unit" failure in some 3.84+ builds) and
        # must be surfaced, not treated as a clean scan.
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            logger.error("TruffleHog exited %s on %s: %s", result.returncode, target, stderr)
            raise TruffleHogScanError(
                f"TruffleHog exited with code {result.returncode}: {stderr[:500]}"
            )

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
