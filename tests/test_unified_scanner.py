"""Tests for unified scanner."""

from pathlib import Path
from unittest.mock import patch

from src.mcp_sentinel_scanner import VulnerabilityFinding
from src.unified_scanner import UnifiedScanner


class TestUnifiedScanner:
    """Test unified scanner orchestration."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = {
            "tools": {"truffleHog": {"enabled": True}, "semgrep": {"enabled": False}},
            "parallel_workers": 8,
        }

        scanner = UnifiedScanner(config)

        assert scanner.config == config
        assert scanner.trufflehog.enabled is True
        assert scanner.semgrep.enabled is False

    @patch("src.unified_scanner.UnifiedScanner._run_mcp_scanner")
    @patch("src.unified_scanner.UnifiedScanner._run_trufflehog")
    @patch("src.unified_scanner.UnifiedScanner._run_semgrep")
    @patch("src.unified_scanner.UnifiedScanner._run_react_analyzer")
    @patch("src.unified_scanner.UnifiedScanner._run_npm_analyzer")
    def test_parallel_execution(
        self, mock_npm, mock_react, mock_semgrep, mock_trufflehog, mock_mcp
    ):
        """Test parallel execution of all scanners."""
        # Mock return values
        mock_mcp.return_value = [self._create_test_finding("mcp")]
        mock_trufflehog.return_value = [self._create_test_finding("trufflehog")]
        mock_semgrep.return_value = [self._create_test_finding("semgrep")]
        mock_react.return_value = [self._create_test_finding("react")]
        mock_npm.return_value = [self._create_test_finding("npm")]

        scanner = UnifiedScanner()
        result = scanner.scan(Path("."))

        # All scanners should be called
        mock_mcp.assert_called_once()
        mock_trufflehog.assert_called_once()
        mock_semgrep.assert_called_once()
        mock_react.assert_called_once()
        mock_npm.assert_called_once()

        # Should have findings from all scanners (after FP reduction)
        assert len(result.findings) > 0
        assert result.summary.vulnerabilities_found > 0

    def test_error_handling(self):
        """Test error handling when scanners fail."""
        scanner = UnifiedScanner()

        # Mock failing scanners
        with patch.object(scanner, "_run_mcp_scanner", side_effect=Exception("MCP failed")):
            with patch.object(scanner, "_run_trufflehog", return_value=[]):
                result = scanner.scan(Path("."))

                # Should not crash and return valid result
                assert isinstance(result.summary.files_scanned, int)
                assert isinstance(result.summary.scan_time, float)

    @patch("src.unified_scanner.UnifiedScanner._run_mcp_scanner")
    def test_false_positive_reduction(self, mock_mcp):
        """Test false positive reduction pipeline."""
        # Create test findings including likely false positives
        findings = [
            VulnerabilityFinding(
                severity="HIGH",
                category="hardcoded_secret",
                description="Test secret",
                file_path="component.test.js",
                line_number=1,
                code_snippet="const MOCK_SECRET = 'test';",
                recommendation="Test",
            ),
            VulnerabilityFinding(
                severity="CRITICAL",
                category="hardcoded_secret",
                description="Real secret",
                file_path="src/config.js",
                line_number=1,
                code_snippet="const API_KEY = 'real-secret';",
                recommendation="Fix",
            ),
        ]

        mock_mcp.return_value = findings

        scanner = UnifiedScanner()
        result = scanner.scan(Path("."))

        # Should filter out test file finding
        assert len(result.findings) < len(findings)
        assert all("test.js" not in f.file_path for f in result.findings)

    def test_summary_calculation(self):
        """Test scan summary calculation."""
        scanner = UnifiedScanner()

        findings = [
            self._create_test_finding("test1", severity="CRITICAL"),
            self._create_test_finding("test2", severity="HIGH"),
            self._create_test_finding("test3", severity="MEDIUM"),
        ]

        summary = scanner._create_summary(Path("."), findings, 1.5)

        assert summary.vulnerabilities_found == 3
        assert summary.scan_time == 1.5
        assert summary.severity_distribution["CRITICAL"] == 1
        assert summary.severity_distribution["HIGH"] == 1
        assert summary.severity_distribution["MEDIUM"] == 1
        assert 0 <= summary.asr_score <= 1

    def test_output_delegation(self):
        """Test output method delegation to MCP scanner."""
        scanner = UnifiedScanner()

        findings = [self._create_test_finding("test")]
        summary = scanner._create_summary(Path("."), findings, 1.0)

        from src.mcp_sentinel_scanner import ScanResult

        result = ScanResult(summary=summary, findings=findings, advanced_findings=[])

        # Test JSON output
        json_output = scanner.to_json(result)
        assert "scan_summary" in json_output

        # Test Markdown output
        md_output = scanner.to_markdown(result)
        assert "# MCP Sentinel Scanner Report" in md_output

    def test_config_integration(self):
        """Test configuration integration."""
        config = {
            "tools": {
                "truffleHog": {"enabled": False},
                "semgrep": {"enabled": True, "rules": ["security"]},
            },
            "falsePositives": {"mlModel": {"enabled": False}},
        }

        scanner = UnifiedScanner(config)

        assert not scanner.trufflehog.enabled
        assert scanner.semgrep.enabled
        assert scanner.semgrep.rules == ["security"]

    def _create_test_finding(self, source: str, severity: str = "HIGH") -> VulnerabilityFinding:
        """Create a test finding."""
        return VulnerabilityFinding(
            severity=severity,
            category="test_category",
            description=f"Test finding from {source}",
            file_path="test.py",
            line_number=1,
            code_snippet="test code",
            recommendation="Fix it",
        )
