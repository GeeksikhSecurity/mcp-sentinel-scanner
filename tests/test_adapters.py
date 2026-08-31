"""Tests for tool adapters."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.adapters import SemgrepAdapter, TruffleHogAdapter
from src.adapters.trufflehog_adapter import TruffleHogScanError


class TestTruffleHogAdapter:
    """Test TruffleHog adapter."""

    def test_disabled_adapter_returns_empty(self):
        """Test disabled adapter returns no findings."""
        adapter = TruffleHogAdapter({"enabled": False})
        result = adapter.run(Path("."))
        assert result == []

    @patch("subprocess.run")
    def test_successful_scan(self, mock_run):
        """Test successful TruffleHog scan."""
        mock_output = json.dumps(
            {
                "Verified": True,
                "DetectorName": "AWS",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config.py", "line": 5}}},
            }
        )

        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        adapter = TruffleHogAdapter()
        findings = adapter.run(Path("."))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "CRITICAL"
        assert finding.category == "hardcoded_secret"
        assert "AWS" in finding.description
        assert finding.file_path == "config.py"
        assert finding.line_number == 5

    @patch("subprocess.run")
    def test_unverified_secrets_ignored(self, mock_run):
        """Test unverified secrets are ignored."""
        mock_output = json.dumps(
            {"Verified": False, "DetectorName": "Generic", "Raw": "not-a-real-secret"}
        )

        mock_run.return_value = Mock(returncode=0, stdout=mock_output)

        adapter = TruffleHogAdapter()
        findings = adapter.run(Path("."))

        assert len(findings) == 0

    @patch("subprocess.run")
    def test_command_failure_raises_instead_of_masking_as_clean(self, mock_run):
        """A non-zero exit is a broken scan, not "0 verified secrets" — it
        must be surfaced, never silently swallowed as a clean result."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="panic: chunking error")

        adapter = TruffleHogAdapter()

        with pytest.raises(TruffleHogScanError):
            adapter.run(Path("."))

    @patch("subprocess.run")
    def test_timeout_raises_instead_of_masking_as_clean(self, mock_run):
        """A timeout is a broken scan, not "0 verified secrets"."""
        mock_run.side_effect = subprocess.TimeoutExpired("trufflehog", 300)

        adapter = TruffleHogAdapter()

        with pytest.raises(TruffleHogScanError):
            adapter.run(Path("."))


class TestSemgrepAdapter:
    """Test Semgrep adapter."""

    def test_disabled_adapter_returns_empty(self):
        """Test disabled adapter returns no findings."""
        adapter = SemgrepAdapter({"enabled": False})
        result = adapter.run(Path("."))
        assert result == []

    @patch("subprocess.run")
    def test_successful_scan(self, mock_run):
        """Test successful Semgrep scan."""
        mock_output = {
            "results": [
                {
                    "check_id": "javascript.lang.security.audit.sqli.node-postgres-sqli",
                    "path": "app.js",
                    "start": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection vulnerability",
                        "lines": "query = 'SELECT * FROM users WHERE id = ' + userId;",
                        "metadata": {"cwe": "89"},
                    },
                }
            ]
        }

        mock_run.return_value = Mock(returncode=1, stdout=json.dumps(mock_output))

        adapter = SemgrepAdapter()
        findings = adapter.run(Path("."))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "HIGH"
        assert finding.category == "sql_injection"
        assert "SQL injection" in finding.description
        assert finding.cwe_id == "CWE-89"

    @patch("subprocess.run")
    def test_no_findings(self, mock_run):
        """Test scan with no findings."""
        mock_output = {"results": []}
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(mock_output))

        adapter = SemgrepAdapter()
        findings = adapter.run(Path("."))

        assert len(findings) == 0

    def test_categorize_rule(self):
        """Test rule categorization."""
        adapter = SemgrepAdapter()

        assert adapter._categorize_rule("sql-injection-test") == "sql_injection"
        assert adapter._categorize_rule("xss-vulnerability") == "xss"
        assert adapter._categorize_rule("command-injection") == "command_injection"
        assert adapter._categorize_rule("crypto-weak-hash") == "weak_crypto"
        assert adapter._categorize_rule("unknown-rule") == "security_issue"
