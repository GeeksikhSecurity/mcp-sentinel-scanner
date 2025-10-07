"""Tests for tool adapters."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.adapters import SemgrepAdapter, TruffleHogAdapter


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
    def test_command_failure_returns_empty(self, mock_run):
        """Test command failure returns empty list."""
        mock_run.return_value = Mock(returncode=1, stdout="")

        adapter = TruffleHogAdapter()
        findings = adapter.run(Path("."))

        assert findings == []

    @patch("subprocess.run")
    def test_timeout_returns_empty(self, mock_run):
        """Test timeout returns empty list."""
        mock_run.side_effect = subprocess.TimeoutExpired("trufflehog", 300)

        adapter = TruffleHogAdapter()
        findings = adapter.run(Path("."))

        assert findings == []


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
