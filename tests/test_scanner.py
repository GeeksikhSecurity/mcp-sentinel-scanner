import json
from pathlib import Path

import pytest

from src import MCPSentinelScanner


def test_scan_detects_expected_categories():
    scanner = MCPSentinelScanner()
    result = scanner.scan(Path("tests"))

    categories = {finding.category for finding in result.findings}
    assert "sql_injection" in categories
    assert "command_injection" in categories
    assert "hardcoded_secret" in categories
    assert "dangerous_function" in categories

    assert result.summary.files_scanned >= 1
    assert result.summary.vulnerabilities_found >= 1
    assert 0 <= result.summary.asr_score <= 1


def test_entropy_threshold_filters_low_entropy(tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text('password = "abc123abc123"\n')

    scanner = MCPSentinelScanner()
    result = scanner.scan(sample)

    secret_findings = [f for f in result.findings if f.category == "hardcoded_secret"]
    assert secret_findings == []


def test_ast_detects_dangerous_calls(tmp_path: Path):
    sample = tmp_path / "danger.py"
    # nosec: Creating intentionally vulnerable test code
    sample.write_text(
        """
import subprocess

def runner(cmd):
    eval(cmd)  # nosec - test code
    subprocess.call(cmd, shell=True)  # nosec - test code
"""
    )

    scanner = MCPSentinelScanner()
    result = scanner.scan(sample)

    categories = {finding.category for finding in result.findings}
    assert "dangerous_function" in categories
    severities = {finding.severity for finding in result.findings if finding.category == "dangerous_function"}
    assert "CRITICAL" in severities


def test_advanced_detection_identifies_semantic_issues():
    scanner = MCPSentinelScanner()
    result = scanner.scan(Path("tests") / "vulnerable_test.py")

    advanced_categories = {finding.category for finding in result.advanced_findings}
    assert "auth_bypass" in advanced_categories
    assert "crypto_misuse" in advanced_categories
    assert "complexity" in advanced_categories

    for finding in result.advanced_findings:
        assert finding.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert finding.file_path.endswith("vulnerable_test.py")


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_report_serialisers(output_format: str):
    scanner = MCPSentinelScanner()
    result = scanner.scan(Path("tests"))

    if output_format == "json":
        payload = scanner.to_json(result)
        data = json.loads(payload)
        assert "scan_summary" in data
        assert data["scan_summary"]["files_scanned"] >= 1
    else:
        markdown = scanner.to_markdown(result)
        assert "## Findings" in markdown
        assert "ASR Score" in markdown
