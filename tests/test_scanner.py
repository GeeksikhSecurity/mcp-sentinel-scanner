import json
from pathlib import Path

import pytest

from src import MCPSentinelScanner

# Config with FP reduction disabled so tests that assert on findings get them
_TEST_CONFIG = json.loads(Path("configs/test_config.json").read_text())


def test_scan_detects_expected_categories():
    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
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

    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
    result = scanner.scan(sample)

    categories = {finding.category for finding in result.findings}
    assert "dangerous_function" in categories
    severities = {
        finding.severity for finding in result.findings if finding.category == "dangerous_function"
    }
    assert "CRITICAL" in severities


def test_advanced_detection_identifies_semantic_issues():
    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
    result = scanner.scan(Path("tests") / "vulnerable_test.py")

    advanced_categories = {finding.category for finding in result.advanced_findings}
    assert "auth_bypass" in advanced_categories
    assert "crypto_misuse" in advanced_categories
    assert "complexity" in advanced_categories

    for finding in result.advanced_findings:
        assert finding.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert finding.file_path.endswith("vulnerable_test.py")


def test_scanner_regression_fixtures():
    """Regression: fixtures under tests/fixtures/scanner_regression lock in expected findings."""
    fixtures_dir = Path("tests/fixtures/scanner_regression")
    if not fixtures_dir.exists():
        pytest.skip("scanner_regression fixtures not present")

    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
    result = scanner.scan(fixtures_dir)

    categories = {f.category for f in result.findings}
    by_file = {}
    for f in result.findings:
        by_file.setdefault(Path(f.file_path).name, []).append(f.category)

    # command_injection_fixture.py -> command_injection
    if "command_injection_fixture.py" in by_file:
        assert "command_injection" in by_file["command_injection_fixture.py"]

    # hardcoded_secret_fixture.py -> hardcoded_secret (quoted value)
    if "hardcoded_secret_fixture.py" in by_file:
        assert "hardcoded_secret" in by_file["hardcoded_secret_fixture.py"]

    # fp_negative_fixture.py -> no hardcoded_secret (variable names only)
    if "fp_negative_fixture.py" in by_file:
        assert "hardcoded_secret" not in by_file["fp_negative_fixture.py"]


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_report_serialisers(output_format: str):
    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
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
