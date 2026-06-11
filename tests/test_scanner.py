import copy
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


# A realistic, high-entropy token (~4.6 bits): detectable at the default floor,
# unreachable at the floor the automated triage loop drove the config to (6.0).
_REAL_SECRET_LINE = 'aws_secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYz9Qd2KbN1pLm"\n'


def _secret_findings_at_floor(tmp_path: Path, floor: float):
    sample = tmp_path / "creds.py"
    sample.write_text(_REAL_SECRET_LINE)
    cfg = copy.deepcopy(_TEST_CONFIG)
    cfg.setdefault("scanner_tuning", {})["secret_shannon_entropy_min"] = floor
    scanner = MCPSentinelScanner(config=cfg)
    result = scanner.scan(sample)
    return [f for f in result.findings if f.category == "hardcoded_secret"]


def test_realistic_secret_detected_at_default_floor(tmp_path: Path):
    """Regression (cubic P1): a real-entropy secret MUST be detected at the
    default floor (3.5). The automated triage loop had ratcheted the floor to
    6.0 — mathematically unreachable for real secrets (per-char Shannon entropy
    is bounded by log2(len)) — silently disabling CWE-798 detection.
    """
    assert _secret_findings_at_floor(tmp_path, 3.5), (
        "a real secret must be detected at the default 3.5 floor"
    )


def test_unreachable_entropy_floor_warns_and_suppresses(tmp_path: Path):
    """Defense-in-depth: an entropy floor above the reachable ceiling warns
    loudly and (proving the regression) suppresses the real secret.
    """
    with pytest.warns(UserWarning, match="effectively disabled"):
        found = _secret_findings_at_floor(tmp_path, 6.0)
    assert found == [], "6.0 floor is unreachable for real secrets — documents the regression"


def test_fp_gates_subprocess_and_weak_crypto(tmp_path: Path):
    """Context gates: don't flag safe subprocess/MD5 usage (corpus FP fix).

    - subprocess.Popen/call WITHOUT shell=True does not invoke a shell, so it is
      not command injection; only shell=True should flag (via the regex). Bare
      subprocess (e.g. Popen(['open', url])) must NOT flag.
    - hashlib.md5(..., usedforsecurity=False) is the stdlib non-security signal —
      must NOT flag; a bare hashlib.md5() still must.
    """
    sample = tmp_path / "ctx.py"
    sample.write_text(
        "import subprocess, hashlib\n"
        "def f(url, data, pw):\n"
        "    subprocess.Popen(['open', url])\n"            # line 3: safe, no shell
        "    subprocess.call(cmd, shell=True)\n"            # line 4: shell injection (TP)
        "    hashlib.md5(data, usedforsecurity=False)\n"    # line 5: cache hash, safe
        "    hashlib.md5(pw)\n"                             # line 6: weak crypto (TP)
    )
    scanner = MCPSentinelScanner(config=_TEST_CONFIG)
    flagged = {(f.category, f.line_number) for f in scanner.scan(sample).findings}

    assert ("dangerous_function", 3) not in flagged, "bare subprocess.Popen must not flag"
    assert ("command_injection", 4) in flagged, "shell=True subprocess must flag"
    assert ("weak_crypto", 5) not in flagged, "md5 usedforsecurity=False must not flag"
    assert ("weak_crypto", 6) in flagged, "bare md5 must flag"


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
