"""Regression tests: credential heuristics must not decide non-credential findings."""

from pathlib import Path

from src import MCPSentinelScanner
from src.filters.false_positive_filter import FalsePositiveFilter, apply_false_positive_filter


def _finding(vuln_type, snippet, path="app/service.py", context="finding"):
    return {
        "vulnerability_type": vuln_type,
        "code_snippet": snippet,
        "file_path": path,
        "context": context,
        "line_number": 1,
    }


def test_non_credential_findings_survive_credential_heuristics():
    # None of these snippets look like API keys; entropy/format checks must not drop them.
    findings = [
        _finding("sql_injection", "query = \"SELECT * FROM users WHERE id = '\" + uid"),
        _finding("command_injection", "subprocess.run(cmd, shell=True)"),
        _finding("dangerous_function", "return eval(expr)"),
        _finding("insecure_deserialization", "return pickle.loads(data)"),
    ]
    kept = apply_false_positive_filter(findings)
    assert {f["vulnerability_type"] for f in kept} == {
        "sql_injection",
        "command_injection",
        "dangerous_function",
        "insecure_deserialization",
    }


def test_the_word_test_in_a_snippet_does_not_suppress_a_non_credential_finding():
    finding = _finding("dangerous_function", "eval(cmd)  # nosec - test code")
    assert apply_false_positive_filter([finding]) == [finding]


def test_bare_relative_path_is_not_path_traversal_but_file_access_is():
    bare = _finding("path_traversal", "if '../' in line:")
    opened = _finding("path_traversal", 'open("../" + user_path)')
    assert apply_false_positive_filter([bare, opened]) == [opened]


def test_fixture_paths_are_suppressed_by_default_and_kept_with_scan_fixtures():
    finding = _finding("sql_injection", "cursor.execute(q + uid)", path="tests/fixtures/app.py")
    assert apply_false_positive_filter([finding]) == []
    assert apply_false_positive_filter([finding], scan_fixtures=True) == [finding]
    # Relative and absolute spellings of the same directory behave the same.
    assert FalsePositiveFilter().is_fixture_path("tests/x.py")
    assert FalsePositiveFilter().is_fixture_path("/repo/tests/x.py")
    assert not FalsePositiveFilter().is_fixture_path("src/contests/x.py")


def test_credential_findings_still_use_credential_heuristics():
    placeholder = _finding("hardcoded_secret", 'API_KEY = "YOUR_API_KEY_HERE"')
    assert apply_false_positive_filter([placeholder]) == []


def test_default_scan_reports_injection_in_ordinary_code(tmp_path: Path):
    sample = tmp_path / "handler.py"
    sample.write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n\n"
        "def lookup(uid):\n"
        "    return \"SELECT * FROM users WHERE id = '\" + uid\n"
    )
    categories = {f.category for f in MCPSentinelScanner().scan(sample).findings}
    assert "command_injection" in categories
    assert "sql_injection" in categories
