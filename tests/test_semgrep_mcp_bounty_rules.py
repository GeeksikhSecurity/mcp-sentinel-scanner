"""Regression tests for the MCP bug-bounty-lesson Semgrep rules in .semgrep.yml.

Source: mcp-huntr sweep, MCP-SCAN-LESSONS.md (archetypes #4, #5, #8, #9).
The rules were proposed externally and validated against true/false-positive
fixtures before being accepted — per this repo's own rule, an external
finding/rule is a hypothesis until the cited pattern is confirmed against
real code, not a verdict. Two of the four originally-proposed patterns did
not actually match anything (dead patterns): `exec("...", ...)` as a
pattern-not is a no-op since a bare "..." string pattern only matches the
literal three-character string, and `$URL.startsWith("https://...")` only
matches that literal string too, not "any string starting with https://".
Both are fixed in .semgrep.yml; this test pins the corrected behavior so a
future edit can't silently reintroduce a non-functional pattern.

`semgrep --test` itself crashes on this repo's config/target path shape
(semgrep 1.172.0, IndexError in relatively_eq) -- so this harness drives
`semgrep scan --json` directly and reads the same `# ruleid:` / `# ok:`
markers a normal semgrep test fixture would use, rather than depending on
the broken --test command.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SEMGREP_CONFIG = REPO_ROOT / ".semgrep.yml"
FIXTURES_DIR = Path(__file__).parent / "semgrep" / "fixtures"

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep is not installed"
)


def _expected_lines(fixture_path: Path, rule_id: str) -> tuple[set[int], set[int]]:
    """Read `# ruleid: <id>` / `// ruleid: <id>` markers from a fixture file.

    Each marker annotates the line *below* it. Returns (should_match_lines,
    should_not_match_lines) for the given rule_id.
    """
    should_match: set[int] = set()
    should_not_match: set[int] = set()
    lines = fixture_path.read_text().splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.endswith(f"ruleid: {rule_id}"):
            should_match.add(i + 2)  # 1-indexed, marker annotates next line
        elif stripped.endswith(f"ok: {rule_id}"):
            should_not_match.add(i + 2)
    return should_match, should_not_match


def _run_semgrep(fixture_path: Path) -> set[tuple[str, int]]:
    result = subprocess.run(
        [
            "semgrep",
            "scan",
            "--config",
            str(SEMGREP_CONFIG),
            "--json",
            "--quiet",
            str(fixture_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(result.stdout)
    return {(r["check_id"], r["start"]["line"]) for r in payload["results"]}


CASES = [
    ("mcp-nodejs-shell-string-interpolation", "mcp_nodejs_shell_string_interpolation.js"),
    ("mcp-python-shell-true-interpolation", "mcp_python_shell_true_interpolation.py"),
    ("mcp-lexical-path-containment-bypass", "mcp_lexical_path_containment_bypass.js"),
    ("mcp-insecure-url-allowlist", "mcp_insecure_url_allowlist.js"),
]


@pytest.mark.parametrize("rule_id,fixture_name", CASES)
def test_rule_matches_expected_lines_only(rule_id, fixture_name):
    fixture_path = FIXTURES_DIR / fixture_name
    should_match, should_not_match = _expected_lines(fixture_path, rule_id)
    assert should_match, f"fixture {fixture_name} has no ruleid: {rule_id} markers"

    matched_lines = {line for (cid, line) in _run_semgrep(fixture_path) if cid == rule_id}

    missing = should_match - matched_lines
    unexpected = matched_lines & should_not_match

    assert not missing, f"{rule_id}: expected match on lines {missing}, got none (false negative)"
    assert not unexpected, f"{rule_id}: matched lines {unexpected} marked safe (false positive)"
