"""Regression tests for the child_process command-injection discriminator.

Lesson source: mcp-huntr bug-bounty sweep, archetype #4 (shell-string exec vs
argv) — docker-mcp-server used `startsWith('docker ')` as a non-guard before
building a shell command string. The mechanical discriminator: exec()/
execSync() always invoke a shell, so any dynamic command string is a sink;
spawn()/execFile()/spawnSync()/execFileSync() pass argv straight to the OS
and are safe UNLESS the caller opts back into shell parsing with
`shell: true`.

Both copies of the analyzer (the pre-refactor `src/multi_language_analyzer.py`
and the namespaced `src/sentinel/analyzers/multi_language.py`) carry this
logic independently — same pattern as the CVE-style FP fix in commit
60bfbd1 — so both are exercised here to keep them from drifting apart again.
"""

import pytest

from src.multi_language_analyzer import TypeScriptAnalyzer as LegacyTSAnalyzer
from src.sentinel.analyzers.multi_language import TypeScriptAnalyzer as NamespacedTSAnalyzer

ANALYZERS = pytest.mark.parametrize(
    "analyzer_cls", [LegacyTSAnalyzer, NamespacedTSAnalyzer], ids=["legacy", "namespaced"]
)


@ANALYZERS
class TestExecIsAlwaysASink:
    def test_exec_with_template_literal_flagged(self, analyzer_cls):
        content = "child_process.exec(`docker exec ${containerId} ls`);"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert any(f["rule_id"] == "node-command-injection" for f in findings)

    def test_exec_with_string_concatenation_flagged(self, analyzer_cls):
        # No template literal at all -- the false negative the old regex missed.
        content = "exec('docker exec ' + containerId + ' ls');"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert any(f["rule_id"] == "node-command-injection" for f in findings)

    def test_exec_sync_flagged(self, analyzer_cls):
        content = "const out = execSync(`ls ${dir}`);"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert any(f["rule_id"] == "node-command-injection" for f in findings)

    def test_exec_with_static_command_not_flagged(self, analyzer_cls):
        content = "exec('docker ps -a');"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert not any(f["rule_id"] == "node-command-injection" for f in findings)


@ANALYZERS
class TestSpawnArgvIsSafeByDefault:
    def test_spawn_with_argv_array_not_flagged(self, analyzer_cls):
        # Textbook-safe usage: dynamic value lives in an argv array element,
        # never touches a shell. The old rule false-flagged this.
        content = "spawn('docker', ['exec', `${containerId}`, 'ls']);"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert not any(f["rule_id"].startswith("node-command-injection") for f in findings)

    def test_exec_file_with_argv_array_not_flagged(self, analyzer_cls):
        content = "execFile('docker', ['exec', containerId, 'ls']);"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert not any(f["rule_id"].startswith("node-command-injection") for f in findings)

    def test_spawn_with_shell_true_flagged(self, analyzer_cls):
        # shell: true re-enables shell parsing -- spawn becomes exec-equivalent.
        content = "spawn('docker exec ' + containerId, { shell: true });"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert any(f["rule_id"] == "node-command-injection-shell-option" for f in findings)

    def test_exec_file_with_shell_true_flagged(self, analyzer_cls):
        content = "execFile(cmd, args, { shell: true });"
        findings = analyzer_cls()._analyze_node_security(content, "server.js")
        assert any(f["rule_id"] == "node-command-injection-shell-option" for f in findings)
