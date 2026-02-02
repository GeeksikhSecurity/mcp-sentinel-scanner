import json

import pytest

from scripts.sentinel_cli import main as cli_main


@pytest.mark.parametrize(
    "args",
    [
        ["tests", "--format", "json", "--no-colors"],
        ["tests", "--format", "markdown", "--no-colors"],
    ],
)
def test_cli_outputs(args, capsys):
    exit_code = cli_main(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out

    if "json" in args:
        data = json.loads(captured.out)
        assert data["scan_summary"]["files_scanned"] >= 1
    else:
        assert "## Summary" in captured.out
        assert "Findings" in captured.out


def test_cli_respects_output_file(tmp_path, capsys):
    output = tmp_path / "report.json"
    exit_code = cli_main(["tests", "--format", "json", "--output", str(output)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert f"Report written to {output}" in captured.out
    data = json.loads(output.read_text())
    assert data["scan_summary"]["vulnerabilities_found"] >= 1


def test_cli_exclude_patterns(tmp_path, capsys):
    ignored = tmp_path / "ignored.py"
    ignored.write_text("eval('oops')")  # nosec - test code

    kept = tmp_path / "kept.py"
    kept.write_text("print('ok')\n")

    exit_code = cli_main([str(tmp_path), "--format", "json", "--exclude", "ignored.py", "--no-colors"])
    captured = capsys.readouterr()

    assert exit_code == 0
    data = json.loads(captured.out)
    categories = {f["category"] for f in data.get("findings", [])}
    assert "dangerous_function" not in categories
