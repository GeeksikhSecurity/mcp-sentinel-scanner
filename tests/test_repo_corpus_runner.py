import json
from pathlib import Path

from scripts.repo_corpus_runner import load_manifest, run_corpus


def test_repo_corpus_runner_local_paths(tmp_path: Path):
    # Create a tiny local repo directory to scan
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("print('hi')\n")

    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "repos": [
                    {
                        "id": "local-repo",
                        "tier": "smoke",
                        "local_path": str(repo_dir),
                        "unified": False,
                        "timeout_sec": 60,
                        "exclude": [],
                    }
                ],
            }
        )
    )

    entries = load_manifest(manifest)
    assert len(entries) == 1
    assert entries[0].id == "local-repo"

    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"

    result = run_corpus(
        manifest_path=manifest,
        tier="smoke",
        workspace_root=tmp_path,
        cache_dir=cache_dir,
        output_dir=out_dir,
        base_config={"exclude": []},
    )

    assert result["count"] == 1
    assert (out_dir / "local-repo" / "summary.json").exists()
    assert (out_dir / "corpus_summary.json").exists()


