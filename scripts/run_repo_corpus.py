#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.repo_corpus_runner import run_corpus


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repo-corpus scans for regression testing.")
    parser.add_argument(
        "--manifest",
        default=str(Path("configs") / "repo_corpus.json"),
        help="Path to repo corpus manifest JSON",
    )
    parser.add_argument(
        "--tier",
        choices=["smoke", "full", "all"],
        default="smoke",
        help="Which tier to run from the manifest",
    )
    parser.add_argument(
        "--cache-dir",
        default=str(Path(".cache") / "repo_corpus"),
        help="Directory to cache cloned repos",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path("reports") / "repo_corpus"),
        help="Directory to write scan outputs",
    )
    parser.add_argument(
        "--base-config",
        default=str(Path("configs") / "ci_config.json"),
        help="Base scanner config (JSON)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="Only run specific repo ids (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    manifest_path = Path(args.manifest).resolve()
    base_config_path = Path(args.base_config).resolve()
    workspace_root = Path(".").resolve()

    base_config = json.loads(base_config_path.read_text(encoding="utf-8"))

    run_corpus(
        manifest_path=manifest_path,
        tier=args.tier,
        workspace_root=workspace_root,
        cache_dir=Path(args.cache_dir),
        output_dir=Path(args.output_dir),
        base_config=base_config,
        only_ids=args.only or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


