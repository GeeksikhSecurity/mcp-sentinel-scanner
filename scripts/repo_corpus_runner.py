from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from src import MCPSentinelScanner
from src.unified_scanner import UnifiedScanner


@dataclass(frozen=True)
class RepoEntry:
    id: str
    tier: str
    unified: bool
    timeout_sec: int
    exclude: List[str]
    url: Optional[str] = None
    ref: Optional[str] = None
    local_path: Optional[str] = None


def load_manifest(manifest_path: Path) -> List[RepoEntry]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    repos = payload.get("repos", [])
    entries: List[RepoEntry] = []
    for raw in repos:
        entries.append(
            RepoEntry(
                id=str(raw["id"]),
                tier=str(raw.get("tier", "full")),
                unified=bool(raw.get("unified", True)),
                timeout_sec=int(raw.get("timeout_sec", 600)),
                exclude=list(raw.get("exclude", [])),
                url=raw.get("url"),
                ref=raw.get("ref"),
                local_path=raw.get("local_path"),
            )
        )
    return entries


def _run_git(args: List[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def ensure_repo_checked_out(
    entry: RepoEntry, *, workspace_root: Path, cache_dir: Path
) -> Path:
    """
    Return a local path containing the repo contents.

    - If entry.local_path is provided, returns that directory (resolved relative to workspace_root).
    - If entry.url is provided, clones/fetches into cache_dir/{id}/ and checks out entry.ref.
    """
    if entry.local_path:
        p = Path(entry.local_path)
        if not p.is_absolute():
            p = (workspace_root / p).resolve()
        if not p.exists():
            raise FileNotFoundError(f"local_path not found for {entry.id}: {p}")
        return p

    if not entry.url or not entry.ref:
        raise ValueError(f"repo entry {entry.id} must include either local_path or url+ref")

    repo_dir = (cache_dir / entry.id).resolve()
    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    if not (repo_dir / ".git").exists():
        _run_git(["clone", "--no-checkout", entry.url, str(repo_dir)], cwd=repo_dir.parent)

    # Fetch requested ref (branch, tag, or sha). Depth 1 works for branches/tags; sha may require
    # server support. If it fails, fall back to a full fetch of that ref.
    try:
        _run_git(["fetch", "--depth", "1", "origin", entry.ref], cwd=repo_dir)
    except subprocess.CalledProcessError:
        _run_git(["fetch", "origin", entry.ref], cwd=repo_dir)

    _run_git(["checkout", "--force", "FETCH_HEAD"], cwd=repo_dir)
    return repo_dir


def run_scan(
    repo_path: Path,
    *,
    unified: bool,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    scanner = UnifiedScanner(config=config) if unified else MCPSentinelScanner(config=config)
    result = scanner.scan(repo_path)
    return {
        "summary": {
            "files_scanned": result.summary.files_scanned,
            "total_lines": result.summary.total_lines,
            "scan_time": result.summary.scan_time,
            "vulnerabilities_found": result.summary.vulnerabilities_found,
            "asr_score": result.summary.asr_score,
            "severity_distribution": result.summary.severity_distribution,
        },
        "json": scanner.to_json(result),
        "sarif": scanner.to_sarif(result, str(repo_path)),
    }


def run_corpus(
    *,
    manifest_path: Path,
    tier: str,
    workspace_root: Path,
    cache_dir: Path,
    output_dir: Path,
    base_config: Dict[str, Any],
    only_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    start = time.perf_counter()
    entries = load_manifest(manifest_path)

    only_set = set(only_ids) if only_ids else None
    selected = [
        e
        for e in entries
        if (e.tier == tier or tier == "all") and (only_set is None or e.id in only_set)
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    for entry in selected:
        repo_start = time.perf_counter()

        repo_path = ensure_repo_checked_out(entry, workspace_root=workspace_root, cache_dir=cache_dir)

        config = dict(base_config)
        config["exclude"] = list(dict.fromkeys(list(config.get("exclude", []) or []) + entry.exclude))

        scan_payload = run_scan(repo_path, unified=entry.unified, config=config)
        duration = time.perf_counter() - repo_start

        repo_out = output_dir / entry.id
        repo_out.mkdir(parents=True, exist_ok=True)

        (repo_out / "summary.json").write_text(
            json.dumps(
                {
                    "id": entry.id,
                    "tier": entry.tier,
                    "repo_path": str(repo_path),
                    "unified": entry.unified,
                    "duration_sec": duration,
                    "summary": scan_payload["summary"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (repo_out / "results.json").write_text(scan_payload["json"], encoding="utf-8")
        (repo_out / "results.sarif").write_text(scan_payload["sarif"], encoding="utf-8")

        results.append(
            {
                "id": entry.id,
                "tier": entry.tier,
                "repo_path": str(repo_path),
                "unified": entry.unified,
                "duration_sec": duration,
                "summary": scan_payload["summary"],
            }
        )

    final = {
        "manifest": str(manifest_path),
        "tier": tier,
        "count": len(results),
        "duration_sec": time.perf_counter() - start,
        "results": results,
    }
    (output_dir / "corpus_summary.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    return final


