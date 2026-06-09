#!/usr/bin/env python3
"""
Phase 1–N triage optimization for MCP Sentinel Scanner.

Reads baseline_efficiency.json, mutates configs/security_rules.json per hypothesis,
runs scripts.benchmark.run_corpus_baseline, logs to optimization_log.jsonl, and
git-commits only when efficiency and CRITICAL gates pass.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

WORKSPACE = Path(__file__).resolve().parent.parent
BASELINE_PATH = WORKSPACE / "baseline_efficiency.json"
RULES_PATH = WORKSPACE / "configs" / "security_rules.json"
LOG_PATH = WORKSPACE / "optimization_log.jsonl"
RESULTS_DIR = WORKSPACE / "results"

EFFICIENCY_COMMIT_MIN = 0.2333
MAX_EXPERIMENTS = 15
PLATEAU_STREAK = 3


def _load_benchmark_module() -> Any:
    path = WORKSPACE / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("sentinel_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sentinel_benchmark"] = mod
    spec.loader.exec_module(mod)
    return mod


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_rules(data: Dict[str, Any]) -> None:
    RULES_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def git_commit(message: str) -> None:
    subprocess.run(["git", "add", "configs/security_rules.json"], cwd=str(WORKSPACE), check=True)
    st = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=str(WORKSPACE))
    if st.returncode != 0:
        subprocess.run(["git", "commit", "-m", message], cwd=str(WORKSPACE), check=True)


def append_log(line: Dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


def run_experiment(
    bench: Any,
    *,
    exp_id: int,
    hypothesis: str,
    variant: str,
    description: str,
    reference_time: float,
    base_critical: int,
    base_findings: int,
) -> Tuple[Dict[str, Any], float, bool, bool, bool]:
    """Returns (result, efficiency, ok_critical, ok_efficiency_gate, ok_recall).

    `ok_recall` guards TOTAL findings, not just CRITICAL. Entropy tuning affects
    HIGH-severity hardcoded_secret findings, which the CRITICAL gate cannot see;
    without this guard the loop is rewarded for deleting true positives. (cubic
    P1/P2 — automated triage silently disabled secret detection.)"""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"experiment_{exp_id:02d}_{variant}.json"
    meta = {
        "experiment_id": exp_id,
        "hypothesis": hypothesis,
        "variant": variant,
        "description": description,
    }
    result = bench.run_corpus_baseline(
        WORKSPACE,
        output_path=out,
        log_path=LOG_PATH,
        reference_total_time_sec=reference_time,
        log_experiment=meta,
    )
    agg = result["aggregate"]
    crit = int(agg["total_critical"])
    find = int(agg["total_findings"])
    eff = float(agg["aggregate_efficiency"] or 0.0)
    ok_crit = crit >= base_critical
    # Recall guard: a "more efficient" config must not drop findings. This is the
    # severity-blind spot the CRITICAL-only gate missed (secrets are HIGH).
    ok_recall = find >= base_findings
    ok_eff = eff >= EFFICIENCY_COMMIT_MIN
    line = {
        "ts": result["generated_at"],
        "phase": 1,
        "event": "optimization_experiment",
        "experiment_id": exp_id,
        "hypothesis": hypothesis,
        "variant": variant,
        "description": description,
        "aggregate_efficiency": eff,
        "total_critical": crit,
        "total_findings": int(agg["total_findings"]),
        "total_time_sec": float(agg["total_time_sec"]),
        "passed_critical_gate": ok_crit,
        "passed_recall_gate": ok_recall,
        "passed_efficiency_gate": ok_eff,
        "output": str(out),
    }
    append_log(line)
    return result, eff, ok_crit, ok_eff, ok_recall


def patch_entropy(base: Dict[str, Any], value: float) -> Dict[str, Any]:
    r = copy.deepcopy(base)
    tun = r.setdefault("scanner_tuning", {})
    tun["secret_shannon_entropy_min"] = value
    tun.setdefault("parallel_workers", 4)
    return r


def patch_parallel(base: Dict[str, Any], workers: int) -> Dict[str, Any]:
    r = copy.deepcopy(base)
    tun = r.setdefault("scanner_tuning", {})
    tun["parallel_workers"] = workers
    tun.setdefault("secret_shannon_entropy_min", 3.5)
    return r


def patch_disable_rule(base: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
    r = copy.deepcopy(base)
    for rule in r.get("custom_rules", []):
        if str(rule.get("id")) == rule_id:
            rule["enabled"] = False
    return r


def main() -> None:
    if not BASELINE_PATH.is_file():
        print(f"Missing {BASELINE_PATH}; run: python scripts/benchmark.py --corpus-baseline")
        sys.exit(1)

    base_doc = load_json(BASELINE_PATH)
    ref_time = float(base_doc["aggregate"]["total_time_sec"])
    base_crit = int(base_doc["aggregate"]["total_critical"])
    base_find = int(base_doc["aggregate"]["total_findings"])
    base_eff = (base_crit / base_find) * (ref_time / ref_time) if base_find else 0.0

    print(
        f"Baseline: critical={base_crit} findings={base_find} "
        f"ref_time={ref_time:.4f}s efficiency≈{base_eff:.6f} "
        f"(commit if eff>={EFFICIENCY_COMMIT_MIN} and no CRITICAL/recall loss)\n"
    )

    bench = _load_benchmark_module()
    committed_head = load_json(RULES_PATH)
    best_eff = base_eff
    exp_id = 0
    plateau = 0

    def try_case(
        rules: Dict[str, Any],
        variant: str,
        hypothesis: str,
        description: str,
    ) -> str:
        nonlocal exp_id, plateau, best_eff, committed_head
        if exp_id >= MAX_EXPERIMENTS:
            return "stop_max"
        if plateau >= PLATEAU_STREAK:
            return "stop_plateau"

        exp_id += 1
        save_rules(rules)
        _result, eff, ok_crit, ok_eff, ok_recall = run_experiment(
            bench,
            exp_id=exp_id,
            hypothesis=hypothesis,
            variant=variant,
            description=description,
            reference_time=ref_time,
            base_critical=base_crit,
            base_findings=base_find,
        )
        print(
            f"  [{exp_id}/{MAX_EXPERIMENTS}] {variant} eff={eff:.6f} "
            f"ok_crit={ok_crit} ok_recall={ok_recall} ok_eff_gate={ok_eff}"
        )

        if not ok_crit:
            print("  -> revert (CRITICAL loss); restore last committed rules")
            save_rules(committed_head)
            return "fail_critical"

        if not ok_recall:
            # A config that drops findings is rejected regardless of efficiency —
            # for a security scanner, lost recall is the real cost. This is the
            # gate the entropy-floor ratchet (4.8→6.0) slipped past.
            print("  -> revert (recall loss; findings dropped); restore last committed rules")
            save_rules(committed_head)
            return "fail_recall"

        if ok_crit and ok_recall and ok_eff:
            best_eff = max(best_eff, eff)
            msg = (
                f"optimize(triage): {description}\n\n"
                f"Aggregate efficiency {eff:.4f} (gate {EFFICIENCY_COMMIT_MIN}). "
                f"CRITICAL count unchanged at {base_crit}; total findings >= "
                f"baseline {base_find} (recall preserved). "
                f"Baseline reference time {ref_time:.4f}s."
            )
            try:
                git_commit(msg)
                committed_head = load_json(RULES_PATH)
                plateau = 0
                print("  -> COMMITTED")
            except subprocess.CalledProcessError as exc:
                print(f"  -> git commit failed: {exc}")
            save_rules(committed_head)
            return "committed"

        if eff > best_eff:
            best_eff = eff
            plateau = 0
        else:
            plateau += 1

        print("  -> revert (efficiency below gate); restore last committed rules")
        save_rules(committed_head)
        if plateau >= PLATEAU_STREAK:
            print("  -> plateau: stopping hypothesis chain")
            return "stop_plateau"
        return "no_commit"

    # --- H1: entropy threshold (raise floor to drop low-entropy secret noise).
    # Empirically, corpus mcp-use secrets are ~4.73 bits; use 4.75+ to remove them (9 -> 7 findings).
    print("=== H1: Entropy threshold (secret_shannon_entropy_min) ===")
    plateau = 0
    for entropy in (4.75, 4.8, 4.85, 5.0, 5.5, 6.0):
        if exp_id >= MAX_EXPERIMENTS or plateau >= PLATEAU_STREAK:
            break
        r = patch_entropy(committed_head, entropy)
        status = try_case(
            r,
            variant=f"h1_entropy_{entropy}",
            hypothesis="H1_entropy_threshold",
            description=f"scanner_tuning.secret_shannon_entropy_min={entropy}",
        )
        if status in ("stop_max", "stop_plateau"):
            break

    # Refresh head after H1
    committed_head = load_json(RULES_PATH)
    plateau = 0

    # --- H2: disable MEDIUM noisy custom rule (mcp-insecure-random) ---
    if exp_id < MAX_EXPERIMENTS and plateau < PLATEAU_STREAK:
        print("\n=== H2: Disable MEDIUM rule mcp-insecure-random (enabled: false) ===")
        r = patch_disable_rule(committed_head, "mcp-insecure-random")
        try_case(
            r,
            variant="h2_disable_insecure_random",
            hypothesis="H2_disable_medium_noise",
            description="custom_rules: mcp-insecure-random enabled=false",
        )

    committed_head = load_json(RULES_PATH)
    plateau = 0

    # --- H3 / H4: parallel_workers (speed leg of efficiency) ---
    if exp_id < MAX_EXPERIMENTS and plateau < PLATEAU_STREAK:
        print("\n=== H3: parallel_workers=8 ===")
        try_case(
            patch_parallel(committed_head, 8),
            variant="h3_workers_8",
            hypothesis="H3_parallel_workers",
            description="scanner_tuning.parallel_workers=8",
        )
    committed_head = load_json(RULES_PATH)
    plateau = 0

    if exp_id < MAX_EXPERIMENTS and plateau < PLATEAU_STREAK:
        print("\n=== H4: parallel_workers=12 ===")
        try_case(
            patch_parallel(committed_head, 12),
            variant="h4_workers_12",
            hypothesis="H4_parallel_workers",
            description="scanner_tuning.parallel_workers=12",
        )
    committed_head = load_json(RULES_PATH)
    plateau = 0

    # --- H5: stack best entropy + disable random if not already ---
    if exp_id < MAX_EXPERIMENTS and plateau < PLATEAU_STREAK:
        print("\n=== H5: combined tuning (entropy 4.0 + disable insecure-random) ===")
        r = patch_disable_rule(patch_entropy(committed_head, 4.0), "mcp-insecure-random")
        try_case(
            r,
            variant="h5_entropy4_disable_random",
            hypothesis="H5_stack_entropy_and_rule_cut",
            description="entropy_min=4.0 and mcp-insecure-random disabled",
        )

    print(f"\nDone. experiments_run={exp_id} best_efficiency={best_eff:.6f} log={LOG_PATH}")


if __name__ == "__main__":
    main()
