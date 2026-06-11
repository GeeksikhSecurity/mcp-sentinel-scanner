#!/usr/bin/env python3
"""Invariant lint — convert prose security rules into a commit-time gate.

Zero-dependency. Exits 1 on any violation. Run:  python scripts/lint-invariants.py

WHY THIS EXISTS
---------------
The project's CLAUDE.md "Optimizer & Metric Integrity" rule already documented
that an entropy floor above the reachable ceiling disables secret detection — yet
the phase2 helper scripts re-baked exactly that (6.5 / 6.0). The rule existed only
as prose + a runtime warning; nothing checked the committed scripts. This lint
makes the invariants mechanical so the regression fails CI instead of shipping.

Checks (stable IDs):
  I1  no entropy floor > the reachable ceiling (_SECRET_ENTROPY_REACHABLE_MAX)
  I2  no `--mcp-insecure-random true` (a no-op that implies coverage it lacks)
  I3  no raw UPN interpolation into KQL string literals (KQL injection)
  I4  no reintroduction of the removed silent semgrep/trufflehog adapters
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []


def err(check: str, path: Path, line: int, msg: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}:{line}  [{check}]  {msg}")


# This lint necessarily contains the very patterns it forbids — never scan it.
_SELF = Path(__file__).resolve()


def _files(*globs: str) -> list[Path]:
    seen: dict[Path, None] = {}
    for g in globs:
        for p in ROOT.glob(g):
            rp = p.resolve()
            if p.is_file() and rp != _SELF:
                seen[rp] = None
    return list(seen)


# Read the reachable ceiling from the scanner itself so the lint never drifts.
def _ceiling() -> float:
    src = (ROOT / "src" / "mcp_sentinel_scanner.py").read_text(encoding="utf-8")
    m = re.search(r"_SECRET_ENTROPY_REACHABLE_MAX\s*=\s*([0-9.]+)", src)
    return float(m.group(1)) if m else 5.0


CEILING = _ceiling()

_ENTROPY_PATTERNS = [
    re.compile(r"--secret-shannon-entropy-min\s+([0-9]+(?:\.[0-9]+)?)"),
    re.compile(r'"secret_shannon_entropy_min"\s*:\s*([0-9]+(?:\.[0-9]+)?)'),
]


def check_entropy_ceiling() -> None:
    for path in _files("scripts/**/*.sh", "scripts/**/*.py", "configs/**/*.json", "configs/*.json"):
        if path.name == "lint-invariants.py":
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for pat in _ENTROPY_PATTERNS:
                m = pat.search(line)
                if m and float(m.group(1)) > CEILING:
                    err("I1", path, i,
                        f"entropy floor {m.group(1)} exceeds reachable ceiling {CEILING} "
                        f"— disables CWE-798 secret detection. Use <= {CEILING} (default 3.5).")


def check_mcp_insecure_random_noop() -> None:
    pat = re.compile(r"--mcp-insecure-random\s+true")
    for path in _files("scripts/**/*.sh", "scripts/**/*.py"):
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                err("I2", path, i,
                    "`--mcp-insecure-random true` is a no-op (rule ships enabled:false); "
                    "it implies coverage that doesn't exist. Drop the flag.")


def check_kql_interpolation() -> None:
    # Raw `... == "$var"` interpolation into KQL, unless the var is sanitized
    # (name starts with `safe`). The adapter must route UPNs through
    # ConvertTo-SafeKqlString first.
    pat = re.compile(r'==\s*"\$(?!safe)[A-Za-z_]')
    for path in _files("scripts/**/*.ps1"):
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                err("I3", path, i,
                    "raw variable interpolated into a KQL string literal (KQL injection) "
                    "— route it through ConvertTo-SafeKqlString first.")


def check_no_silent_adapters() -> None:
    pat = re.compile(r"_run_semgrep|_run_trufflehog|register_adapter|from .*adapters import")
    for path in _files("src/**/*.py"):
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                err("I4", path, i,
                    "the silent semgrep/trufflehog adapters were removed (issue #8); "
                    "do not reintroduce them in the default run path.")


def main() -> int:
    check_entropy_ceiling()
    check_mcp_insecure_random_noop()
    check_kql_interpolation()
    check_no_silent_adapters()

    print("\n═══ invariant lint ═══")
    if not errors:
        print(f"  no issues found (ceiling={CEILING})")
    else:
        print(f"\n  {len(errors)} ERROR(s):")
        for e in errors:
            print(f"    {e}")
    print(f"\n  Summary: {len(errors)} errors")
    print("  Rules:   CLAUDE.md (Optimizer & Metric Integrity)\n")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
