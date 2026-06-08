#!/usr/bin/env python3
"""Command-line interface for the MCP Sentinel Scanner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path for standalone execution
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from colorama import Fore, Style
from colorama import init as colorama_init
from tabulate import tabulate

from src import MCPSentinelScanner
from src.unified_scanner import UnifiedScanner

colorama_init()


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel_cli.py",
        description="MCP Sentinel Scanner - Advanced Security Analysis Tool",
    )
    parser.add_argument("target", help="Target directory or file to scan")
    parser.add_argument(
        "-c",
        "--config",
        help="Configuration file path (defaults to configs/security_rules.json next to this repo)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        nargs="+",
        default=[],
        help="Exclude paths/patterns (repeatable). Examples: --exclude node_modules dist \"*.d.ts\"",
    )
    parser.add_argument("-o", "--output", help="Output file for scan report")
    parser.add_argument(
        "-f",
        "--format",
        "--output-format",
        choices=["json", "markdown", "terminal", "sarif", "html"],
        default="terminal",
        help="Output format",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity level to report",
    )
    parser.add_argument("--no-colors", action="store_true", help="Disable colored output")
    parser.add_argument(
        "--parallel",
        type=int,
        default=4,
        help=(
            "Number of parallel workers (default 4). The default value is treated "
            "as 'no explicit intent' and yields to config scanner_tuning.parallel_workers; "
            "use --parallel-workers to force a value (including 4)."
        ),
    )
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        metavar="N",
        help="Override parallel workers (same as --parallel; takes precedence if set)",
    )
    parser.add_argument(
        "--secret-shannon-entropy-min",
        type=float,
        default=None,
        metavar="BITS",
        help="Minimum Shannon entropy for hardcoded_secret matches (overrides config file)",
    )
    parser.add_argument(
        "--mcp-insecure-random",
        choices=("true", "false"),
        default=None,
        help=(
            "Toggle the CLI-level disable of the mcp-insecure-random custom rule "
            "(false = force off). NOTE: the rule ships 'enabled: false' in "
            "configs/security_rules.json, so 'true' only clears a CLI disable and "
            "does NOT by itself re-enable the rule."
        ),
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress the 'Report written to ...' stderr notice when using -o",
    )
    parser.add_argument(
        "--deep-scan", action="store_true", help="Enable advanced detection modules"
    )
    parser.add_argument("--unified", action="store_true", help="Use unified scanner with all tools")
    return parser.parse_args(argv)


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def severity_order(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(severity, 4)


def format_terminal(result, use_color: bool) -> str:
    summary = result.summary
    color_map = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.MAGENTA,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
    }

    lines = [
        f"Scanned files: {summary.files_scanned}",
        f"Total lines: {summary.total_lines}",
        f"Vulnerabilities: {summary.vulnerabilities_found}",
        f"ASR Score: {summary.asr_score:.2%}",
        "",
    ]

    table = []
    for finding in sorted(
        result.findings, key=lambda f: (severity_order(f.severity), -f.confidence)
    ):
        color = color_map.get(finding.severity, "") if use_color else ""
        reset = Style.RESET_ALL if use_color else ""
        table.append(
            [
                f"{color}{finding.severity}{reset}",
                finding.category,
                f"{finding.file_path}:{finding.line_number}",
                finding.description,
                f"{finding.confidence:.0%}",
            ]
        )

    if table:
        lines.append(
            tabulate(
                table, headers=["Severity", "Category", "Location", "Description", "Confidence"]
            )
        )
    else:
        lines.append("No vulnerabilities detected.")

    if result.advanced_findings:
        lines.append("\nAdvanced detection findings:")
        for adv in result.advanced_findings:
            color = color_map.get(adv.severity, "") if use_color else ""
            reset = Style.RESET_ALL if use_color else ""
            location = f"{adv.file_path}:{adv.line_number}" if adv.line_number else adv.file_path
            lines.append(
                f"- {color}{adv.severity}{reset} {adv.category} · {adv.description} ({location})"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config_path = args.config
    if not config_path:
        default_rules = _repo_root() / "configs" / "security_rules.json"
        if default_rules.is_file():
            config_path = str(default_rules)

    try:
        config = load_config(config_path) if config_path else {}
    except Exception as exc:  # pragma: no cover - defensive
        print(f"Failed to load configuration: {exc}", file=sys.stderr)
        return 2

    if config_path and "custom_rules_file" not in config:
        config["custom_rules_file"] = str(Path(config_path).resolve())

    tuning = config.setdefault("scanner_tuning", {})
    if args.secret_shannon_entropy_min is not None:
        tuning["secret_shannon_entropy_min"] = args.secret_shannon_entropy_min
    # Do not overwrite file defaults with --parallel 4; only apply explicit CLI intent.
    if args.parallel_workers is not None:
        tuning["parallel_workers"] = args.parallel_workers
    elif args.parallel != 4:
        tuning["parallel_workers"] = args.parallel

    effective_parallel = (
        args.parallel_workers if args.parallel_workers is not None else args.parallel
    )

    if args.mcp_insecure_random == "false":
        dis = list(config.get("disabled_custom_rule_ids") or [])
        if "mcp-insecure-random" not in dis:
            dis.append("mcp-insecure-random")
        config["disabled_custom_rule_ids"] = dis
    elif args.mcp_insecure_random == "true":
        # Symmetric with the "false" branch: clear a CLI-level disable. This does
        # NOT activate the rule on its own — it ships `enabled: false` in
        # security_rules.json and _extend_patterns_from_custom_rules_file skips
        # enabled:false rules. Documented in the flag's help text.
        config["disabled_custom_rule_ids"] = [
            r for r in (config.get("disabled_custom_rule_ids") or [])
            if r != "mcp-insecure-random"
        ]

    # Merge CLI excludes into config (config values first, then CLI additions).
    cli_excludes = [item for group in (args.exclude or []) for item in group]
    if cli_excludes:
        config_excludes = list(config.get("exclude", []) or [])
        # Preserve order, avoid duplicates.
        merged = []
        for value in config_excludes + cli_excludes:
            if value not in merged:
                merged.append(value)
        config["exclude"] = merged

    if args.unified:
        scanner = UnifiedScanner(config=config)
    else:
        scanner = MCPSentinelScanner(config=config, parallel_workers=effective_parallel)

    try:
        result = scanner.scan(args.target)
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    if args.severity:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        allowed = {s for s in allowed if severity_order(s) <= severity_order(args.severity)}
        result.findings = [f for f in result.findings if f.severity in allowed]

    if args.format == "json":
        output_text = scanner.to_json(result)
    elif args.format == "markdown":
        output_text = scanner.to_markdown(result)
    elif args.format == "sarif":
        output_text = scanner.to_sarif(result, args.target)
    elif args.format == "html":
        output_text = scanner.to_html(result)
    else:
        output_text = format_terminal(result, use_color=not args.no_colors)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        if not args.quiet:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
