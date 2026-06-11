"""Sentinel CLI — Universal Code Security Scanner.

Usage:
    sentinel scan <target>       Scan for vulnerabilities
    sentinel doctor              Check tool availability
    sentinel comply <target>     Run compliance check
    sentinel report <target>     Generate client report
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from ..core.registry import ScannerRegistry
from ..core.pipeline import ScanPipeline, detect_project_type

console = Console()


def _build_registry(tools: Optional[str] = None) -> ScannerRegistry:
    """Build a registry with all available scanners."""
    registry = ScannerRegistry()

    # Built-in analyzer (always available, zero external deps)
    from ..analyzers.builtin import BuiltinAnalyzer
    registry.register_analyzer(BuiltinAnalyzer())

    # Built-in code analyzers (pure Python, no external deps)
    from ..analyzers.npm import NpmAnalyzer
    from ..analyzers.react import ReactAnalyzer
    registry.register_analyzer(NpmAnalyzer())
    registry.register_analyzer(ReactAnalyzer())

    # NOTE (SAY-281, cubic P2 — prose detectors not yet wired):
    # ProseAttackSurfaceAnalyzer and ProseCompositionAnalyzer are intentionally
    # NOT registered here yet. The single-file ProseAttackSurfaceAnalyzer could
    # register like the analyzers above, but ProseCompositionAnalyzer is
    # corpus-level (`analyze_corpus` over many files) and needs a multi-file pass
    # plus the ProseSarifEmitter wired into the output path — that integration is
    # Phase 3b. Until then the prose detectors run ONLY via their unit tests and
    # the `sentinel.sarif.prose_sarif` helpers; they do not execute in a normal
    # scan. Do not assume prose findings appear in CLI output until wired.

    # External tool adapters (semgrep/trufflehog) are intentionally NOT registered.
    # In external-corpus testing they silently contributed nothing — the adapters
    # returned [] on timeout/error with no warning (issue #8), giving a false sense
    # of coverage. Run semgrep/trufflehog as dedicated tools; this scanner is the
    # precise, validated layer. The adapter modules remain for explicit/opt-in use.

    return registry


@click.group()
@click.version_option(package_name="sentinel-scanner")
def cli() -> None:
    """Sentinel — Universal Code Security Scanner.

    One command to scan any project for vulnerabilities, secrets, and compliance gaps.
    """
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option("-f", "--format", "output_format",
              type=click.Choice(["terminal", "json", "sarif", "html", "markdown"]),
              default="terminal", help="Output format")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("-s", "--severity", default="LOW",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              help="Minimum severity threshold")
@click.option("--tools", default=None,
              help="Comma-separated tool list (builtin,semgrep,trufflehog,trivy,codeql)")
@click.option("--deep", is_flag=True, help="Enable CodeQL deep scan")
@click.option("--parallel", default=4, type=int, help="Number of workers")
@click.option("-q", "--quiet", is_flag=True, help="Minimal output")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(
    target: str,
    output_format: str,
    output: Optional[str],
    severity: str,
    tools: Optional[str],
    deep: bool,
    parallel: int,
    quiet: bool,
    verbose: bool,
) -> None:
    """Scan a codebase for security vulnerabilities."""
    target_path = Path(target).resolve()

    if not quiet:
        console.print(Panel(
            f"[bold]Scanning:[/bold] {target_path}",
            title="Sentinel Scanner",
            border_style="blue",
        ))

    # Detect project type
    project_types = detect_project_type(target_path)
    if project_types and not quiet:
        console.print(f"  Project types: {', '.join(project_types.keys())}")

    # Build registry and pipeline
    tool_list = tools.split(",") if tools else None
    registry = _build_registry(tools)
    pipeline = ScanPipeline(
        registry=registry,
        parallel=parallel,
        severity_threshold=severity,
    )

    # Run scan
    with console.status("[bold blue]Scanning...") as status:
        result = pipeline.run(target_path, tools=tool_list)

    # Display results
    if output_format == "terminal":
        _render_terminal(result, quiet)
    elif output_format == "json":
        data = {
            "target": result.target,
            "summary": {
                "total": result.summary.total_findings,
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
                "duration": round(result.summary.scan_duration, 2),
            },
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "cwe": f.cwe_id,
                }
                for f in result.findings
            ],
        }
        out = json.dumps(data, indent=2)
        if output:
            Path(output).write_text(out)
            console.print(f"Wrote JSON to {output}")
        else:
            click.echo(out)

    # Exit code: 1 if critical/high findings
    if result.summary.critical > 0 or result.summary.high > 0:
        sys.exit(1)


@cli.command()
def doctor() -> None:
    """Check tool availability and system readiness."""
    console.print(Panel("[bold]Sentinel Doctor[/bold]", border_style="blue"))

    registry = _build_registry()
    status = registry.doctor()

    table = Table(title="Scanner Status")
    table.add_column("Scanner", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("Command", style="dim")
    table.add_column("Available", justify="center")
    table.add_column("Enabled", justify="center")

    # Check external tools directly
    external_tools = {
        "semgrep": "semgrep",
        "trufflehog": "trufflehog",
        "trivy": "trivy",
        "codeql": "codeql",
        "npm": "npm",
        "pip-audit": "pip-audit",
    }

    for name, cmd in external_tools.items():
        available = shutil.which(cmd) is not None
        style = "green" if available else "red"
        table.add_row(
            name,
            "external (run separately)",
            cmd,
            f"[{style}]{'yes' if available else 'no'}[/{style}]",
            "[green]yes[/green]",
        )

    # Built-in scanners
    table.add_row("builtin", "analyzer", "built-in", "[green]yes[/green]", "[green]yes[/green]")

    console.print(table)

    # Suggestions for missing tools
    missing = [name for name, cmd in external_tools.items() if not shutil.which(cmd)]
    if missing:
        console.print("\n[yellow]Missing tools — install for deeper scanning:[/yellow]")
        install_hints = {
            "semgrep": "pip install semgrep",
            "trufflehog": "brew install trufflehog",
            "trivy": "brew install trivy",
            "codeql": "brew install codeql",
            "npm": "brew install node",
            "pip-audit": "pip install pip-audit",
        }
        for name in missing:
            hint = install_hints.get(name, f"Install {name}")
            console.print(f"  {name}: [dim]{hint}[/dim]")
    else:
        console.print("\n[green]All tools available![/green]")


@cli.command()
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option("--framework", type=click.Choice(["pci-dss", "soc2", "hipaa", "owasp", "gdpr", "nist", "all"]),
              default="owasp", help="Compliance framework")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def comply(target: str, framework: str, output: Optional[str]) -> None:
    """Check compliance against security frameworks."""
    console.print(Panel(
        f"[bold]Compliance Check:[/bold] {framework.upper()}\n[dim]{target}[/dim]",
        title="Sentinel Comply",
        border_style="blue",
    ))
    # TODO: Implement in Phase 4 (compliance engine)
    console.print("[yellow]Compliance engine coming in Phase 4[/yellow]")


@cli.command()
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option("--client", required=True, help="Client name for report branding")
@click.option("--template", type=click.Choice(["executive", "technical", "full"]),
              default="full", help="Report template")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def report(target: str, client: str, template: str, output: Optional[str]) -> None:
    """Generate a client-ready security assessment report."""
    console.print(Panel(
        f"[bold]Client Report:[/bold] {client}\n[dim]{target}[/dim]",
        title="Sentinel Report",
        border_style="blue",
    ))
    # TODO: Implement in Phase 6 (client reporter)
    console.print("[yellow]Client reporter coming in Phase 6[/yellow]")


@cli.command()
@click.argument("target", type=click.Path(), default=".")
def init(target: str) -> None:
    """Initialize a .sentinel.json config in the project."""
    target_path = Path(target).resolve()
    config_path = target_path / ".sentinel.json"

    if config_path.exists():
        console.print(f"[yellow]{config_path} already exists[/yellow]")
        return

    project_types = detect_project_type(target_path)
    config = {
        "version": "2.0",
        "project_types": list(project_types.keys()),
        "severity_threshold": "LOW",
        "tools": {
            "builtin": {"enabled": True},
            "semgrep": {"enabled": True},
            "trufflehog": {"enabled": True},
            "trivy": {"enabled": True},
            "codeql": {"enabled": False},
        },
        "exclude": ["node_modules", "dist", "build", ".git", "__pycache__", ".venv"],
        "parallel": 4,
    }

    config_path.write_text(json.dumps(config, indent=2))
    console.print(f"[green]Created {config_path}[/green]")
    console.print(f"  Detected: {', '.join(project_types.keys()) or 'generic'}")


def _render_terminal(result, quiet: bool = False) -> None:
    """Render scan results to terminal using rich."""
    summary = result.summary

    if quiet:
        console.print(
            f"Findings: {summary.total_findings} "
            f"(C:{summary.critical} H:{summary.high} M:{summary.medium} L:{summary.low})"
        )
        return

    # Summary panel
    summary_text = (
        f"[red]Critical: {summary.critical}[/red]  "
        f"[yellow]High: {summary.high}[/yellow]  "
        f"[blue]Medium: {summary.medium}[/blue]  "
        f"[dim]Low: {summary.low}[/dim]\n"
        f"Duration: {summary.scan_duration:.1f}s  "
        f"Files: {summary.files_scanned}"
    )
    console.print(Panel(summary_text, title="Scan Summary", border_style="green"))

    if not result.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    # Findings table
    table = Table(title=f"{summary.total_findings} Finding(s)")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Category", width=20)
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Description", max_width=50)

    severity_styles = {
        "CRITICAL": "red bold",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "dim",
    }

    for f in result.findings:
        style = severity_styles.get(f.severity, "dim")
        table.add_row(
            f"[{style}]{f.severity}[/{style}]",
            f.category,
            f.file_path,
            str(f.line_number),
            f.description[:50],
        )

    console.print(table)


if __name__ == "__main__":
    cli()
