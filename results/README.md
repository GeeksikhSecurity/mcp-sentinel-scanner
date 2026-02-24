# Results Folder Structure

This directory keeps scan outputs and artifacts out of the repo root. Store all generated results here unless they are part of source or documentation.

## Layout

1. `results/scans/` raw scanner outputs like JSON and SARIF.
2. `results/reports/` human-readable reports like HTML and Markdown.
3. `results/exports/` sanitized bundles prepared for sharing.
4. `results/benchmarks/` performance runs and timing data.
5. `results/logs/` execution logs.

## Naming Convention

Use a consistent timestamped naming scheme:

`YYYYMMDD_HHMMSS_target_format.ext`

Examples:

`20260208_140530_repoA_json.json`
`20260208_140530_repoA_sarif.sarif`
`20260208_140530_repoA_html.html`

