"""HTML report generator with interactive charts."""

from __future__ import annotations

from datetime import datetime
from typing import Dict

from ..mcp_sentinel_scanner import ScanResult


class HTMLReporter:
    """Generate interactive HTML reports."""

    @staticmethod
    def generate(result: ScanResult, title: str = "MCP Sentinel Security Report") -> str:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;  # noqa: E501
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        .summary-card .label {{
            font-size: 0.9em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .charts {{
            padding: 40px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }}
        .chart-container {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .chart-container h3 {{
            margin-bottom: 20px;
            color: #495057;
        }}
        .findings {{
            padding: 40px;
        }}
        .findings h2 {{
            margin-bottom: 30px;
            color: #495057;
        }}
        .finding {{
            background: white;
            margin-bottom: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
            border-left: 5px solid;
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #20c997; }}
        .finding-header {{
            padding: 20px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .finding-header .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        .finding-header .severity.critical {{
            background: #dc3545;
            color: white;
        }}
        .finding-header .severity.high {{
            background: #fd7e14;
            color: white;
        }}
        .finding-header .severity.medium {{
            background: #ffc107;
            color: #000;
        }}
        .finding-header .severity.low {{
            background: #20c997;
            color: white;
        }}
        .finding-body {{
            padding: 20px;
        }}
        .finding-body .field {{
            margin-bottom: 15px;
        }}
        .finding-body .field-label {{
            font-weight: bold;
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .finding-body .code-snippet {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin-top: 10px;
        }}
        .confidence-bar {{
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }}
        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s;
        }}
        .footer {{
            padding: 30px;
            text-align: center;
            background: #f8f9fa;
            color: #6c757d;
        }}
        @media (max-width: 768px) {{
            .charts {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ MCP Sentinel Security Report</h1>
            <div class="subtitle">Advanced Security Analysis · {datetime.now().strftime("%B %d, %Y at %H:%M")}</div>  # noqa: E501
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="label">Files Scanned</div>
                <div class="value">{result.summary.files_scanned}</div>
            </div>
            <div class="summary-card">
                <div class="label">Total Lines</div>
                <div class="value">{result.summary.total_lines:,}</div>
            </div>
            <div class="summary-card">
                <div class="label">Vulnerabilities</div>
                <div class="value">{result.summary.vulnerabilities_found}</div>
            </div>
            <div class="summary-card">
                <div class="label">ASR Score</div>
                <div class="value">{result.summary.asr_score:.0%}</div>
            </div>
            <div class="summary-card">
                <div class="label">Scan Time</div>
                <div class="value">{result.summary.scan_time:.2f}s</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Category Breakdown</h3>
                <canvas id="categoryChart"></canvas>
            </div>
        </div>

        <div class="findings">
            <h2>Detailed Findings ({len(result.findings)})</h2>
"""

        # Add findings
        for finding in sorted(
            result.findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[f.severity],
        ):
            sev_class = finding.severity.lower()
            html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="severity {sev_class}">{finding.severity}</span>
                    <span>{finding.category.replace('_', ' ').title()}</span>
                    <span>{finding.file_path.split('/')[-1]}:{finding.line_number}</span>
                </div>
                <div class="finding-body">
                    <div class="field">
                        <div class="field-label">Description</div>
                        <div>{finding.description}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">File Location</div>
                        <div><code>{finding.file_path}:{finding.line_number}</code></div>
                    </div>
                    <div class="field">
                        <div class="field-label">Recommendation</div>
                        <div>{finding.recommendation}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">CWE Reference</div>
                        <div>{finding.cwe_id or 'N/A'}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Confidence: {finding.confidence:.0%}</div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {finding.confidence * 100}%"></div>  # noqa: E501
                        </div>
                    </div>
                    <div class="field">
                        <div class="field-label">Code Snippet</div>
                        <div class="code-snippet">{finding.code_snippet or '(no snippet)'}</div>
                    </div>
                </div>
            </div>
"""

        # Calculate category distribution
        category_counts: Dict[str, int] = {}
        for finding in result.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        # Generate chart data
        severity_data = result.summary.severity_distribution
        category_labels = list(category_counts.keys())
        category_values = list(category_counts.values())

        html += f"""
        </div>

        <div class="footer">
            <p>Generated by MCP Sentinel Scanner v1.0 · Based on research by Zhao et al. (2025)</p>
            <p>Report generated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>

    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: {list(severity_data.keys())},
                datasets: [{{
                    data: {list(severity_data.values())},
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#20c997'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {category_values},
                    backgroundColor: 'rgba(102, 126, 234, 0.8)'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        return html


__all__ = ["HTMLReporter"]
