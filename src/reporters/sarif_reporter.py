"""SARIF (Static Analysis Results Interchange Format) reporter."""

from __future__ import annotations

import json
from typing import Any, Dict

from ..mcp_sentinel_scanner import ScanResult


class SARIFReporter:
    """Generate SARIF format reports for IDE integration."""

    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "MCP Sentinel Scanner"
    TOOL_VERSION = "1.0.0"

    @staticmethod
    def generate(result: ScanResult, source_root: str = ".") -> str:
        """Generate SARIF format report."""
        sarif_report: Dict[str, Any] = {
            "version": SARIFReporter.SARIF_VERSION,
            "$schema": f"https://json.schemastore.org/sarif-{SARIFReporter.SARIF_VERSION}.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": SARIFReporter.TOOL_NAME,
                            "version": SARIFReporter.TOOL_VERSION,
                            "informationUri": "https://github.com/mcp-security/mcp-sentinel-scanner",  # noqa: E501
                            "rules": SARIFReporter._generate_rules(result),
                        }
                    },
                    "results": SARIFReporter._generate_results(result, source_root),
                    "columnKind": "utf16CodeUnits",
                    "properties": {
                        "scanSummary": {
                            "filesScanned": result.summary.files_scanned,
                            "totalLines": result.summary.total_lines,
                            "vulnerabilitiesFound": result.summary.vulnerabilities_found,
                            "asrScore": result.summary.asr_score,
                            "scanTime": result.summary.scan_time,
                        }
                    },
                }
            ],
        }

        return json.dumps(sarif_report, indent=2)

    @staticmethod
    def _generate_rules(result: ScanResult) -> list:
        """Generate SARIF rules from findings."""
        rules = {}

        for finding in result.findings:
            rule_id = f"{finding.category}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.category.replace("_", " ").title(),
                    "shortDescription": {"text": finding.description},
                    "fullDescription": {"text": finding.recommendation},
                    "help": {
                        "text": finding.recommendation,
                        "markdown": f"## {finding.category}\n\n{finding.recommendation}",
                    },
                    "properties": {
                        "tags": [finding.severity.lower(), finding.category],
                        "precision": "high" if finding.confidence > 0.8 else "medium",
                    },
                }

                if finding.cwe_id:
                    rules[rule_id]["properties"]["tags"].append(finding.cwe_id)

        return list(rules.values())

    @staticmethod
    def _generate_results(result: ScanResult, source_root: str) -> list:
        """Generate SARIF results from findings."""
        results = []

        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }

        for finding in result.findings:
            sarif_result = {
                "ruleId": finding.category,
                "level": severity_map.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "snippet": {"text": finding.code_snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "recommendation": finding.recommendation,
                },
            }

            if finding.cwe_id:
                sarif_result["properties"]["cweId"] = finding.cwe_id

            results.append(sarif_result)

        return results


__all__ = ["SARIFReporter"]
