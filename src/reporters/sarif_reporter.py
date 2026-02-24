"""SARIF (Static Analysis Results Interchange Format) reporter."""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path
from typing import Any, Dict, Tuple

from ..mcp_sentinel_scanner import ScanResult


class SARIFReporter:
    """Generate SARIF format reports for IDE integration."""

    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "MCP Sentinel Scanner"
    try:
        TOOL_VERSION = pkg_version("mcp-sentinel-scanner")
    except PackageNotFoundError:  # pragma: no cover
        TOOL_VERSION = "dev"

    @staticmethod
    def generate(result: ScanResult, source_root: str = ".") -> str:
        """Generate SARIF format report."""
        base_uri = SARIFReporter._normalize_base_uri(source_root)
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
                    "originalUriBaseIds": {
                        "%SRCROOT%": {"uri": base_uri},
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
    def _normalize_base_uri(source_root: str) -> str:
        """
        Create a stable base URI for %SRCROOT%.

        Use a file:// URI when possible (absolute paths). Otherwise fall back to the string as-is.
        """
        try:
            p = Path(source_root).expanduser().resolve()
            # Ensure trailing slash for base URIs
            return p.as_uri().rstrip("/") + "/"
        except Exception:
            normalized = str(source_root).replace("\\", "/").rstrip("/") + "/"
            return normalized

    @staticmethod
    def _to_sarif_uri(file_path: str, source_root: str) -> Tuple[str, str | None]:
        """
        Convert a finding file path to a SARIF artifactLocation uri.

        Prefer paths relative to source_root with uriBaseId=%SRCROOT%.
        """
        try:
            root = Path(source_root).expanduser().resolve()
            p = Path(file_path).expanduser()
            if p.is_absolute():
                p = p.resolve()
            else:
                # keep relative paths as-is
                return p.as_posix(), "%SRCROOT%"

            try:
                rel = p.relative_to(root)
                return rel.as_posix(), "%SRCROOT%"
            except ValueError:
                return p.as_posix(), None
        except Exception:
            return str(file_path).replace("\\", "/"), None

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
            uri, uri_base_id = SARIFReporter._to_sarif_uri(finding.file_path, source_root)
            artifact_location: Dict[str, Any] = {"uri": uri}
            if uri_base_id:
                artifact_location["uriBaseId"] = uri_base_id

            sarif_result = {
                "ruleId": finding.category,
                "level": severity_map.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                **artifact_location,
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
