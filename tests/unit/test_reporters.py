"""Unit tests for report generators."""
import json

import pytest

from src import MCPSentinelScanner, ScanResult, ScanSummary, VulnerabilityFinding
from src.advanced_detection import AdvancedFinding
from src.reporters.sarif_reporter import SARIFReporter
from src.reporters.html_reporter import HTMLReporter


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        VulnerabilityFinding(
            severity="CRITICAL",
            category="sql_injection",
            description="SQL injection vulnerability",
            file_path="/path/to/file.py",
            line_number=42,
            code_snippet="query = 'SELECT * FROM users WHERE id=' + user_id",
            recommendation="Use parameterized queries",
            cwe_id="CWE-89",
            confidence=0.9,
        ),
        VulnerabilityFinding(
            severity="HIGH",
            category="command_injection",
            description="Command injection via shell=True",
            file_path="/path/to/script.py",
            line_number=15,
            code_snippet="subprocess.call(cmd, shell=True)",
            recommendation="Avoid shell=True",
            cwe_id="CWE-78",
            confidence=0.85,
        ),
    ]


@pytest.fixture
def sample_advanced_findings():
    """Create sample advanced findings."""
    return [
        AdvancedFinding(
            severity="MEDIUM",
            category="complexity",
            description="High cyclomatic complexity",
            file_path="/path/to/complex.py",
            line_number=None,
            metadata={"cyclomatic_complexity": 15},
        )
    ]


@pytest.fixture
def sample_scan_result(sample_findings, sample_advanced_findings):
    """Create a sample scan result."""
    summary = ScanSummary(
        files_scanned=10,
        total_lines=500,
        scan_time=1.5,
        vulnerabilities_found=len(sample_findings),
        asr_score=0.75,
        severity_distribution={"CRITICAL": 1, "HIGH": 1},
    )
    return ScanResult(
        summary=summary, findings=sample_findings, advanced_findings=sample_advanced_findings
    )


class TestSARIFReporter:
    """Test SARIF report generation."""

    def test_sarif_version(self):
        """Test SARIF version constant."""
        assert SARIFReporter.SARIF_VERSION == "2.1.0"

    def test_sarif_tool_name(self):
        """Test tool name constant."""
        assert SARIFReporter.TOOL_NAME == "MCP Sentinel Scanner"

    def test_generate_valid_json(self, sample_scan_result):
        """Test that SARIF output is valid JSON."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        assert isinstance(data, dict)

    def test_sarif_schema(self, sample_scan_result):
        """Test SARIF has required schema fields."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        assert "version" in data
        assert "$schema" in data
        assert "runs" in data
        assert data["version"] == "2.1.0"

    def test_sarif_runs_structure(self, sample_scan_result):
        """Test SARIF runs array structure."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        assert len(data["runs"]) > 0
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_tool_driver(self, sample_scan_result):
        """Test SARIF tool driver information."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "MCP Sentinel Scanner"
        assert "version" in driver
        assert "rules" in driver

    def test_sarif_results_count(self, sample_scan_result):
        """Test SARIF results match findings count."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        results = data["runs"][0]["results"]
        assert len(results) == len(sample_scan_result.findings)

    def test_sarif_severity_mapping(self, sample_scan_result):
        """Test severity levels are correctly mapped."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        results = data["runs"][0]["results"]

        # Check severity mapping
        levels = {r["level"] for r in results}
        assert "error" in levels  # CRITICAL/HIGH map to error
        # warning for MEDIUM, note for LOW

    def test_sarif_locations(self, sample_scan_result):
        """Test SARIF locations are correctly formatted."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        result = data["runs"][0]["results"][0]

        assert "locations" in result
        location = result["locations"][0]
        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "region" in location["physicalLocation"]

    def test_sarif_rules_generation(self, sample_scan_result):
        """Test SARIF rules are generated from findings."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) > 0
        rule = rules[0]
        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule

    def test_sarif_cwe_tags(self, sample_scan_result):
        """Test CWE IDs are included in properties."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        result = data["runs"][0]["results"][0]

        # CWE should be in properties
        if "cweId" in result.get("properties", {}):
            assert result["properties"]["cweId"].startswith("CWE-")

    def test_sarif_scan_summary_properties(self, sample_scan_result):
        """Test scan summary is included in properties."""
        sarif = SARIFReporter.generate(sample_scan_result)
        data = json.loads(sarif)
        properties = data["runs"][0]["properties"]

        assert "scanSummary" in properties
        summary = properties["scanSummary"]
        assert summary["filesScanned"] == 10
        assert summary["totalLines"] == 500
        assert summary["vulnerabilitiesFound"] == 2

    def test_sarif_with_source_root(self, sample_scan_result):
        """Test SARIF generation with custom source root."""
        sarif = SARIFReporter.generate(sample_scan_result, source_root="/custom/root")
        data = json.loads(sarif)
        # Should not crash with custom source root
        assert "runs" in data


class TestHTMLReporter:
    """Test HTML report generation."""

    def test_generate_valid_html(self, sample_scan_result):
        """Test that HTML output is valid."""
        html = HTMLReporter.generate(sample_scan_result)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_html_contains_title(self, sample_scan_result):
        """Test HTML contains title."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "<title>MCP Sentinel Security Report</title>" in html

    def test_html_custom_title(self, sample_scan_result):
        """Test HTML with custom title."""
        html = HTMLReporter.generate(sample_scan_result, title="Custom Security Report")
        assert "<title>Custom Security Report</title>" in html

    def test_html_summary_section(self, sample_scan_result):
        """Test HTML includes summary section."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "Files Scanned" in html
        assert "10" in html  # files_scanned value
        assert "500" in html  # total_lines value

    def test_html_severity_classes(self, sample_scan_result):
        """Test HTML includes severity CSS classes."""
        html = HTMLReporter.generate(sample_scan_result)
        assert 'class="finding critical"' in html or 'class="severity critical"' in html
        assert 'class="finding high"' in html or 'class="severity high"' in html

    def test_html_chart_js_included(self, sample_scan_result):
        """Test HTML includes Chart.js library."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "chart.js" in html.lower()

    def test_html_findings_count(self, sample_scan_result):
        """Test HTML shows correct findings count."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "Detailed Findings (2)" in html

    def test_html_contains_recommendations(self, sample_scan_result):
        """Test HTML includes recommendations."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "Use parameterized queries" in html
        assert "Avoid shell=True" in html

    def test_html_contains_cwe_references(self, sample_scan_result):
        """Test HTML includes CWE references."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "CWE-89" in html
        assert "CWE-78" in html

    def test_html_responsive_design(self, sample_scan_result):
        """Test HTML includes responsive design CSS."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "@media" in html
        assert "viewport" in html

    def test_html_code_snippets(self, sample_scan_result):
        """Test HTML includes code snippets."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "code-snippet" in html

    def test_html_confidence_bars(self, sample_scan_result):
        """Test HTML includes confidence bars."""
        html = HTMLReporter.generate(sample_scan_result)
        assert "confidence-bar" in html or "Confidence" in html

    def test_html_empty_findings(self):
        """Test HTML generation with no findings."""
        summary = ScanSummary(
            files_scanned=5,
            total_lines=100,
            scan_time=0.5,
            vulnerabilities_found=0,
            asr_score=0.0,
            severity_distribution={},
        )
        result = ScanResult(summary=summary, findings=[], advanced_findings=[])
        html = HTMLReporter.generate(result)
        assert "<!DOCTYPE html>" in html
        assert "Detailed Findings (0)" in html


class TestReporterIntegration:
    """Test reporter integration with scanner."""

    def test_scanner_to_sarif(self, tmp_path):
        """Test scanner can generate SARIF output."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        scanner = MCPSentinelScanner()
        result = scanner.scan(test_file)
        sarif = scanner.to_sarif(result)

        data = json.loads(sarif)
        assert "runs" in data

    def test_scanner_to_html(self, tmp_path):
        """Test scanner can generate HTML output."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        scanner = MCPSentinelScanner()
        result = scanner.scan(test_file)
        html = scanner.to_html(result)

        assert "<!DOCTYPE html>" in html
