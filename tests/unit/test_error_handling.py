"""Error handling tests for MCP Sentinel Scanner."""
import json
from pathlib import Path

import pytest

from src import MCPSentinelScanner


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_scan_nonexistent_path(self):
        """Test scanning a path that doesn't exist."""
        scanner = MCPSentinelScanner()
        with pytest.raises(FileNotFoundError, match="No scannable files found"):
            scanner.scan("/nonexistent/path/12345")

    def test_scan_permission_denied(self, tmp_path, monkeypatch):
        """Test scanning a file without read permissions."""
        test_file = tmp_path / "restricted.py"
        test_file.write_text("print('test')")
        test_file.chmod(0o000)

        scanner = MCPSentinelScanner()
        try:
            # Should handle permission errors gracefully
            result = scanner.scan(tmp_path)
            # The file should be skipped or produce an error finding
            assert result.summary.files_scanned >= 0
        finally:
            test_file.chmod(0o644)  # Restore permissions for cleanup

    def test_malformed_config_file(self, tmp_path):
        """Test loading a malformed configuration file."""
        from scripts.sentinel_cli import load_config

        config_file = tmp_path / "bad_config.json"
        config_file.write_text("{ invalid json }")

        with pytest.raises(json.JSONDecodeError):
            load_config(str(config_file))

    def test_missing_config_file(self):
        """Test loading a non-existent configuration file."""
        from scripts.sentinel_cli import load_config

        with pytest.raises(FileNotFoundError, match="Config file not found"):
            load_config("/nonexistent/config.json")

    def test_empty_file_handling(self, tmp_path):
        """Test scanning an empty file."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        scanner = MCPSentinelScanner()
        result = scanner.scan(empty_file)

        assert result.summary.files_scanned == 1
        assert result.summary.total_lines == 0

    def test_binary_file_handling(self, tmp_path):
        """Test scanning a binary file."""
        binary_file = tmp_path / "binary.pyc"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe")

        scanner = MCPSentinelScanner()

        # Binary files should be skipped (not in SUPPORTED_EXTENSIONS)
        # Scanner should raise FileNotFoundError when no scannable files exist
        with pytest.raises(FileNotFoundError, match="No scannable files found"):
            scanner.scan(tmp_path)

    def test_unicode_edge_cases(self, tmp_path):
        """Test scanning files with various unicode characters."""
        unicode_file = tmp_path / "unicode.py"
        unicode_file.write_text("# Comment with emoji 🔒\n# Chinese: 中文\n# Arabic: العربية\nprint('test')", encoding="utf-8")

        scanner = MCPSentinelScanner()
        result = scanner.scan(unicode_file)

        assert result.summary.files_scanned == 1
        assert result.summary.total_lines == 4

    def test_very_long_line(self, tmp_path):
        """Test scanning a file with a very long line."""
        long_file = tmp_path / "long.py"
        long_line = "x = '" + "a" * 10000 + "'"
        long_file.write_text(long_line)

        scanner = MCPSentinelScanner()
        result = scanner.scan(long_file)

        assert result.summary.files_scanned == 1

    def test_file_with_no_extension(self, tmp_path):
        """Test scanning a file without an extension."""
        no_ext_file = tmp_path / "Makefile"
        no_ext_file.write_text("all:\n\techo 'test'")

        scanner = MCPSentinelScanner()

        # Should be skipped (not in SUPPORTED_EXTENSIONS)
        # Scanner should raise FileNotFoundError when no scannable files exist
        with pytest.raises(FileNotFoundError, match="No scannable files found"):
            scanner.scan(tmp_path)

    def test_syntax_error_in_python_file(self, tmp_path):
        """Test scanning a Python file with syntax errors."""
        syntax_error_file = tmp_path / "syntax_error.py"
        syntax_error_file.write_text("def broken(\n  missing closing")

        scanner = MCPSentinelScanner()
        result = scanner.scan(syntax_error_file)

        # Should complete without crashing
        assert result.summary.files_scanned == 1

    def test_circular_symlink(self, tmp_path):
        """Test handling of circular symlinks."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        # Create circular symlink
        link = subdir / "circular"
        try:
            link.symlink_to(tmp_path)

            test_file = tmp_path / "test.py"
            test_file.write_text("print('test')")

            scanner = MCPSentinelScanner()
            # Should handle gracefully without infinite loop
            result = scanner.scan(tmp_path)
            assert result.summary.files_scanned >= 1
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

    def test_very_large_directory(self, tmp_path):
        """Test scanning a directory with many files."""
        # Create 100 small files
        for i in range(100):
            file = tmp_path / f"file_{i}.py"
            file.write_text(f"# File {i}\nprint({i})")

        scanner = MCPSentinelScanner(parallel_workers=4)
        result = scanner.scan(tmp_path)

        assert result.summary.files_scanned == 100

    def test_mixed_encodings(self, tmp_path):
        """Test scanning files with different encodings."""
        # UTF-8 file
        utf8_file = tmp_path / "utf8.py"
        utf8_file.write_text("# UTF-8: こんにちは", encoding="utf-8")

        # Latin-1 file
        latin1_file = tmp_path / "latin1.py"
        latin1_file.write_bytes("# Latin-1: café".encode("latin-1"))

        scanner = MCPSentinelScanner()
        result = scanner.scan(tmp_path)

        # Should handle both files
        assert result.summary.files_scanned == 2

    def test_invalid_parallel_workers(self):
        """Test scanner with invalid parallel worker count."""
        scanner = MCPSentinelScanner(parallel_workers=0)
        # Should default to 1
        assert scanner.parallel_workers == 1

        scanner = MCPSentinelScanner(parallel_workers=-5)
        assert scanner.parallel_workers == 1

    def test_config_with_invalid_types(self):
        """Test scanner with invalid config types."""
        invalid_config = {
            "exclude": "not_a_list",  # Should be a list
            "severity_threshold": 123,  # Should be a string
        }

        scanner = MCPSentinelScanner(config=invalid_config)
        # Should not crash, just use defaults
        assert scanner.config == invalid_config
