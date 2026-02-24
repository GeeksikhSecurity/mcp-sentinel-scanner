"""Tests for flaky test management functionality"""

import pytest
from datetime import datetime
from src.test_reliability import FlakyTestManager, FlakyTestConfig, ScanTestResult


class TestFlakyTestManager:
    
    def setup_method(self):
        self.config = FlakyTestConfig(
            detection_enabled=True,
            auto_quarantine=True,
            max_retries=2
        )
        self.manager = FlakyTestManager(self.config)
    
    def test_should_execute_non_quarantined_test(self):
        assert self.manager.should_execute_test("test_security_scan")
    
    def test_quarantine_test(self):
        self.manager.quarantine_test("flaky_test")
        assert not self.manager.should_execute_test("flaky_test")
        assert "flaky_test" in self.manager.get_quarantined_tests()
    
    def test_release_from_quarantine(self):
        self.manager.quarantine_test("test_name")
        assert self.manager.release_from_quarantine("test_name")
        assert self.manager.should_execute_test("test_name")
    
    def test_flaky_detection_with_mixed_results(self):
        # Add mixed pass/fail results
        for i in range(10):
            status = 'pass' if i % 2 == 0 else 'fail'
            result = ScanTestResult(
                id=f"test_{i}",
                name="mixed_test",
                status=status,
                duration=1.0,
                timestamp=datetime.now().isoformat(),
                build_id=f"build_{i}",
                environment="test"
            )
            self.manager.add_test_result(result)
        
        # Should detect as flaky due to mixed results
        flaky_tests = self.manager.detect_flaky_tests([])
        assert "mixed_test" in flaky_tests
    
    def test_stable_test_not_detected_as_flaky(self):
        # Add only passing results
        for i in range(10):
            result = ScanTestResult(
                id=f"test_{i}",
                name="stable_test",
                status='pass',
                duration=1.0,
                timestamp=datetime.now().isoformat(),
                build_id=f"build_{i}",
                environment="test"
            )
            self.manager.add_test_result(result)
        
        flaky_tests = self.manager.detect_flaky_tests([])
        assert "stable_test" not in flaky_tests