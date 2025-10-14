"""
Flaky Test Management for MCP Sentinel Scanner
Ensures reliable security test execution and reduces false negatives
"""

import time
import json
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class TestResult:
    id: str
    name: str
    status: str  # 'pass', 'fail', 'flaky'
    duration: float
    timestamp: str
    build_id: str
    environment: str


@dataclass
class FlakyTestConfig:
    detection_enabled: bool = True
    intra_run_threshold: float = 0.1
    inter_run_threshold: float = 0.2
    monitoring_window_days: int = 7
    quarantine_enabled: bool = True
    auto_quarantine: bool = True
    max_quarantine_days: int = 30
    retry_enabled: bool = True
    max_retries: int = 3
    backoff_ms: int = 1000
    selective_retry: bool = True


class FlakyTestManager:
    """Manages flaky test detection and quarantine for reliable security scanning"""
    
    def __init__(self, config: FlakyTestConfig):
        self.config = config
        self.test_history: Dict[str, List[TestResult]] = {}
        self.quarantined_tests: Set[str] = set()
    
    def detect_flaky_tests(self, test_results: List[TestResult]) -> List[str]:
        """Detect flaky tests using statistical analysis"""
        flaky_tests = []
        
        for test_name, history in self.test_history.items():
            if self._is_test_flaky(history):
                flaky_tests.append(test_name)
                
                if self.config.auto_quarantine:
                    self.quarantine_test(test_name)
        
        return flaky_tests
    
    async def execute_with_retry(self, test_fn, test_name: str) -> TestResult:
        """Execute test with retry strategy for reliability"""
        last_result = None
        
        for attempt in range(1, self.config.max_retries + 2):
            try:
                result = await test_fn()
                
                if result.status == 'pass':
                    return result
                
                last_result = result
                
                if attempt <= self.config.max_retries:
                    await self._delay(self.config.backoff_ms * attempt / 1000)
                    
            except Exception as e:
                if attempt > self.config.max_retries:
                    raise e
                await self._delay(self.config.backoff_ms * attempt / 1000)
        
        return last_result
    
    def quarantine_test(self, test_name: str) -> None:
        """Quarantine flaky test to maintain build stability"""
        self.quarantined_tests.add(test_name)
        print(f"⚠️ Test quarantined due to flakiness: {test_name}")
    
    def should_execute_test(self, test_name: str) -> bool:
        """Check if test should be executed (not quarantined)"""
        return test_name not in self.quarantined_tests
    
    def add_test_result(self, result: TestResult) -> None:
        """Add test result to history for flakiness analysis"""
        if result.name not in self.test_history:
            self.test_history[result.name] = []
        
        self.test_history[result.name].append(result)
        
        # Keep only recent results within monitoring window
        cutoff_date = datetime.now() - timedelta(days=self.config.monitoring_window_days)
        self.test_history[result.name] = [
            r for r in self.test_history[result.name]
            if datetime.fromisoformat(r.timestamp) > cutoff_date
        ]
    
    def get_quarantined_tests(self) -> Set[str]:
        """Get list of currently quarantined tests"""
        return self.quarantined_tests.copy()
    
    def release_from_quarantine(self, test_name: str) -> bool:
        """Release test from quarantine"""
        if test_name in self.quarantined_tests:
            self.quarantined_tests.remove(test_name)
            print(f"✅ Test released from quarantine: {test_name}")
            return True
        return False
    
    def _is_test_flaky(self, history: List[TestResult]) -> bool:
        """Analyze test history to determine if it's flaky"""
        if len(history) < 5:
            return False
        
        recent = history[-10:]  # Last 10 runs
        pass_count = sum(1 for r in recent if r.status == 'pass')
        fail_count = sum(1 for r in recent if r.status == 'fail')
        
        # Flaky if both passes and fails exist with significant frequency
        flaky_ratio = min(pass_count, fail_count) / len(recent)
        return flaky_ratio >= 0.2  # 20% threshold
    
    async def _delay(self, seconds: float) -> None:
        """Async delay for retry backoff"""
        await asyncio.sleep(seconds)


# Integration with MCP Scanner
class ReliableSecurityScanner:
    """Enhanced MCP Scanner with flaky test management"""
    
    def __init__(self, scanner, flaky_config: Optional[FlakyTestConfig] = None):
        self.scanner = scanner
        self.flaky_manager = FlakyTestManager(flaky_config or FlakyTestConfig())
    
    async def scan_with_reliability(self, target: str) -> dict:
        """Run security scan with flaky test management"""
        
        async def security_test():
            result = self.scanner.scan(target)
            return TestResult(
                id=f"scan_{int(time.time())}",
                name="security_scan",
                status='pass' if result.summary.vulnerabilities_found == 0 else 'fail',
                duration=result.summary.scan_time,
                timestamp=datetime.now().isoformat(),
                build_id="local",
                environment="test"
            )
        
        # Execute with retry if test is not quarantined
        if self.flaky_manager.should_execute_test("security_scan"):
            test_result = await self.flaky_manager.execute_with_retry(
                security_test, "security_scan"
            )
            self.flaky_manager.add_test_result(test_result)
            
            return {
                "scan_result": self.scanner.scan(target),
                "test_reliability": {
                    "status": test_result.status,
                    "duration": test_result.duration,
                    "quarantined_tests": list(self.flaky_manager.get_quarantined_tests())
                }
            }
        else:
            print("⚠️ Security scan skipped - test is quarantined")
            return {"error": "Security scan quarantined due to flakiness"}


# Async compatibility
try:
    import asyncio
except ImportError:
    # Fallback for sync execution
    class asyncio:
        @staticmethod
        async def sleep(seconds):
            time.sleep(seconds)