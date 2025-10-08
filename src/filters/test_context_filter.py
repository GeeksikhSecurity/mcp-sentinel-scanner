"""Test context filter for false positive reduction."""

import re
from pathlib import Path
from typing import List, Set
from dataclasses import dataclass


@dataclass
class Finding:
    file_path: str
    code_snippet: str
    confidence: float
    category: str


class TestContextFilter:
    """Aggressive test context detection and filtering."""
    
    def __init__(self):
        self.test_path_patterns = {
            'test', 'tests', '__tests__', 'spec', 'specs',
            'test_', '_test', '.test.', '.spec.',
            'testing', 'fixtures', 'mocks', 'stubs'
        }
        
        self.test_value_patterns = [
            r'test[-_]?secret', r'mock[-_]?secret', r'dummy[-_]?key',
            r'example[-_]?key', r'placeholder', r'your[-_]?.*[-_]?(key|secret)',
            r'abc123', r'test123', r'secret123', r'key123',
            r'fake[-_]?token', r'sample[-_]?key', r'demo[-_]?secret'
        ]
        
        self.test_frameworks = {
            'pytest', 'unittest', 'jest', 'mocha', 'jasmine',
            'describe(', 'it(', 'test(', 'expect(', 'assert',
            '@patch', '@mock', 'mock.', 'stub.'
        }
    
    def is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file."""
        path_lower = file_path.lower()
        return any(pattern in path_lower for pattern in self.test_path_patterns)
    
    def is_test_value(self, code_snippet: str) -> bool:
        """Check if code contains test values."""
        code_lower = code_snippet.lower()
        return any(re.search(pattern, code_lower) for pattern in self.test_value_patterns)
    
    def has_test_framework_indicators(self, code_snippet: str) -> bool:
        """Check for test framework indicators."""
        return any(indicator in code_snippet for indicator in self.test_frameworks)
    
    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter out test-related false positives."""
        filtered = []
        
        for finding in findings:
            confidence_penalty = 1.0
            
            # Test file penalty
            if self.is_test_file(finding.file_path):
                confidence_penalty *= 0.05  # 95% reduction
            
            # Test value penalty
            if self.is_test_value(finding.code_snippet):
                confidence_penalty *= 0.05  # 95% reduction
            
            # Test framework penalty
            if self.has_test_framework_indicators(finding.code_snippet):
                confidence_penalty *= 0.1   # 90% reduction
            
            # Apply penalty
            new_confidence = finding.confidence * confidence_penalty
            
            # Only keep if confidence above threshold
            if new_confidence >= 0.3:
                finding.confidence = new_confidence
                filtered.append(finding)
        
        return filtered