"""Placeholder value filter for documentation and examples."""

import re
from typing import List
from dataclasses import dataclass


@dataclass
class Finding:
    code_snippet: str
    confidence: float


class PlaceholderFilter:
    """Filter obvious placeholder values."""
    
    def __init__(self):
        self.placeholder_patterns = [
            # Generic placeholders
            r'your[-_]?.*[-_]?(key|secret|token|password)',
            r'example[-_]?(key|secret|token|password)',
            r'placeholder[-_]?(key|secret|token|password)',
            r'sample[-_]?(key|secret|token|password)',
            
            # Common test values
            r'(key|secret|token|password)[-_]?(123|test|example|demo)',
            r'abc123|test123|demo123|example123',
            r'xxx+|yyy+|zzz+',
            
            # Documentation patterns
            r'<[A-Z_]+>',  # <API_KEY>
            r'\{[A-Z_]+\}',  # {API_KEY}
            r'\$\{[A-Z_]+\}',  # ${API_KEY}
            
            # Obvious fake values
            r'fake[-_]?(key|secret|token)',
            r'dummy[-_]?(key|secret|token)',
            r'mock[-_]?(key|secret|token)',
            
            # Redacted values
            r'<redacted>|<REDACTED>|\*+|x+',
            r'\.\.\.+|---+|___+',
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.placeholder_patterns]
    
    def is_placeholder(self, code_snippet: str) -> bool:
        """Check if code contains placeholder values."""
        return any(pattern.search(code_snippet) for pattern in self.compiled_patterns)
    
    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter placeholder-related findings."""
        filtered = []
        
        for finding in findings:
            if self.is_placeholder(finding.code_snippet):
                # Massive confidence reduction for placeholders
                finding.confidence *= 0.01  # 99% reduction
            
            # Only keep if above threshold
            if finding.confidence >= 0.3:
                filtered.append(finding)
        
        return filtered