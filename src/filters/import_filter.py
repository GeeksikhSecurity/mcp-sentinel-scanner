"""Import statement filter for path traversal false positives."""

import re
from typing import List
from dataclasses import dataclass


@dataclass
class Finding:
    code_snippet: str
    confidence: float
    category: str


class ImportFilter:
    """Filter import-related path traversal false positives."""
    
    def __init__(self):
        self.import_patterns = [
            r'^\s*import\s+.*from\s+[\'"].*[\'"]',
            r'^\s*from\s+[\'"].*[\'"].*import',
            r'^\s*import\s+[\'"].*[\'"]',
            r'^\s*require\s*\([\'"].*[\'"]\)',
            r'^\s*#include\s+[\'"].*[\'"]',
        ]
        
        self.compiled_patterns = [re.compile(p, re.MULTILINE) for p in self.import_patterns]
    
    def is_import_statement(self, code_snippet: str) -> bool:
        """Check if code is an import statement."""
        stripped = code_snippet.strip()
        return any(pattern.match(stripped) for pattern in self.compiled_patterns)
    
    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter import-related path traversal findings."""
        filtered = []
        
        for finding in findings:
            # Only apply to path traversal findings
            if finding.category == 'path_traversal' and self.is_import_statement(finding.code_snippet):
                # Massive confidence reduction for import statements
                finding.confidence *= 0.02  # 98% reduction
            
            # Only keep if above threshold
            if finding.confidence >= 0.3:
                filtered.append(finding)
        
        return filtered