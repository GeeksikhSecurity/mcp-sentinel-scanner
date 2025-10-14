#!/usr/bin/env python3
"""Enhanced False Positive Reducer for Documentation Examples."""

import re
from typing import Dict, Any, List

class EnhancedFalsePositiveReducer:
    """Advanced false positive reduction focusing on documentation examples."""
    
    def __init__(self):
        # Documentation context patterns
        self.docstring_patterns = [
            r'""".*?"""',  # Triple-quoted docstrings
            r"'''.*?'''",  # Single-quoted docstrings
            r'# Example:',  # Example comments
            r'# Usage:',    # Usage comments
        ]
        
        # Placeholder credential patterns
        self.placeholder_patterns = [
            r'username="user"',
            r'password="pass"',
            r'username="<.*?>"',
            r'password="<.*?>"',
            r'token="<.*?>"',
            r'key="<.*?>"',
            r'secret="<.*?>"',
        ]
        
        # Documentation file indicators
        self.doc_indicators = [
            'example', 'demo', 'tutorial', 'guide', 'readme',
            'docs', 'documentation', 'sample'
        ]
    
    def is_documentation_example(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is in documentation/example context."""
        
        file_path = finding.get('file_path', '').lower()
        code_snippet = finding.get('code_snippet', '')
        
        # Check if in documentation file
        if any(indicator in file_path for indicator in self.doc_indicators):
            return True
        
        # Check for placeholder patterns
        if any(re.search(pattern, code_snippet, re.IGNORECASE) 
               for pattern in self.placeholder_patterns):
            return True
        
        # Check if within docstring context (simplified)
        if '"""' in code_snippet or "'''" in code_snippet:
            return True
        
        return False
    
    def reduce_false_positives(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out documentation examples from findings."""
        
        filtered_findings = []
        
        for finding in findings:
            if not self.is_documentation_example(finding):
                filtered_findings.append(finding)
            else:
                # Mark as documentation example
                finding['fp_reason'] = 'documentation_example'
                finding['confidence'] *= 0.1  # Reduce confidence by 90%
        
        return filtered_findings