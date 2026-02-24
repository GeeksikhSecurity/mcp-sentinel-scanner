"""
Result anonymizer for safe GitHub commits.
Removes sensitive paths and code snippets while preserving security analysis.
"""

import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Any


class ResultAnonymizer:
    """Anonymizes scan results for safe public sharing."""
    
    def __init__(self):
        self.path_mapping = {}
        self.code_mapping = {}
        
    def anonymize_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize complete scan results."""
        anonymized = results.copy()
        
        # Anonymize findings
        if 'findings' in anonymized:
            anonymized['findings'] = [
                self._anonymize_finding(finding) 
                for finding in anonymized['findings']
            ]
            
        # Anonymize scan summary paths
        if 'scan_summary' in anonymized:
            anonymized['scan_summary'] = self._anonymize_summary(
                anonymized['scan_summary']
            )
            
        return anonymized
    
    def _anonymize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize individual finding."""
        anonymized = finding.copy()
        
        # Anonymize file path
        if 'file_path' in anonymized:
            anonymized['file_path'] = self._anonymize_path(anonymized['file_path'])
            
        # Anonymize code snippet
        if 'code_snippet' in anonymized:
            anonymized['code_snippet'] = self._anonymize_code(
                anonymized['code_snippet']
            )
            
        return anonymized
    
    def _anonymize_path(self, file_path: str) -> str:
        """Convert file path to anonymous format."""
        if file_path in self.path_mapping:
            return self.path_mapping[file_path]
            
        # Extract components
        path_obj = Path(file_path)
        parts = path_obj.parts
        
        # Generate anonymous path
        anonymous_parts = []
        for i, part in enumerate(parts):
            if i == 0:  # Root
                anonymous_parts.append('/anonymous')
            elif part in ['src', 'lib', 'app', 'components']:
                anonymous_parts.append(part)
            elif part.endswith('.py'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.py')
            elif part.endswith('.js'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.js')
            elif part.endswith('.ts'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.ts')
            else:
                anonymous_parts.append(f'dir_{self._hash_string(part)[:8]}')
                
        anonymous_path = '/'.join(anonymous_parts)
        self.path_mapping[file_path] = anonymous_path
        return anonymous_path
    
    def _anonymize_code(self, code_snippet: str) -> str:
        """Anonymize code snippet while preserving vulnerability pattern."""
        if code_snippet in self.code_mapping:
            return self.code_mapping[code_snippet]
            
        anonymized = code_snippet
        
        # Replace sensitive patterns
        patterns = [
            (r'client_secret="[^"]*"', 'client_secret="<REDACTED>"'),
            (r'api_key="[^"]*"', 'api_key="<REDACTED>"'),
            (r'password="[^"]*"', 'password="<REDACTED>"'),
            (r'token="[^"]*"', 'token="<REDACTED>"'),
            (r'/home/[^/\s]*', '/home/<USER>'),
            (r'/Users/[^/\s]*', '/Users/<USER>'),
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '<EMAIL>'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP_ADDRESS>'),
        ]
        
        for pattern, replacement in patterns:
            anonymized = re.sub(pattern, replacement, anonymized)
            
        self.code_mapping[code_snippet] = anonymized
        return anonymized
    
    def _anonymize_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize scan summary."""
        anonymized = summary.copy()
        
        # Remove or anonymize sensitive summary data
        if 'scan_path' in anonymized:
            anonymized['scan_path'] = '/anonymous/project'
            
        return anonymized
    
    def _hash_string(self, text: str) -> str:
        """Generate consistent hash for string."""
        return hashlib.md5(text.encode()).hexdigest()


def anonymize_results_file(input_file: str, output_file: str) -> None:
    """Anonymize results file for safe sharing."""
    anonymizer = ResultAnonymizer()
    
    with open(input_file, 'r') as f:
        results = json.load(f)
        
    anonymized = anonymizer.anonymize_scan_results(results)
    
    with open(output_file, 'w') as f:
        json.dump(anonymized, f, indent=2)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python result_anonymizer.py <input_file> <output_file>")
        sys.exit(1)
        
    anonymize_results_file(sys.argv[1], sys.argv[2])