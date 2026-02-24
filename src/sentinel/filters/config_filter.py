"""Configuration file filter for reducing false positives in sample keys and documentation."""

import re
from pathlib import Path
from typing import List, Dict, Any

class ConfigurationFilter:
    """Filter for configuration files and documentation examples."""
    
    def __init__(self):
        # Sample/example key patterns commonly found in documentation
        self.sample_key_patterns = [
            r'your[_-]?key[_-]?here',
            r'replace[_-]?me',
            r'example[_-]?key',
            r'sample[_-]?key',
            r'demo[_-]?key',
            r'test[_-]?key',
            r'placeholder',
            r'todo[_-]?replace',
            r'insert[_-]?key',
            r'add[_-]?your[_-]?key',
            r'sk-[x]{20,}',  # OpenAI placeholder keys
            r'ghp_[x]{20,}',  # GitHub placeholder tokens
            r'AKIA[X]{12,}',  # AWS placeholder keys
            r'AIza[X]{20,}',  # Google placeholder keys
            r'[0-9a-f]{32}',  # Generic hex that's all same digit
            r'[0-9a-f]{40}',  # Generic hex that's all same digit
        ]
        
        # Configuration file indicators
        self.config_file_patterns = [
            'config', 'settings', 'env', 'environment', '.env',
            'configuration', 'setup', 'default', 'template',
            'example', 'sample', 'demo'
        ]
        
        # Documentation file patterns
        self.doc_file_patterns = [
            'readme', 'docs', 'documentation', 'guide', 'tutorial',
            'example', 'sample', 'demo', 'howto', 'getting-started'
        ]
        
        # Common placeholder values
        self.placeholder_values = {
            'sk-1234567890abcdef1234567890abcdef12345678',  # OpenAI example
            'ghp_1234567890abcdef1234567890abcdef123456',   # GitHub example
            'AKIAIOSFODNN7EXAMPLE',                         # AWS example
            'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',      # Google example
            '12345678901234567890123456789012',             # Generic 32-char
            '1234567890123456789012345678901234567890',     # Generic 40-char
            'abcdef1234567890abcdef1234567890abcdef12',     # Mixed hex example
        }
    
    def is_config_file(self, file_path: str) -> bool:
        """Check if file is a configuration file."""
        path_lower = file_path.lower()
        return any(pattern in path_lower for pattern in self.config_file_patterns)
    
    def is_documentation_file(self, file_path: str) -> bool:
        """Check if file is documentation."""
        path_lower = file_path.lower()
        return any(pattern in path_lower for pattern in self.doc_file_patterns)
    
    def is_sample_key(self, key_value: str, context: str = "") -> bool:
        """Check if a key appears to be a sample/placeholder."""
        key_lower = key_value.lower()
        context_lower = context.lower()
        
        # Check for explicit sample patterns
        for pattern in self.sample_key_patterns:
            if re.search(pattern, key_lower):
                return True
        
        # Check for known placeholder values
        if key_value in self.placeholder_values:
            return True
        
        # Check for repetitive patterns (likely placeholders)
        if self._is_repetitive_pattern(key_value):
            return True
        
        # Check context for sample indicators
        sample_context_indicators = [
            'example', 'sample', 'demo', 'placeholder', 'replace',
            'your_key', 'insert', 'todo', 'template'
        ]
        if any(indicator in context_lower for indicator in sample_context_indicators):
            return True
        
        return False
    
    def _is_repetitive_pattern(self, value: str) -> bool:
        """Check if value has repetitive patterns indicating it's a placeholder."""
        # All same character
        if len(set(value)) <= 2 and len(value) > 10:
            return True
        
        # Sequential patterns
        if re.match(r'^(123|abc|xyz|000|111|aaa|xxx)+', value.lower()):
            return True
        
        # Alternating patterns
        if re.match(r'^([a-z0-9])\1*$', value.lower()) and len(value) > 8:
            return True
        
        return False
    
    def filter_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Apply configuration-specific filtering to a finding."""
        file_path = finding.get('file_path', '')
        code_snippet = finding.get('code_snippet', '')
        category = finding.get('category', '')
        
        # Extract potential key value from code snippet
        key_value = self._extract_key_value(code_snippet)
        
        # Apply filters
        confidence_multiplier = 1.0
        
        # Configuration file reduction
        if self.is_config_file(file_path):
            confidence_multiplier *= 0.3  # 70% reduction
        
        # Documentation file reduction
        if self.is_documentation_file(file_path):
            confidence_multiplier *= 0.1  # 90% reduction
        
        # Sample key detection
        if key_value and self.is_sample_key(key_value, code_snippet):
            confidence_multiplier *= 0.05  # 95% reduction
        
        # Apply multiplier
        finding['confidence'] = finding.get('confidence', 1.0) * confidence_multiplier
        
        # Add context information
        finding['filter_context'] = {
            'is_config_file': self.is_config_file(file_path),
            'is_documentation': self.is_documentation_file(file_path),
            'is_sample_key': key_value and self.is_sample_key(key_value, code_snippet),
            'confidence_reduction': 1.0 - confidence_multiplier
        }
        
        return finding
    
    def _extract_key_value(self, code_snippet: str) -> str:
        """Extract potential key value from code snippet."""
        # Common patterns for key assignment
        patterns = [
            r'["\']([^"\']{20,})["\']',  # Quoted strings
            r'=\s*([a-zA-Z0-9_-]{20,})',  # Assignment
            r':\s*["\']([^"\']{20,})["\']',  # JSON/YAML style
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code_snippet)
            if match:
                return match.group(1)
        
        return ""