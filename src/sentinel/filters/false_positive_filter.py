#!/usr/bin/env python3
"""
False Positive Filter for MCP Sentinel Scanner
Reduces noise by filtering out demo credentials, test keys, and placeholders
"""

import re
import math
from typing import List, Dict, Any, Optional
from collections import Counter

class FalsePositiveFilter:
    def __init__(self):
        self.test_indicators = [
            'test', 'demo', 'example', 'sample', 'placeholder', 'dummy',
            'fake', 'mock', 'stub', 'template', 'tutorial', 'docs'
        ]
        
        self.placeholder_patterns = [
            r'YOUR_\w+', r'REPLACE_\w+', r'INSERT_\w+', r'ADD_\w+',
            r'PUT_\w+', r'ENTER_\w+', r'SET_\w+', r'CHANGE_\w+'
        ]
        
        self.fake_patterns = [
            r'12345+', r'67890+', r'abcdef+', r'qwerty+', r'password+',
            r'secret+', r'token+', r'key+', r'admin+', r'user+'
        ]
        
        self.test_key_prefixes = [
            'sk_test_', 'pk_test_', 'whsec_test_', 'acct_test_',
            'test_', 'demo_', 'sample_', 'example_'
        ]
        
        self.localhost_patterns = [
            'localhost', '127.0.0.1', '0.0.0.0', 'example.com',
            'test.com', 'demo.com', 'sample.com'
        ]

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def is_sequential_pattern(self, text: str) -> bool:
        """Check if string contains obvious sequential patterns"""
        sequential_patterns = [
            '123456', '654321', 'abcdef', 'fedcba',
            '111111', '000000', 'aaaaaa', 'zzzzzz'
        ]
        
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in sequential_patterns)

    def has_test_indicators(self, credential: str, context: str = "") -> bool:
        """Check for test/demo indicators in credential or context"""
        combined_text = f"{credential} {context}".lower()
        
        # Check for test indicators
        for indicator in self.test_indicators:
            if indicator in combined_text:
                return True
        
        # Check for test key prefixes
        for prefix in self.test_key_prefixes:
            if credential.lower().startswith(prefix):
                return True
        
        return False

    def has_placeholder_patterns(self, credential: str) -> bool:
        """Check for placeholder patterns"""
        for pattern in self.placeholder_patterns:
            if re.search(pattern, credential, re.IGNORECASE):
                return True
        return False

    def has_fake_patterns(self, credential: str) -> bool:
        """Check for obviously fake patterns"""
        credential_lower = credential.lower()
        
        for pattern in self.fake_patterns:
            if re.search(pattern, credential_lower):
                return True
        
        return False

    def has_localhost_indicators(self, credential: str, context: str = "") -> bool:
        """Check for localhost/development indicators"""
        combined_text = f"{credential} {context}".lower()
        
        return any(pattern in combined_text for pattern in self.localhost_patterns)

    def is_realistic_credential_format(self, credential: str, cred_type: str = "") -> bool:
        """Validate credential against known realistic formats"""
        
        # Length checks for different credential types
        length_requirements = {
            'api_key': (16, 64),
            'secret': (20, 128),
            'token': (16, 256),
            'password': (8, 64),
            'client_id': (16, 32)
        }
        
        # Check length
        if cred_type in length_requirements:
            min_len, max_len = length_requirements[cred_type]
            if not (min_len <= len(credential) <= max_len):
                return False
        
        # Check for realistic character distribution
        has_letters = bool(re.search(r'[a-zA-Z]', credential))
        has_numbers = bool(re.search(r'[0-9]', credential))
        
        # Real credentials usually have both letters and numbers
        if len(credential) > 8 and not (has_letters and has_numbers):
            return False
        
        return True

    def is_false_positive(self, credential: str, context: str = "", 
                         file_path: str = "", cred_type: str = "") -> bool:
        """Main false positive detection method"""
        
        # Skip empty credentials
        if not credential or len(credential) < 4:
            return True
        
        # Check entropy (real credentials have higher entropy)
        entropy = self.calculate_entropy(credential)
        if entropy < 2.5:  # Low entropy indicates fake/repetitive patterns
            return True
        
        # Check for sequential patterns
        if self.is_sequential_pattern(credential):
            return True
        
        # Check for test indicators
        if self.has_test_indicators(credential, context):
            return True
        
        # Check for placeholder patterns
        if self.has_placeholder_patterns(credential):
            return True
        
        # Check for fake patterns
        if self.has_fake_patterns(credential):
            return True
        
        # Check for localhost indicators
        if self.has_localhost_indicators(credential, context):
            return True
        
        # Check file path for test indicators
        if file_path:
            test_paths = ['test/', 'tests/', 'spec/', 'demo/', 'example/', 'sample/']
            if any(test_path in file_path.lower() for test_path in test_paths):
                return True
        
        # Check realistic format
        if not self.is_realistic_credential_format(credential, cred_type):
            return True
        
        return False

    def filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter a list of vulnerability findings to remove false positives"""
        filtered_findings = []
        
        for finding in findings:
            credential = finding.get('code_snippet', '')
            context = finding.get('context', '')
            file_path = finding.get('file_path', '')
            vuln_type = finding.get('vulnerability_type', '')
            
            # Extract credential from code snippet if needed
            if 'hardcoded' in vuln_type.lower() or 'credential' in vuln_type.lower():
                # Try to extract the actual credential value
                credential_match = re.search(r'["\']([^"\']{8,})["\']', credential)
                if credential_match:
                    credential = credential_match.group(1)
            
            # Check if it's a false positive
            if not self.is_false_positive(credential, context, file_path):
                # Add confidence score
                finding['confidence_score'] = self.calculate_confidence_score(
                    credential, context, file_path, vuln_type
                )
                filtered_findings.append(finding)
        
        return filtered_findings

    def calculate_confidence_score(self, credential: str, context: str, 
                                 file_path: str, vuln_type: str) -> float:
        """Calculate confidence score for a finding (0.0 to 1.0)"""
        score = 0.5  # Base score
        
        # Entropy bonus
        entropy = self.calculate_entropy(credential)
        if entropy > 4.0:
            score += 0.2
        elif entropy > 3.0:
            score += 0.1
        
        # Length bonus for realistic credentials
        if 16 <= len(credential) <= 64:
            score += 0.1
        
        # Production context bonus
        if 'production' in context.lower() or 'prod' in context.lower():
            score += 0.1
        
        # Real domain bonus
        if re.search(r'[a-zA-Z0-9-]+\.(com|org|net|io)', context):
            score += 0.1
        
        # File path context
        if not any(test_path in file_path.lower() 
                  for test_path in ['test', 'demo', 'example']):
            score += 0.1
        
        return min(1.0, max(0.0, score))

# Integration with existing scanner
def apply_false_positive_filter(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply false positive filtering to scanner results"""
    filter_instance = FalsePositiveFilter()
    return filter_instance.filter_findings(findings)

if __name__ == "__main__":
    # Test the filter
    test_findings = [
        {
            'code_snippet': 'API_KEY = "production_client_12345"',
            'vulnerability_type': 'Hardcoded Credentials',
            'file_path': 'config/demo.js',
            'context': 'demo configuration file'
        },
        {
            'code_snippet': 'SECRET = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
            'vulnerability_type': 'Hardcoded Credentials', 
            'file_path': 'src/auth.py',
            'context': 'production authentication module'
        }
    ]
    
    filter_instance = FalsePositiveFilter()
    filtered = filter_instance.filter_findings(test_findings)
    
    print(f"Original findings: {len(test_findings)}")
    print(f"After filtering: {len(filtered)}")
    for finding in filtered:
        print(f"Confidence: {finding['confidence_score']:.2f} - {finding['code_snippet']}")