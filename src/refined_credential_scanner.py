#!/usr/bin/env python3
"""Refined Credential Scanner - Focus on Real Secrets Only."""

import re
from pathlib import Path
from typing import Dict, List, Any

class RefinedCredentialScanner:
    """Scanner focused exclusively on real hardcoded credentials."""
    
    def __init__(self):
        # High-confidence credential patterns only
        self.real_credential_patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'github_classic': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret': r'[A-Za-z0-9/+=]{40}',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'api_key_pattern': r'["\']([a-zA-Z0-9]{32,})["\']',
        }
        
        # Exclude common false positives
        self.exclusions = [
            r'github\.com/.*blob/[a-f0-9]{40}',  # GitHub URLs
            r'modelcontextprotocol/blob/[a-f0-9]{40}',  # MCP spec URLs
            r'username="user"',
            r'password="pass"',
            r'token="test',
            r'key="test',
            r'secret="test',
            r'[a-f0-9]{40}',  # Generic hex (likely commit hashes)
            r'[a-f0-9]{32}',  # Generic hex
        ]
    
    def scan_for_real_credentials(self, repo_path: str) -> Dict[str, Any]:
        """Scan for actual hardcoded credentials only."""
        
        repo_path = Path(repo_path)
        real_findings = []
        
        for file_path in repo_path.rglob('*.py'):
            # Skip test files
            if any(test in str(file_path).lower() for test in ['test', 'spec', 'mock']):
                continue
            
            findings = self._scan_file(file_path)
            real_findings.extend(findings)
        
        return {
            'repository': repo_path.name,
            'real_credentials': len(real_findings),
            'findings': real_findings
        }
    
    def _scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan individual file for real credentials."""
        
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        # Look for actual credential assignments
        for line_num, line in enumerate(lines, 1):
            # Skip comments and docstrings
            if line.strip().startswith('#') or '"""' in line or "'''" in line:
                continue
            
            # Look for variable assignments with credentials
            if '=' in line and any(keyword in line.lower() for keyword in 
                                 ['password', 'secret', 'token', 'key', 'auth']):
                
                # Extract potential credential value
                credential = self._extract_credential_value(line)
                if credential and self._is_real_credential(credential):
                    findings.append({
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'code_snippet': line.strip(),
                        'credential_type': self._identify_credential_type(credential),
                        'confidence': 0.9
                    })
        
        return findings
    
    def _extract_credential_value(self, line: str) -> str:
        """Extract credential value from assignment line."""
        
        # Look for quoted strings
        patterns = [
            r'["\']([^"\']{20,})["\']',  # Quoted strings 20+ chars
            r'=\s*([A-Za-z0-9+/=]{32,})',  # Unquoted alphanumeric 32+ chars
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return ""
    
    def _is_real_credential(self, credential: str) -> bool:
        """Check if credential appears to be real (not test/example)."""
        
        # Exclude obvious test/example values
        test_indicators = [
            'test', 'example', 'demo', 'sample', 'placeholder',
            'your_key', 'replace_me', 'insert_key'
        ]
        
        if any(indicator in credential.lower() for indicator in test_indicators):
            return False
        
        # Exclude common false positives
        for exclusion in self.exclusions:
            if re.search(exclusion, credential, re.IGNORECASE):
                return False
        
        # Must have sufficient entropy and length
        if len(credential) < 20:
            return False
        
        # Check for reasonable entropy (not all same character)
        if len(set(credential)) < 5:
            return False
        
        return True
    
    def _identify_credential_type(self, credential: str) -> str:
        """Identify the type of credential."""
        
        if credential.startswith('ghp_'):
            return 'github_token'
        elif credential.startswith('sk-'):
            return 'openai_key'
        elif credential.startswith('AKIA'):
            return 'aws_access_key'
        elif credential.startswith('eyJ'):
            return 'jwt_token'
        else:
            return 'generic_credential'

def main():
    """Test refined credential scanner."""
    
    scanner = RefinedCredentialScanner()
    
    # Test on the problematic repository
    result = scanner.scan_for_real_credentials('scans/popular_mcps/modelcontextprotocol-python-sdk')
    
    print(f"🔍 Refined Credential Scanner Results:")
    print(f"📁 Repository: {result['repository']}")
    print(f"🚨 Real credentials found: {result['real_credentials']}")
    
    if result['findings']:
        print(f"\n⚠️  ACTUAL CREDENTIALS DETECTED:")
        for finding in result['findings']:
            print(f"  🔴 {finding['credential_type']} in {Path(finding['file_path']).name}:{finding['line_number']}")
            print(f"     Code: {finding['code_snippet']}")
            print(f"     Confidence: {finding['confidence']}")
    else:
        print(f"\n✅ No real hardcoded credentials detected!")
    
    return result

if __name__ == '__main__':
    main()