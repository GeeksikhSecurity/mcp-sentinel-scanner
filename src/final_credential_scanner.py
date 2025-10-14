#!/usr/bin/env python3
"""Final Credential Scanner - Only Real Hardcoded Secrets."""

import re
from pathlib import Path
from typing import Dict, List, Any

class FinalCredentialScanner:
    """Ultra-focused scanner for actual hardcoded secrets only."""
    
    def __init__(self):
        # Only high-confidence, specific credential patterns
        self.patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'github_classic': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z-]{10,48}',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        }
    
    def scan_for_secrets(self, repo_path: str) -> Dict[str, Any]:
        """Scan for actual hardcoded secrets with high precision."""
        
        repo_path = Path(repo_path)
        secrets_found = []
        
        for file_path in repo_path.rglob('*.py'):
            # Skip test files completely
            if self._is_test_file(file_path):
                continue
            
            secrets = self._scan_file_for_secrets(file_path)
            secrets_found.extend(secrets)
        
        return {
            'repository': repo_path.name,
            'secrets_detected': len(secrets_found),
            'findings': secrets_found
        }
    
    def _is_test_file(self, file_path: Path) -> bool:
        """Check if file is a test file."""
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in 
                  ['test', 'spec', 'mock', 'fixture', 'demo', 'example'])
    
    def _scan_file_for_secrets(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan file for actual secrets."""
        
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return secrets
        
        # Look for each pattern
        for pattern_name, pattern in self.patterns.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Skip if in comment or docstring
                if self._is_comment_or_docstring(line_content):
                    continue
                
                # Skip if obvious test/example value
                if self._is_test_value(match.group()):
                    continue
                
                secrets.append({
                    'type': pattern_name,
                    'file_path': str(file_path),
                    'line_number': line_num,
                    'code_snippet': line_content.strip(),
                    'secret_value': match.group()[:10] + '...',  # Truncated for safety
                    'confidence': 0.95
                })
        
        return secrets
    
    def _is_comment_or_docstring(self, line: str) -> bool:
        """Check if line is comment or docstring."""
        stripped = line.strip()
        return (stripped.startswith('#') or 
                '"""' in stripped or 
                "'''" in stripped)
    
    def _is_test_value(self, value: str) -> bool:
        """Check if value is obviously a test/example."""
        test_indicators = [
            'test', 'example', 'demo', 'sample', 'fake', 'mock',
            'placeholder', 'your_key', 'replace_me'
        ]
        return any(indicator in value.lower() for indicator in test_indicators)

def main():
    """Test final credential scanner."""
    
    scanner = FinalCredentialScanner()
    
    # Test on modelcontextprotocol-python-sdk
    result = scanner.scan_for_secrets('scans/popular_mcps/modelcontextprotocol-python-sdk')
    
    print(f"🔍 Final Credential Scanner Results:")
    print(f"📁 Repository: {result['repository']}")
    print(f"🚨 Actual secrets detected: {result['secrets_detected']}")
    
    if result['findings']:
        print(f"\n⚠️  REAL HARDCODED SECRETS FOUND:")
        for finding in result['findings']:
            print(f"  🔴 {finding['type']} in {Path(finding['file_path']).name}:{finding['line_number']}")
            print(f"     Value: {finding['secret_value']}")
            print(f"     Code: {finding['code_snippet']}")
            print()
    else:
        print(f"\n✅ No actual hardcoded secrets detected!")
        print(f"   Repository appears to follow secure coding practices.")
    
    return result

if __name__ == '__main__':
    main()