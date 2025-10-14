#!/usr/bin/env python3
"""Improved MCP Scanner v2.4 with Enhanced False Positive Reduction."""

import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class Finding:
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    context: str = "production"

class ImprovedMCPScanner:
    """Enhanced scanner focusing on actual hardcoded credentials."""
    
    def __init__(self):
        # Real credential patterns (high entropy, specific formats)
        self.credential_patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'generic_api_key': r'[a-zA-Z0-9]{32,}',
        }
        
        # Documentation/example exclusions
        self.doc_exclusions = [
            r'username="user"',
            r'password="pass"',
            r'token="<.*?>"',
            r'key="<.*?>"',
            r'secret="<.*?>"',
            r'your[_-]?key[_-]?here',
            r'replace[_-]?me',
            r'example[_-]?key',
        ]
        
        # Context indicators
        self.test_indicators = ['test', 'spec', 'mock', 'fixture', 'demo']
        self.doc_indicators = ['example', 'tutorial', 'guide', 'readme', 'docs']
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan file for actual hardcoded credentials."""
        
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        # Skip if file is clearly documentation
        if self._is_documentation_file(file_path):
            return findings
        
        for pattern_name, pattern in self.credential_patterns.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Skip if matches exclusion patterns
                if self._is_excluded_pattern(match.group()):
                    continue
                
                # Determine context
                context = self._determine_context(file_path, line_content)
                
                # Calculate confidence based on context and pattern
                confidence = self._calculate_confidence(pattern_name, context, line_content)
                
                # Only include high-confidence findings
                if confidence >= 0.7:
                    findings.append(Finding(
                        severity='HIGH',
                        category=f'hardcoded_{pattern_name}',
                        description=f'Actual {pattern_name.replace("_", " ")} detected',
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line_content.strip(),
                        confidence=confidence,
                        context=context
                    ))
        
        return findings
    
    def _is_documentation_file(self, file_path: Path) -> bool:
        """Check if file is documentation."""
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in self.doc_indicators)
    
    def _is_excluded_pattern(self, credential: str) -> bool:
        """Check if credential matches exclusion patterns."""
        return any(re.search(pattern, credential, re.IGNORECASE) 
                  for pattern in self.doc_exclusions)
    
    def _determine_context(self, file_path: Path, line_content: str) -> str:
        """Determine if finding is in test, doc, or production context."""
        
        path_str = str(file_path).lower()
        
        # Check for test context
        if any(indicator in path_str for indicator in self.test_indicators):
            return "test"
        
        # Check for documentation context
        if any(indicator in path_str for indicator in self.doc_indicators):
            return "documentation"
        
        # Check for docstring context
        if '"""' in line_content or "'''" in line_content:
            return "documentation"
        
        return "production"
    
    def _calculate_confidence(self, pattern_name: str, context: str, line_content: str) -> float:
        """Calculate confidence score based on multiple factors."""
        
        base_confidence = 0.8
        
        # Adjust based on context
        if context == "test":
            base_confidence *= 0.3
        elif context == "documentation":
            base_confidence *= 0.1
        
        # Adjust based on pattern specificity
        if pattern_name in ['github_token', 'openai_key', 'aws_access_key']:
            base_confidence *= 1.2  # High specificity
        elif pattern_name == 'jwt_token':
            base_confidence *= 1.1
        else:
            base_confidence *= 0.9  # Generic patterns
        
        # Check for variable assignment (higher confidence)
        if '=' in line_content and not line_content.strip().startswith('#'):
            base_confidence *= 1.1
        
        return min(base_confidence, 1.0)
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan repository with improved false positive reduction."""
        
        repo_path = Path(repo_path)
        all_findings = []
        
        # Scan Python files
        for file_path in repo_path.rglob('*.py'):
            findings = self.scan_file(file_path)
            all_findings.extend(findings)
        
        # Filter by confidence and context
        production_findings = [
            f for f in all_findings 
            if f.context == "production" and f.confidence >= 0.7
        ]
        
        return {
            'repository': repo_path.name,
            'total_findings': len(all_findings),
            'production_findings': len(production_findings),
            'findings': [self._finding_to_dict(f) for f in production_findings],
            'false_positive_rate': (len(all_findings) - len(production_findings)) / len(all_findings) * 100 if all_findings else 0
        }
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'severity': finding.severity,
            'category': finding.category,
            'description': finding.description,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'code_snippet': finding.code_snippet,
            'confidence': finding.confidence,
            'context': finding.context
        }

def main():
    """Test improved scanner."""
    scanner = ImprovedMCPScanner()
    
    # Test on the problematic repository
    result = scanner.scan_repository('scans/popular_mcps/modelcontextprotocol-python-sdk')
    
    print(f"🛡️ Improved Scanner v2.4 Results:")
    print(f"📁 Repository: {result['repository']}")
    print(f"🔍 Total findings: {result['total_findings']}")
    print(f"🚨 Production findings: {result['production_findings']}")
    print(f"📈 False positive rate: {result['false_positive_rate']:.1f}%")
    
    if result['findings']:
        print(f"\n🎯 Production Findings:")
        for finding in result['findings']:
            print(f"  • {finding['category']} in {Path(finding['file_path']).name}:{finding['line_number']}")
            print(f"    Confidence: {finding['confidence']:.2f}")
    
    return result

if __name__ == '__main__':
    main()