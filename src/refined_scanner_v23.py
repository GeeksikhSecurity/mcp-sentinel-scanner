#!/usr/bin/env python3
"""Refined MCP Scanner v2.3 with enhanced false positive reduction for config files."""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

from filters.config_filter import ConfigurationFilter
from utils.repo_cloner import RepositoryCloner

@dataclass
class Finding:
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float

class RefinedMCPScanner:
    """Refined scanner with enhanced config file filtering."""
    
    def __init__(self):
        self.config_filter = ConfigurationFilter()
        self.repo_cloner = RepositoryCloner()
        
        # Refined secret patterns
        self.secret_patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'generic_hex32': r'[0-9a-f]{32}',
            'generic_hex40': r'[0-9a-f]{40}',
        }
        
        # Sample key exclusions
        self.sample_exclusions = [
            r'sk-[x]{20,}',  # OpenAI placeholders
            r'ghp_[x]{20,}',  # GitHub placeholders
            r'AKIA[X]{12,}',  # AWS placeholders
            r'your[_-]?key[_-]?here',
            r'replace[_-]?me',
            r'example[_-]?key',
        ]
    
    def scan_repositories_safely(self, repo_urls: List[str]) -> Dict[str, Any]:
        """Safely clone and scan repositories with error handling."""
        print("🔄 Cloning repositories with error handling...")
        clone_results = self.repo_cloner.clone_repositories(repo_urls)
        
        scan_results = []
        for repo in clone_results['successful']:
            result = self.scan_repository(repo['repo_name'])
            scan_results.append(result)
        
        return {
            'clone_summary': {
                'successful': len(clone_results['successful']),
                'failed': len(clone_results['failed']),
                'failed_repos': [r['repo_name'] for r in clone_results['failed']]
            },
            'scan_results': scan_results
        }
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan repository with refined filtering."""
        repo_path = Path(repo_path)
        findings = []
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.json', '.env', '.yaml']:
                findings.extend(self._scan_file(file_path))
        
        # Apply refined filtering
        filtered_findings = self._apply_refined_filtering(findings)
        
        return {
            'repository': repo_path.name,
            'total_findings': len(findings),
            'filtered_findings': len(filtered_findings),
            'reduction_rate': (len(findings) - len(filtered_findings)) / len(findings) * 100 if findings else 0,
            'findings': [self._finding_to_dict(f) for f in filtered_findings]
        }
    
    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan file for secrets with initial detection."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        for pattern_name, pattern in self.secret_patterns.items():
            for match in re.finditer(pattern, content):
                # Skip if matches sample exclusions
                if any(re.search(excl, match.group(), re.IGNORECASE) for excl in self.sample_exclusions):
                    continue
                
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                findings.append(Finding(
                    severity='HIGH',
                    category=f'hardcoded_{pattern_name}',
                    description=f"Potential {pattern_name.replace('_', ' ')} detected",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line_content.strip(),
                    confidence=0.8
                ))
        
        return findings
    
    def _apply_refined_filtering(self, findings: List[Finding]) -> List[Finding]:
        """Apply refined filtering with config file awareness."""
        filtered = []
        
        for finding in findings:
            # Convert to dict for filter processing
            finding_dict = self._finding_to_dict(finding)
            
            # Apply configuration filter
            filtered_finding = self.config_filter.filter_finding(finding_dict)
            
            # Keep findings above threshold
            if filtered_finding['confidence'] >= 0.3:
                # Convert back to Finding object
                finding.confidence = filtered_finding['confidence']
                filtered.append(finding)
        
        return filtered
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'severity': finding.severity,
            'category': finding.category,
            'description': finding.description,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'code_snippet': finding.code_snippet,
            'confidence': finding.confidence
        }

def main():
    """Test the refined scanner."""
    scanner = RefinedMCPScanner()
    
    # Test repositories (mix of existing and non-existing)
    test_repos = [
        'https://github.com/modelcontextprotocol/servers.git',
        'https://github.com/modelcontextprotocol/typescript-sdk.git',
        'https://github.com/blazickjp/mcp-server-time.git',  # May not exist
        'https://github.com/nonexistent/fake-repo.git',      # Definitely doesn't exist
    ]
    
    print("🛡️ Refined MCP Scanner v2.3 - Testing")
    results = scanner.scan_repositories_safely(test_repos)
    
    print(f"\n📊 Clone Results:")
    print(f"✅ Successful: {results['clone_summary']['successful']}")
    print(f"❌ Failed: {results['clone_summary']['failed']}")
    
    if results['clone_summary']['failed_repos']:
        print(f"Failed repos: {', '.join(results['clone_summary']['failed_repos'])}")
    
    print(f"\n🔍 Scan Results: {len(results['scan_results'])} repositories scanned")
    
    return results

if __name__ == '__main__':
    main()