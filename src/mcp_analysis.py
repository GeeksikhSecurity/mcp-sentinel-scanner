#!/usr/bin/env python3
"""Comprehensive MCP Repository Analysis Script."""

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
import hashlib

@dataclass
class SecurityFinding:
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    is_api_key: bool = False

class MCPAnalyzer:
    """Comprehensive MCP repository analyzer."""
    
    def __init__(self):
        self.api_key_patterns = [
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI API keys
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub personal access tokens
            r'gho_[a-zA-Z0-9]{36}',  # GitHub OAuth tokens
            r'ghu_[a-zA-Z0-9]{36}',  # GitHub user tokens
            r'ghs_[a-zA-Z0-9]{36}',  # GitHub server tokens
            r'ghr_[a-zA-Z0-9]{36}',  # GitHub refresh tokens
            r'AKIA[0-9A-Z]{16}',     # AWS Access Key ID
            r'AIza[0-9A-Za-z\\-_]{35}',  # Google API Key
            r'ya29\.[0-9A-Za-z\\-_]+',   # Google OAuth Access Token
            r'[0-9a-f]{32}',         # Generic 32-char hex (MD5-like)
            r'[0-9a-f]{40}',         # Generic 40-char hex (SHA1-like)
            r'[0-9a-f]{64}',         # Generic 64-char hex (SHA256-like)
        ]
        
        self.secret_keywords = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'auth', 'credential', 'private_key', 'access_token'
        ]
        
        self.vulnerability_patterns = {
            'command_injection': [
                r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
                r'os\.system\s*\(',
                r'exec\s*\(',
                r'eval\s*\('
            ],
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'SELECT.*\+.*FROM'
            ],
            'path_traversal': [
                r'\.\./.*\.\.',
                r'\.\.[\\/]',
                r'path.*\.\.'
            ],
            'xss': [
                r'innerHTML\s*=.*\+',
                r'document\.write\s*\(',
                r'eval\s*\(.*request'
            ]
        }
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """Analyze a single MCP repository."""
        start_time = time.time()
        repo_path = Path(repo_path)
        
        print(f"🔍 Analyzing {repo_path.name}...")
        
        # Get repository stats
        stats = self._get_repo_stats(repo_path)
        
        # Scan for vulnerabilities
        findings = self._scan_vulnerabilities(repo_path)
        
        # Scan for API keys (separate tracking)
        api_keys = self._scan_api_keys(repo_path)
        
        # Calculate metrics
        scan_time = time.time() - start_time
        
        return {
            'repository': repo_path.name,
            'scan_time': round(scan_time, 2),
            'stats': stats,
            'vulnerabilities': {
                'total': len(findings),
                'by_severity': self._group_by_severity(findings),
                'by_category': self._group_by_category(findings),
                'findings': [self._finding_to_dict(f) for f in findings]
            },
            'api_keys': {
                'total': len(api_keys),
                'findings': [self._finding_to_dict(f) for f in api_keys]
            },
            'risk_score': self._calculate_risk_score(findings, api_keys)
        }
    
    def _get_repo_stats(self, repo_path: Path) -> Dict[str, Any]:
        """Get repository statistics."""
        stats = {
            'total_files': 0,
            'python_files': 0,
            'typescript_files': 0,
            'javascript_files': 0,
            'json_files': 0,
            'total_lines': 0,
            'languages': []
        }
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file():
                stats['total_files'] += 1
                
                if file_path.suffix == '.py':
                    stats['python_files'] += 1
                    if 'Python' not in stats['languages']:
                        stats['languages'].append('Python')
                elif file_path.suffix == '.ts':
                    stats['typescript_files'] += 1
                    if 'TypeScript' not in stats['languages']:
                        stats['languages'].append('TypeScript')
                elif file_path.suffix == '.js':
                    stats['javascript_files'] += 1
                    if 'JavaScript' not in stats['languages']:
                        stats['languages'].append('JavaScript')
                elif file_path.suffix == '.json':
                    stats['json_files'] += 1
                
                # Count lines
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        stats['total_lines'] += len(f.readlines())
                except:
                    pass
        
        return stats
    
    def _scan_vulnerabilities(self, repo_path: Path) -> List[SecurityFinding]:
        """Scan for security vulnerabilities."""
        findings = []
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts']:
                findings.extend(self._scan_file(file_path))
        
        return findings
    
    def _scan_api_keys(self, repo_path: Path) -> List[SecurityFinding]:
        """Scan for API keys and secrets."""
        findings = []
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.json', '.env', '.yaml', '.yml']:
                findings.extend(self._scan_file_for_secrets(file_path))
        
        return findings
    
    def _scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a single file for vulnerabilities."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            # Skip test files and comments
            if self._is_test_file(file_path) or line.strip().startswith('#'):
                continue
            
            for category, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Skip obvious false positives
                        if self._is_false_positive(line, category):
                            continue
                            
                        findings.append(SecurityFinding(
                            severity=self._get_severity(category),
                            category=category,
                            description=f"Potential {category.replace('_', ' ')} vulnerability",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            confidence=self._get_confidence(line, category)
                        ))
        
        return findings
    
    def _scan_file_for_secrets(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a file for API keys and secrets."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        # Scan for API key patterns
        for line_num, line in enumerate(lines, 1):
            for pattern in self.api_key_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Skip obvious test values
                    if self._is_test_secret(match.group()):
                        continue
                    
                    findings.append(SecurityFinding(
                        severity='CRITICAL',
                        category='hardcoded_api_key',
                        description=f"Potential API key detected: {pattern}",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=self._mask_secret(line.strip()),
                        confidence=0.9,
                        is_api_key=True
                    ))
        
        # Scan for secret keywords
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for keyword in self.secret_keywords:
                if keyword in line_lower and '=' in line:
                    # Extract potential secret value
                    if '"' in line or "'" in line:
                        # Skip obvious test values
                        if any(test in line_lower for test in ['test', 'example', 'placeholder', 'dummy']):
                            continue
                        
                        findings.append(SecurityFinding(
                            severity='HIGH',
                            category='hardcoded_secret',
                            description=f"Potential hardcoded secret: {keyword}",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=self._mask_secret(line.strip()),
                            confidence=0.7,
                            is_api_key=True
                        ))
        
        return findings
    
    def _is_test_file(self, file_path: Path) -> bool:
        """Check if file is a test file."""
        test_indicators = ['test', 'spec', '__test__', 'tests']
        return any(indicator in str(file_path).lower() for indicator in test_indicators)
    
    def _is_false_positive(self, line: str, category: str) -> bool:
        """Check if finding is likely a false positive."""
        line_lower = line.lower()
        
        # Common false positive patterns
        if any(fp in line_lower for fp in ['import', 'from', 'example', 'test', 'placeholder']):
            return True
        
        if category == 'path_traversal' and 'import' in line_lower:
            return True
        
        return False
    
    def _is_test_secret(self, secret: str) -> bool:
        """Check if secret is a test value."""
        test_patterns = [
            'test', 'example', 'placeholder', 'dummy', 'fake', 'mock',
            '123456', 'abcdef', '000000', 'xxxxxx'
        ]
        return any(pattern in secret.lower() for pattern in test_patterns)
    
    def _mask_secret(self, line: str) -> str:
        """Mask secrets in code snippets."""
        # Mask quoted strings that might contain secrets
        masked = re.sub(r'(["\'])([^"\']{8,})(["\'])', r'\1***MASKED***\3', line)
        return masked
    
    def _get_severity(self, category: str) -> str:
        """Get severity for vulnerability category."""
        severity_map = {
            'command_injection': 'CRITICAL',
            'sql_injection': 'HIGH',
            'path_traversal': 'MEDIUM',
            'xss': 'HIGH'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_confidence(self, line: str, category: str) -> float:
        """Get confidence score for finding."""
        if self._is_test_file(Path(line)):
            return 0.3
        
        confidence_map = {
            'command_injection': 0.9,
            'sql_injection': 0.8,
            'path_traversal': 0.6,
            'xss': 0.7
        }
        return confidence_map.get(category, 0.5)
    
    def _group_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Group findings by severity."""
        groups = {}
        for finding in findings:
            groups[finding.severity] = groups.get(finding.severity, 0) + 1
        return groups
    
    def _group_by_category(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Group findings by category."""
        groups = {}
        for finding in findings:
            groups[finding.category] = groups.get(finding.category, 0) + 1
        return groups
    
    def _calculate_risk_score(self, vulnerabilities: List[SecurityFinding], api_keys: List[SecurityFinding]) -> float:
        """Calculate overall risk score."""
        score = 0.0
        
        # Weight by severity
        severity_weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.2}
        
        for finding in vulnerabilities + api_keys:
            weight = severity_weights.get(finding.severity, 0.2)
            score += weight * finding.confidence
        
        return min(score, 10.0)  # Cap at 10
    
    def _finding_to_dict(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'severity': finding.severity,
            'category': finding.category,
            'description': finding.description,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'code_snippet': finding.code_snippet,
            'confidence': finding.confidence,
            'is_api_key': finding.is_api_key
        }

def main():
    """Main analysis function."""
    analyzer = MCPAnalyzer()
    
    # MCP repositories to analyze
    repos = [
        'mcp-servers',
        'mcp-typescript-sdk', 
        'mcp-python-sdk',
        'mcp-inspector',
        'mcp-obsidian',
        'official-servers',
        'filesystem-server',
        'git-server',
        'memory-server',
        'time-server'
    ]
    
    base_path = Path('../scans/popular_mcps')
    results_path = Path('../scans/results')
    results_path.mkdir(exist_ok=True)
    
    all_results = []
    total_api_keys = []
    
    print("🚀 Starting comprehensive MCP security analysis...")
    print("=" * 60)
    
    for repo in repos:
        repo_path = base_path / repo
        if repo_path.exists():
            result = analyzer.analyze_repository(str(repo_path))
            all_results.append(result)
            
            # Collect API keys for local report
            if result['api_keys']['findings']:
                total_api_keys.extend(result['api_keys']['findings'])
            
            print(f"✅ {repo}: {result['vulnerabilities']['total']} vulnerabilities, {result['api_keys']['total']} API keys")
        else:
            print(f"❌ {repo}: Repository not found")
    
    # Generate comprehensive report
    report = {
        'scan_metadata': {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'repositories_scanned': len(all_results),
            'total_files': sum(r['stats']['total_files'] for r in all_results),
            'total_lines': sum(r['stats']['total_lines'] for r in all_results)
        },
        'aggregate_metrics': {
            'total_vulnerabilities': sum(r['vulnerabilities']['total'] for r in all_results),
            'total_api_keys': len(total_api_keys),
            'average_risk_score': sum(r['risk_score'] for r in all_results) / len(all_results) if all_results else 0,
            'languages_detected': list(set(lang for r in all_results for lang in r['stats']['languages']))
        },
        'repository_results': all_results,
        'api_keys_found': total_api_keys  # Local report only
    }
    
    # Save full report locally (with API keys)
    with open(results_path / 'mcp_security_analysis_full.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Create sanitized report (without API keys) for potential GitHub commit
    sanitized_report = report.copy()
    sanitized_report.pop('api_keys_found', None)
    for repo_result in sanitized_report['repository_results']:
        repo_result['api_keys'] = {
            'total': repo_result['api_keys']['total'],
            'findings': []  # Remove actual API key findings
        }
    
    with open(results_path / 'mcp_security_analysis_sanitized.json', 'w') as f:
        json.dump(sanitized_report, f, indent=2)
    
    # Generate summary report
    print("\n" + "=" * 60)
    print("📊 COMPREHENSIVE MCP SECURITY ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"📁 Repositories Analyzed: {len(all_results)}")
    print(f"📄 Total Files: {report['scan_metadata']['total_files']:,}")
    print(f"📝 Total Lines: {report['scan_metadata']['total_lines']:,}")
    print(f"🌐 Languages: {', '.join(report['aggregate_metrics']['languages_detected'])}")
    print(f"🔍 Total Vulnerabilities: {report['aggregate_metrics']['total_vulnerabilities']}")
    print(f"🔑 Total API Keys Found: {report['aggregate_metrics']['total_api_keys']}")
    print(f"⚠️  Average Risk Score: {report['aggregate_metrics']['average_risk_score']:.2f}/10")
    
    if total_api_keys:
        print("\n🚨 API KEYS DETECTED (LOCAL REPORT ONLY):")
        for i, key in enumerate(total_api_keys, 1):
            print(f"  {i}. {key['category']} in {Path(key['file_path']).name}:{key['line_number']}")
    
    print(f"\n📋 Full report saved to: {results_path / 'mcp_security_analysis_full.json'}")
    print(f"📋 Sanitized report saved to: {results_path / 'mcp_security_analysis_sanitized.json'}")

if __name__ == '__main__':
    main()