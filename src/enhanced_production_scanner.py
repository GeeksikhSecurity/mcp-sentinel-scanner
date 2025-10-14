#!/usr/bin/env python3
"""
Enhanced Production Scanner v2.5
Removes synthetic data and implements advanced false positive filtering
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Finding:
    repo_name: str
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    code_snippet: str
    description: str
    confidence: float
    context: Dict[str, Any]

class EnhancedProductionScanner:
    def __init__(self):
        self.false_positive_patterns = self._load_false_positive_patterns()
        self.test_file_patterns = {
            r'test[_/]', r'spec[_/]', r'__test__', r'\.test\.', r'\.spec\.',
            r'mock', r'fixture', r'example', r'demo', r'sample'
        }
        self.placeholder_patterns = {
            r'sk-[0-9a-f]{48}',  # OpenAI placeholder pattern
            r'xoxb-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]{24}',  # Slack placeholder
            r'your[_-]?api[_-]?key', r'replace[_-]?with', r'example[_-]?key',
            r'dummy[_-]?key', r'test[_-]?key', r'fake[_-]?key'
        }
        self.synthetic_repo_patterns = {
            r'core_mcp-\d+$', r'ai_integrations-\d+$', 
            r'anthropic/core_mcp', r'mcp-official/core_mcp',
            r'modelcontextprotocol/core_mcp', r'claude-mcp/', r'gemini-mcp/', r'openai-mcp/'
        }
        
    def _load_false_positive_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that commonly cause false positives"""
        return {
            'hardcoded_secrets': [
                r'const\s+\w+\s*=\s*["\']sk-1234567890abcdef',  # Obvious placeholder
                r'API_KEY\s*=\s*["\']sk-1234567890abcdef',
                r'["\']your[_-]?api[_-]?key[_-]?here["\']',
                r'["\']replace[_-]?with[_-]?actual[_-]?key["\']',
                r'["\']example[_-]?key["\']',
                r'["\']test[_-]?key["\']',
                r'["\']dummy[_-]?key["\']',
                r'["\']fake[_-]?key["\']'
            ],
            'sql_injection': [
                r'//.*sql_injection.*vulnerability',  # Comment patterns
                r'#.*example.*sql.*injection',
                r'SELECT.*FROM.*example',
                r'WHERE.*id.*=.*\$\{?example',
            ],
            'command_injection': [
                r'//.*command_injection.*vulnerability',
                r'#.*example.*command.*injection',
                r'exec\(["\']cat.*example',
                r'system\(["\']cat.*test'
            ],
            'generic_comments': [
                r'//.*vulnerability',
                r'#.*vulnerability',
                r'/\*.*vulnerability.*\*/',
                r'<!--.*vulnerability.*-->'
            ]
        }
    
    def is_synthetic_repo(self, repo_name: str) -> bool:
        """Check if repository name matches synthetic patterns"""
        for pattern in self.synthetic_repo_patterns:
            if re.search(pattern, repo_name, re.IGNORECASE):
                return True
        return False
    
    def is_test_file(self, file_path: str) -> bool:
        """Check if file is a test/mock/example file"""
        file_path_lower = file_path.lower()
        for pattern in self.test_file_patterns:
            if re.search(pattern, file_path_lower):
                return True
        return False
    
    def is_placeholder_content(self, content: str) -> bool:
        """Check if content contains placeholder/example data"""
        content_lower = content.lower()
        for pattern in self.placeholder_patterns:
            if re.search(pattern, content_lower):
                return True
        return False
    
    def is_false_positive(self, finding: Finding) -> bool:
        """Enhanced false positive detection"""
        # Check synthetic repository
        if self.is_synthetic_repo(finding.repo_name):
            return True
            
        # Check test files
        if self.is_test_file(finding.file_path):
            return True
            
        # Check placeholder content
        if self.is_placeholder_content(finding.code_snippet):
            return True
            
        # Check vulnerability-specific patterns
        vuln_patterns = self.false_positive_patterns.get(finding.vulnerability_type, [])
        for pattern in vuln_patterns:
            if re.search(pattern, finding.code_snippet, re.IGNORECASE):
                return True
                
        # Check generic comment patterns
        for pattern in self.false_positive_patterns.get('generic_comments', []):
            if re.search(pattern, finding.code_snippet):
                return True
                
        return False
    
    def calculate_confidence(self, finding: Finding) -> float:
        """Calculate confidence score based on multiple factors"""
        base_confidence = 0.5
        
        # Increase confidence for specific patterns
        if finding.vulnerability_type == 'hardcoded_secrets':
            if re.search(r'[A-Za-z0-9]{32,}', finding.code_snippet):
                base_confidence += 0.3
            if 'environment' not in finding.code_snippet.lower():
                base_confidence += 0.2
                
        elif finding.vulnerability_type == 'sql_injection':
            if 'prepare' not in finding.code_snippet.lower():
                base_confidence += 0.3
            if re.search(r'\+.*user', finding.code_snippet, re.IGNORECASE):
                base_confidence += 0.2
                
        elif finding.vulnerability_type == 'command_injection':
            if 'shell=True' in finding.code_snippet or 'system(' in finding.code_snippet:
                base_confidence += 0.4
                
        # Decrease confidence for suspicious patterns
        if re.search(r'//.*example|#.*example|/\*.*example', finding.code_snippet):
            base_confidence -= 0.4
            
        if 'TODO' in finding.code_snippet or 'FIXME' in finding.code_snippet:
            base_confidence -= 0.2
            
        return min(max(base_confidence, 0.0), 1.0)
    
    def scan_real_repositories(self, repo_paths: List[str]) -> List[Finding]:
        """Scan real repositories with enhanced filtering"""
        findings = []
        
        for repo_path in repo_paths:
            if not os.path.exists(repo_path):
                continue
                
            repo_name = os.path.basename(repo_path)
            
            # Skip synthetic repositories
            if self.is_synthetic_repo(repo_name):
                continue
                
            # Scan repository files
            for root, dirs, files in os.walk(repo_path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.pytest_cache'}]
                
                for file in files:
                    if file.endswith(('.py', '.js', '.ts', '.go', '.rs', '.java', '.php')):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, repo_path)
                        
                        # Skip test files
                        if self.is_test_file(relative_path):
                            continue
                            
                        findings.extend(self._scan_file(repo_name, file_path, relative_path))
        
        # Filter false positives
        filtered_findings = []
        for finding in findings:
            if not self.is_false_positive(finding):
                finding.confidence = self.calculate_confidence(finding)
                if finding.confidence >= 0.6:  # Only high-confidence findings
                    filtered_findings.append(finding)
        
        return filtered_findings
    
    def _scan_file(self, repo_name: str, file_path: str, relative_path: str) -> List[Finding]:
        """Scan individual file for vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Skip empty lines and obvious comments
                if not line_stripped or line_stripped.startswith(('///', '###', '"""')):
                    continue
                
                # Detect hardcoded secrets
                if self._detect_hardcoded_secrets(line_stripped):
                    finding = Finding(
                        repo_name=repo_name,
                        file_path=relative_path,
                        line_number=line_num,
                        vulnerability_type='hardcoded_secrets',
                        severity='HIGH',
                        code_snippet=line_stripped,
                        description='Potential hardcoded secret detected',
                        confidence=0.0,  # Will be calculated later
                        context={'file_type': file_path.split('.')[-1]}
                    )
                    findings.append(finding)
                
                # Detect SQL injection
                if self._detect_sql_injection(line_stripped):
                    finding = Finding(
                        repo_name=repo_name,
                        file_path=relative_path,
                        line_number=line_num,
                        vulnerability_type='sql_injection',
                        severity='CRITICAL',
                        code_snippet=line_stripped,
                        description='Potential SQL injection vulnerability',
                        confidence=0.0,
                        context={'file_type': file_path.split('.')[-1]}
                    )
                    findings.append(finding)
                
                # Detect command injection
                if self._detect_command_injection(line_stripped):
                    finding = Finding(
                        repo_name=repo_name,
                        file_path=relative_path,
                        line_number=line_num,
                        vulnerability_type='command_injection',
                        severity='CRITICAL',
                        code_snippet=line_stripped,
                        description='Potential command injection vulnerability',
                        confidence=0.0,
                        context={'file_type': file_path.split('.')[-1]}
                    )
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            
        return findings
    
    def _detect_hardcoded_secrets(self, line: str) -> bool:
        """Detect hardcoded secrets with improved accuracy"""
        # Skip obvious placeholders and comments
        if re.search(r'//.*|#.*|/\*.*\*/|<!--.*-->', line):
            return False
            
        # Look for high-entropy strings that aren't placeholders
        patterns = [
            r'["\'][A-Za-z0-9+/]{40,}["\']',  # Base64-like
            r'["\'][A-Fa-f0-9]{32,}["\']',    # Hex strings
            r'sk-[A-Za-z0-9]{48}',            # OpenAI keys (real pattern)
            r'xoxb-\d+-\d+-\d+-[a-f0-9]{24}', # Slack tokens (real pattern)
        ]
        
        for pattern in patterns:
            if re.search(pattern, line):
                # Additional validation - not a placeholder
                if not re.search(r'example|test|dummy|fake|placeholder|your.*key', line, re.IGNORECASE):
                    return True
        return False
    
    def _detect_sql_injection(self, line: str) -> bool:
        """Detect SQL injection vulnerabilities"""
        # Skip comments
        if re.search(r'//.*|#.*|/\*.*\*/|<!--.*-->', line):
            return False
            
        # Look for string concatenation in SQL queries
        sql_patterns = [
            r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\w+',
            r'(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}',
            r'(SELECT|INSERT|UPDATE|DELETE).*%s.*%',
            r'execute\s*\(\s*f["\'].*\{.*\}',
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def _detect_command_injection(self, line: str) -> bool:
        """Detect command injection vulnerabilities"""
        # Skip comments
        if re.search(r'//.*|#.*|/\*.*\*/|<!--.*-->', line):
            return False
            
        # Look for dangerous command execution patterns
        cmd_patterns = [
            r'os\.system\s*\(\s*.*\+',
            r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
            r'exec\s*\(\s*["\'].*\+',
            r'eval\s*\(\s*.*\+',
            r'system\s*\(\s*.*\+',
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def generate_clean_report(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate clean report with real findings only"""
        if not findings:
            return {
                "scan_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "scanner_version": "Enhanced Production Scanner v2.5",
                    "total_findings": 0,
                    "false_positives_filtered": "All synthetic data removed"
                },
                "summary": "No real vulnerabilities found after filtering synthetic data",
                "findings": []
            }
        
        # Group findings by repository
        repo_findings = {}
        for finding in findings:
            if finding.repo_name not in repo_findings:
                repo_findings[finding.repo_name] = []
            repo_findings[finding.repo_name].append({
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "vulnerability_type": finding.vulnerability_type,
                "severity": finding.severity,
                "code_snippet": finding.code_snippet,
                "description": finding.description,
                "confidence": round(finding.confidence, 2),
                "context": finding.context
            })
        
        # Calculate statistics
        severity_counts = {}
        vuln_type_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            vuln_type_counts[finding.vulnerability_type] = vuln_type_counts.get(finding.vulnerability_type, 0) + 1
        
        return {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "scanner_version": "Enhanced Production Scanner v2.5",
                "total_findings": len(findings),
                "repositories_scanned": len(repo_findings),
                "filtering_applied": "Synthetic data removed, test files excluded, placeholders filtered"
            },
            "statistics": {
                "severity_distribution": severity_counts,
                "vulnerability_types": vuln_type_counts,
                "average_confidence": round(sum(f.confidence for f in findings) / len(findings), 2)
            },
            "findings_by_repository": repo_findings,
            "remediation_summary": {
                "immediate_actions": [
                    "Review and validate all HIGH and CRITICAL findings",
                    "Rotate any confirmed hardcoded secrets",
                    "Implement input validation for injection vulnerabilities"
                ],
                "long_term_improvements": [
                    "Implement secrets scanning in CI/CD pipeline",
                    "Add parameterized queries for database operations",
                    "Establish secure coding guidelines"
                ]
            }
        }

def main():
    scanner = EnhancedProductionScanner()
    
    # Example usage - scan real repositories only
    # In practice, you would provide actual repository paths
    real_repo_paths = [
        # Add real repository paths here
        # "/path/to/real/mcp/repository1",
        # "/path/to/real/mcp/repository2",
    ]
    
    print("🔍 Enhanced Production Scanner v2.5")
    print("=" * 50)
    print("✅ Synthetic data filtering: ENABLED")
    print("✅ Test file exclusion: ENABLED") 
    print("✅ Placeholder detection: ENABLED")
    print("✅ Confidence scoring: ENABLED")
    print("=" * 50)
    
    if not real_repo_paths:
        print("⚠️  No real repository paths provided")
        print("📝 This scanner filters out all synthetic/mock data")
        print("🎯 Only real vulnerabilities in production code will be reported")
        return
    
    findings = scanner.scan_real_repositories(real_repo_paths)
    report = scanner.generate_clean_report(findings)
    
    # Save clean report
    output_file = f"clean_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📊 Clean report saved to: {output_file}")
    print(f"🔍 Total findings: {len(findings)}")
    print(f"🏢 Repositories: {report['scan_metadata']['repositories_scanned']}")
    
    if findings:
        print("\n🚨 Real Vulnerabilities Found:")
        for finding in findings[:5]:  # Show first 5
            print(f"  • {finding.vulnerability_type} in {finding.repo_name}")
            print(f"    {finding.file_path}:{finding.line_number}")
            print(f"    Confidence: {finding.confidence:.2f}")
    else:
        print("\n✅ No real vulnerabilities found after filtering")

if __name__ == "__main__":
    main()