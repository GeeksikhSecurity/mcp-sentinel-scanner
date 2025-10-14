#!/usr/bin/env python3
"""Enhanced MCP Scanner v2.2 - Fine-tuned based on 10 popular MCP repository analysis."""

import json
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
    is_production: bool = True
    context_type: str = "production"

class EnhancedMCPScanner:
    """Enhanced MCP Scanner v2.2 with real-world fine-tuning."""
    
    def __init__(self):
        # Refined patterns based on 10 MCP repository analysis
        self.vulnerability_patterns = {
            'command_injection': [
                r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
                r'exec\s*\([^)]*\+[^)]*\)',  # Dynamic command construction
                r'eval\s*\([^)]*request[^)]*\)',  # User input evaluation
                r'os\.system\s*\([^)]*\+[^)]*\)',  # Dynamic system calls
            ],
            'path_traversal': [
                r'\.\./.*\.\.',  # Multiple traversal attempts
                r'\.\.[\\/][^/\\]*[\\/]',  # Directory traversal patterns
                r'path.*\.\.[^/\\]*[/\\]',  # Path manipulation
                r'join\([^)]*\.\.[^)]*\)',  # Path join with traversal
            ],
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'SELECT.*\+.*FROM',
                r'cursor\.execute\([^)]*%[^)]*\)',
            ],
            'xss': [
                r'innerHTML\s*=.*\+',
                r'document\.write\s*\(',
                r'eval\s*\(.*request',
                r'dangerouslySetInnerHTML.*\+',
            ]
        }
        
        # Enhanced secret patterns based on real findings
        self.secret_patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'github_oauth': r'gho_[a-zA-Z0-9]{36}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'generic_hex32': r'[0-9a-f]{32}',
            'generic_hex40': r'[0-9a-f]{40}',
            'generic_hex64': r'[0-9a-f]{64}',
        }
        
        # Context-aware filtering based on MCP analysis
        self.context_indicators = {
            'test_files': [
                'test', 'spec', '__test__', 'tests', '.test.', '.spec.',
                'test_', 'spec_', 'testing', 'fixtures'
            ],
            'documentation': [
                'example', 'demo', 'sample', 'docs', 'readme', 'tutorial',
                'guide', 'documentation', 'examples'
            ],
            'configuration': [
                'config', 'settings', 'env', 'environment', '.env',
                'configuration', 'setup'
            ]
        }
        
        # MCP-specific patterns (learned from analysis)
        self.mcp_patterns = {
            'oauth_test_tokens': [
                r'Bearer\s+[a-zA-Z0-9_-]+',
                r'access_token.*=.*["\'][^"\']+["\']',
                r'refresh_token.*=.*["\'][^"\']+["\']',
            ],
            'mcp_server_patterns': [
                r'mcp\.server',
                r'ModelContextProtocol',
                r'@mcp\.tool',
                r'mcp_server',
            ]
        }
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced repository scanning with MCP-specific analysis."""
        start_time = time.time()
        repo_path = Path(repo_path)
        
        print(f"🔍 Scanning {repo_path.name} with Enhanced MCP Scanner v2.2...")
        
        # Repository statistics
        stats = self._get_repo_stats(repo_path)
        
        # Vulnerability scanning
        vulnerabilities = self._scan_vulnerabilities(repo_path)
        
        # Secret scanning with context awareness
        secrets = self._scan_secrets_with_context(repo_path)
        
        # MCP-specific analysis
        mcp_analysis = self._analyze_mcp_patterns(repo_path)
        
        # Calculate enhanced risk score
        risk_score = self._calculate_enhanced_risk_score(vulnerabilities, secrets, mcp_analysis)
        
        scan_time = time.time() - start_time
        
        return {
            'repository': repo_path.name,
            'scan_time': round(scan_time, 2),
            'scanner_version': 'v2.2',
            'stats': stats,
            'vulnerabilities': {
                'total': len(vulnerabilities),
                'by_severity': self._group_by_severity(vulnerabilities),
                'by_context': self._group_by_context(vulnerabilities),
                'findings': [self._finding_to_dict(f) for f in vulnerabilities]
            },
            'secrets': {
                'total': len(secrets),
                'production_secrets': len([s for s in secrets if s.is_production]),
                'test_secrets': len([s for s in secrets if not s.is_production]),
                'by_context': self._group_by_context(secrets),
                'findings': [self._finding_to_dict(f) for f in secrets]
            },
            'mcp_analysis': mcp_analysis,
            'risk_score': risk_score,
            'recommendations': self._generate_recommendations(vulnerabilities, secrets, mcp_analysis)
        }
    
    def _get_repo_stats(self, repo_path: Path) -> Dict[str, Any]:
        """Enhanced repository statistics."""
        stats = {
            'total_files': 0,
            'python_files': 0,
            'typescript_files': 0,
            'javascript_files': 0,
            'json_files': 0,
            'test_files': 0,
            'config_files': 0,
            'total_lines': 0,
            'languages': [],
            'mcp_indicators': 0
        }
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file():
                stats['total_files'] += 1
                
                # Language detection
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
                
                # Context detection
                if self._is_test_file(file_path):
                    stats['test_files'] += 1
                if self._is_config_file(file_path):
                    stats['config_files'] += 1
                
                # Count lines and MCP indicators
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        stats['total_lines'] += len(content.split('\n'))
                        
                        # Check for MCP patterns
                        for pattern in self.mcp_patterns['mcp_server_patterns']:
                            if re.search(pattern, content, re.IGNORECASE):
                                stats['mcp_indicators'] += 1
                                break
                except:
                    pass
        
        return stats
    
    def _scan_vulnerabilities(self, repo_path: Path) -> List[SecurityFinding]:
        """Enhanced vulnerability scanning with context awareness."""
        findings = []
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts']:
                findings.extend(self._scan_file_for_vulnerabilities(file_path))
        
        return self._apply_context_filtering(findings)
    
    def _scan_secrets_with_context(self, repo_path: Path) -> List[SecurityFinding]:
        """Enhanced secret scanning with context awareness."""
        findings = []
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.json', '.env', '.yaml', '.yml']:
                findings.extend(self._scan_file_for_secrets(file_path))
        
        return self._apply_context_filtering(findings)
    
    def _scan_file_for_vulnerabilities(self, file_path: Path) -> List[SecurityFinding]:
        """Scan file for vulnerabilities with enhanced patterns."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            if line.strip().startswith('#') or line.strip().startswith('//') or not line.strip():
                continue
            
            for category, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        confidence = self._calculate_initial_confidence(line, category, file_path)
                        
                        findings.append(SecurityFinding(
                            severity=self._get_severity(category),
                            category=category,
                            description=f"Potential {category.replace('_', ' ')} vulnerability",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            confidence=confidence,
                            context_type=self._determine_context_type(file_path)
                        ))
        
        return findings
    
    def _scan_file_for_secrets(self, file_path: Path) -> List[SecurityFinding]:
        """Enhanced secret scanning with context awareness."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        # Scan for specific secret patterns
        for secret_type, pattern in self.secret_patterns.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Skip obvious test values
                if self._is_test_secret(match.group()):
                    continue
                
                confidence = self._calculate_secret_confidence(match.group(), line_content, file_path)
                
                findings.append(SecurityFinding(
                    severity='CRITICAL' if confidence > 0.8 else 'HIGH',
                    category=f'hardcoded_{secret_type}',
                    description=f"Potential {secret_type.replace('_', ' ')} detected",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=self._mask_secret(line_content),
                    confidence=confidence,
                    context_type=self._determine_context_type(file_path)
                ))
        
        return findings
    
    def _analyze_mcp_patterns(self, repo_path: Path) -> Dict[str, Any]:
        """Analyze MCP-specific patterns and configurations."""
        analysis = {
            'is_mcp_repository': False,
            'mcp_servers_found': 0,
            'mcp_tools_found': 0,
            'oauth_implementations': 0,
            'security_features': [],
            'potential_issues': []
        }
        
        for file_path in repo_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check for MCP server patterns
                    if re.search(r'mcp\.server|ModelContextProtocol', content, re.IGNORECASE):
                        analysis['is_mcp_repository'] = True
                        analysis['mcp_servers_found'] += 1
                    
                    # Check for MCP tools
                    if re.search(r'@mcp\.tool|mcp_tool', content, re.IGNORECASE):
                        analysis['mcp_tools_found'] += 1
                    
                    # Check for OAuth implementations
                    if re.search(r'oauth|OAuth|bearer.*token', content, re.IGNORECASE):
                        analysis['oauth_implementations'] += 1
                    
                    # Check for security features
                    if re.search(r'auth|authentication|authorization', content, re.IGNORECASE):
                        if 'Authentication' not in analysis['security_features']:
                            analysis['security_features'].append('Authentication')
                    
                    if re.search(r'encrypt|decrypt|crypto', content, re.IGNORECASE):
                        if 'Encryption' not in analysis['security_features']:
                            analysis['security_features'].append('Encryption')
                    
                except:
                    pass
        
        return analysis
    
    def _apply_context_filtering(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Apply context-aware filtering based on MCP analysis."""
        filtered_findings = []
        
        for finding in findings:
            file_path = Path(finding.file_path)
            
            # Determine if this is production code
            finding.is_production = not (
                self._is_test_file(file_path) or 
                self._is_documentation_file(file_path)
            )
            
            # Apply context-based confidence adjustments
            if finding.context_type == 'test':
                finding.confidence *= 0.1  # 90% reduction for test files
            elif finding.context_type == 'documentation':
                finding.confidence *= 0.2  # 80% reduction for docs
            elif finding.context_type == 'configuration':
                finding.confidence *= 0.5  # 50% reduction for config files
            
            # Special handling for OAuth patterns in test contexts
            if 'oauth' in finding.code_snippet.lower() and finding.context_type == 'test':
                finding.confidence *= 0.05  # 95% reduction for OAuth test patterns
            
            # Keep findings above confidence threshold
            if finding.confidence >= 0.3:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def _calculate_enhanced_risk_score(self, vulnerabilities: List[SecurityFinding], 
                                     secrets: List[SecurityFinding], 
                                     mcp_analysis: Dict[str, Any]) -> float:
        """Calculate enhanced risk score with MCP-specific factors."""
        score = 0.0
        
        # Vulnerability scoring
        severity_weights = {'CRITICAL': 3.0, 'HIGH': 2.0, 'MEDIUM': 1.0, 'LOW': 0.5}
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 0.5)
            context_multiplier = 1.0 if vuln.is_production else 0.1
            score += weight * vuln.confidence * context_multiplier
        
        # Secret scoring (only production secrets count significantly)
        for secret in secrets:
            if secret.is_production:
                score += 2.0 * secret.confidence
            else:
                score += 0.1 * secret.confidence  # Test secrets have minimal impact
        
        # MCP-specific risk factors
        if mcp_analysis['oauth_implementations'] > 0 and len(vulnerabilities) > 0:
            score *= 1.2  # OAuth + vulnerabilities = higher risk
        
        if mcp_analysis['is_mcp_repository'] and not mcp_analysis['security_features']:
            score += 1.0  # MCP repo without security features
        
        return min(score, 10.0)  # Cap at 10
    
    def _generate_recommendations(self, vulnerabilities: List[SecurityFinding], 
                                secrets: List[SecurityFinding], 
                                mcp_analysis: Dict[str, Any]) -> List[str]:
        """Generate context-aware recommendations."""
        recommendations = []
        
        # Vulnerability-based recommendations
        critical_vulns = [v for v in vulnerabilities if v.severity == 'CRITICAL' and v.is_production]
        if critical_vulns:
            recommendations.append(f"🚨 URGENT: Fix {len(critical_vulns)} critical vulnerabilities in production code")
        
        # Secret-based recommendations
        prod_secrets = [s for s in secrets if s.is_production]
        if prod_secrets:
            recommendations.append(f"🔑 Review {len(prod_secrets)} hardcoded secrets in production code")
        
        # MCP-specific recommendations
        if mcp_analysis['is_mcp_repository']:
            if mcp_analysis['oauth_implementations'] > 0:
                recommendations.append("🔐 Implement proper OAuth token validation and expiration")
            
            if not mcp_analysis['security_features']:
                recommendations.append("🛡️ Add authentication and authorization to MCP server")
            
            recommendations.append("📋 Follow MCP security best practices for server implementation")
        
        return recommendations
    
    def _is_test_file(self, file_path: Path) -> bool:
        """Enhanced test file detection."""
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in self.context_indicators['test_files'])
    
    def _is_documentation_file(self, file_path: Path) -> bool:
        """Enhanced documentation file detection."""
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in self.context_indicators['documentation'])
    
    def _is_config_file(self, file_path: Path) -> bool:
        """Enhanced configuration file detection."""
        path_str = str(file_path).lower()
        return any(indicator in path_str for indicator in self.context_indicators['configuration'])
    
    def _determine_context_type(self, file_path: Path) -> str:
        """Determine the context type of a file."""
        if self._is_test_file(file_path):
            return 'test'
        elif self._is_documentation_file(file_path):
            return 'documentation'
        elif self._is_config_file(file_path):
            return 'configuration'
        else:
            return 'production'
    
    def _calculate_initial_confidence(self, line: str, category: str, file_path: Path) -> float:
        """Calculate initial confidence score."""
        base_confidence = {
            'command_injection': 0.9,
            'sql_injection': 0.8,
            'path_traversal': 0.7,
            'xss': 0.8
        }.get(category, 0.6)
        
        # Adjust based on context
        if self._is_test_file(file_path):
            base_confidence *= 0.3
        
        return base_confidence
    
    def _calculate_secret_confidence(self, secret: str, line: str, file_path: Path) -> float:
        """Calculate confidence score for secrets."""
        confidence = 0.8
        
        # Pattern-specific confidence
        if len(secret) >= 32:  # Long secrets are more likely real
            confidence += 0.1
        
        # Context adjustments
        if self._is_test_file(file_path):
            confidence *= 0.1
        elif self._is_documentation_file(file_path):
            confidence *= 0.2
        
        return min(confidence, 1.0)
    
    def _is_test_secret(self, secret: str) -> bool:
        """Enhanced test secret detection."""
        test_patterns = [
            'test', 'example', 'placeholder', 'dummy', 'fake', 'mock',
            'sample', 'demo', '123456', 'abcdef', '000000', 'xxxxxx',
            'your_key_here', 'replace_me', 'todo'
        ]
        return any(pattern in secret.lower() for pattern in test_patterns)
    
    def _mask_secret(self, line: str) -> str:
        """Mask secrets in code snippets."""
        return re.sub(r'(["\'])([^"\']{8,})(["\'])', r'\1***MASKED***\3', line)
    
    def _get_severity(self, category: str) -> str:
        """Get severity for vulnerability category."""
        severity_map = {
            'command_injection': 'CRITICAL',
            'sql_injection': 'HIGH',
            'path_traversal': 'MEDIUM',
            'xss': 'HIGH'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _group_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Group findings by severity."""
        groups = {}
        for finding in findings:
            groups[finding.severity] = groups.get(finding.severity, 0) + 1
        return groups
    
    def _group_by_context(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Group findings by context type."""
        groups = {}
        for finding in findings:
            groups[finding.context_type] = groups.get(finding.context_type, 0) + 1
        return groups
    
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
            'is_production': finding.is_production,
            'context_type': finding.context_type
        }

def main():
    """Main function for command-line usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python enhanced_mcp_scanner_v22.py <repository_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    scanner = EnhancedMCPScanner()
    
    print("🛡️ Enhanced MCP Scanner v2.2")
    print("=" * 50)
    
    result = scanner.scan_repository(repo_path)
    
    print(f"\n📊 Scan Results for {result['repository']}:")
    print(f"⏱️  Scan Time: {result['scan_time']}s")
    print(f"📁 Files: {result['stats']['total_files']}")
    print(f"📝 Lines: {result['stats']['total_lines']:,}")
    print(f"🔍 Vulnerabilities: {result['vulnerabilities']['total']}")
    print(f"🔑 Secrets: {result['secrets']['total']} ({result['secrets']['production_secrets']} in production)")
    print(f"⚠️  Risk Score: {result['risk_score']:.1f}/10")
    
    if result['recommendations']:
        print("\n💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"  • {rec}")
    
    # Save detailed results
    output_file = f"{result['repository']}_security_scan_v22.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n📋 Detailed results saved to: {output_file}")

if __name__ == '__main__':
    main()