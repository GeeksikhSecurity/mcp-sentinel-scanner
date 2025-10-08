"""
Standalone Enhanced MCP Scanner with simplified implementation.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class Finding:
    """Simplified finding structure."""
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float


class EnhancedASRCalculator:
    """Enhanced ASR calculator with context awareness."""
    
    def __init__(self):
        self.vulnerability_weights = {
            'hardcoded_secret': 0.85,
            'path_traversal': 0.82,
            'security_issue': 0.75,
            'command_injection': 0.90,
            'sql_injection': 0.87,
            'xss': 0.80
        }
        
        self.context_penalties = {
            'test_file': 0.3,
            'import_statement': 0.2,
            'placeholder': 0.1
        }
    
    def calculate_asr(self, findings: List[Finding]) -> float:
        """Calculate enhanced ASR score."""
        if not findings:
            return 0.0
            
        total_score = 0.0
        max_possible = 0.0
        
        for finding in findings:
            base_weight = self.vulnerability_weights.get(finding.category, 0.5)
            context_modifier = self._get_context_modifier(finding)
            
            score = base_weight * context_modifier * finding.confidence
            total_score += score
            max_possible += base_weight
            
        return min(total_score / max_possible if max_possible > 0 else 0.0, 1.0)
    
    def _get_context_modifier(self, finding: Finding) -> float:
        """Get context modifier for finding."""
        modifier = 1.0
        
        # Test file penalty
        if any(test in finding.file_path.lower() 
               for test in ['test', 'spec', '__tests__']):
            modifier *= (1.0 - self.context_penalties['test_file'])
            
        # Import statement penalty
        if any(imp in finding.code_snippet.lower()
               for imp in ['import ', 'from ', 'require(']):
            modifier *= (1.0 - self.context_penalties['import_statement'])
            
        # Placeholder penalty
        if any(placeholder in finding.code_snippet.lower()
               for placeholder in ['<redacted>', 'your_', 'example_']):
            modifier *= (1.0 - self.context_penalties['placeholder'])
            
        return max(modifier, 0.1)


class SimplifiedScanner:
    """Simplified scanner for demonstration."""
    
    def __init__(self):
        self.asr_calculator = EnhancedASRCalculator()
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan repository with enhanced analysis."""
        start_time = time.time()
        
        print("Phase 1: Pattern-based analysis...")
        findings = self._pattern_scan(repo_path)
        
        print("Phase 2: Context analysis...")
        enhanced_findings = self._enhance_findings(findings)
        
        print("Phase 3: ASR calculation...")
        enhanced_asr = self.asr_calculator.calculate_asr(enhanced_findings)
        
        scan_time = time.time() - start_time
        file_count = self._count_files(repo_path)
        
        return {
            'scan_summary': {
                'files_scanned': file_count,
                'scan_time': scan_time,
                'vulnerabilities_found': len(enhanced_findings),
                'enhanced_asr_score': enhanced_asr,
                'severity_distribution': self._get_severity_distribution(enhanced_findings)
            },
            'findings': [self._finding_to_dict(f) for f in enhanced_findings],
            'enhancement_metrics': {
                'context_filtered': len(findings) - len(enhanced_findings),
                'accuracy_improvement': self._calculate_accuracy_improvement(findings, enhanced_findings)
            }
        }
    
    def _pattern_scan(self, repo_path: str) -> List[Finding]:
        """Simple pattern-based scan."""
        findings = []
        repo_path = Path(repo_path)
        
        # Scan Python files
        for py_file in repo_path.rglob('*.py'):
            findings.extend(self._scan_python_file(py_file))
            
        # Scan TypeScript/JavaScript files
        for js_file in repo_path.rglob('*.ts'):
            findings.extend(self._scan_js_file(js_file))
        for js_file in repo_path.rglob('*.js'):
            findings.extend(self._scan_js_file(js_file))
            
        return findings
    
    def _scan_python_file(self, file_path: Path) -> List[Finding]:
        """Scan Python file for vulnerabilities."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines, 1):
                line_lower = line.lower()
                
                # Hardcoded secrets
                if any(secret in line_lower for secret in ['password=', 'secret=', 'key=', 'token=']):
                    if '=' in line and '"' in line:
                        findings.append(Finding(
                            severity='HIGH',
                            category='hardcoded_secret',
                            description='Potential hardcoded secret detected',
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.7
                        ))
                
                # Path traversal
                if '../' in line:
                    findings.append(Finding(
                        severity='HIGH',
                        category='path_traversal',
                        description='Path traversal pattern detected',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.6
                    ))
                
                # Command injection
                if any(cmd in line_lower for cmd in ['subprocess.', 'os.system', 'shell=true']):
                    findings.append(Finding(
                        severity='HIGH',
                        category='command_injection',
                        description='Potential command injection',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.8
                    ))
                    
        except Exception:
            pass
            
        return findings
    
    def _scan_js_file(self, file_path: Path) -> List[Finding]:
        """Scan JavaScript/TypeScript file."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines, 1):
                line_lower = line.lower()
                
                # Import path traversal
                if 'import' in line_lower and '../' in line:
                    findings.append(Finding(
                        severity='MEDIUM',
                        category='path_traversal',
                        description='Import path traversal detected',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.4  # Lower confidence for imports
                    ))
                    
        except Exception:
            pass
            
        return findings
    
    def _enhance_findings(self, findings: List[Finding]) -> List[Finding]:
        """Enhance findings with context analysis."""
        enhanced = []
        
        for finding in findings:
            # Apply context-based filtering
            if self._should_keep_finding(finding):
                # Adjust confidence based on context
                finding.confidence = self._adjust_confidence(finding)
                enhanced.append(finding)
                
        return enhanced
    
    def _should_keep_finding(self, finding: Finding) -> bool:
        """Determine if finding should be kept."""
        # Filter out very low confidence findings
        if finding.confidence < 0.3:
            return False
            
        # Filter out obvious false positives
        if (finding.category == 'path_traversal' and 
            'import' in finding.code_snippet.lower() and
            finding.confidence < 0.5):
            return False
            
        return True
    
    def _adjust_confidence(self, finding: Finding) -> float:
        """Adjust confidence based on context."""
        confidence = finding.confidence
        
        # Reduce confidence for test files
        if any(test in finding.file_path.lower() 
               for test in ['test', 'spec', '__tests__']):
            confidence *= 0.7
            
        # Reduce confidence for placeholder values
        if any(placeholder in finding.code_snippet.lower()
               for placeholder in ['<redacted>', 'your_', 'example_']):
            confidence *= 0.5
            
        return max(confidence, 0.1)
    
    def _count_files(self, repo_path: str) -> int:
        """Count scannable files."""
        repo_path = Path(repo_path)
        count = 0
        
        for ext in ['*.py', '*.js', '*.ts']:
            count += len(list(repo_path.rglob(ext)))
            
        return count
    
    def _get_severity_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        """Get severity distribution."""
        distribution = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            distribution[finding.severity] = distribution.get(finding.severity, 0) + 1
            
        return distribution
    
    def _calculate_accuracy_improvement(self, original: List[Finding], 
                                      enhanced: List[Finding]) -> float:
        """Calculate accuracy improvement percentage."""
        if not original:
            return 0.0
            
        filtered_count = len(original) - len(enhanced)
        return (filtered_count / len(original)) * 100
    
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