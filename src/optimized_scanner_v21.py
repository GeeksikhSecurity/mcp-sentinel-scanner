"""Optimized MCP Scanner v2.1 with modular false positive reduction."""

import json
import time
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

from filters.test_context_filter import TestContextFilter
from filters.placeholder_filter import PlaceholderFilter
from filters.import_filter import ImportFilter


@dataclass
class Finding:
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float


class OptimizedASRCalculator:
    """Recalibrated ASR calculator based on real-world impact."""
    
    def __init__(self):
        # Recalibrated weights from manual validation
        self.vulnerability_weights = {
            'command_injection': 0.95,      # Critical in production
            'sql_injection': 0.90,          # High impact
            'hardcoded_secret': 0.40,       # Often test values
            'path_traversal': 0.25,         # Usually imports
            'xss': 0.80,                    # Context-dependent
            'security_issue': 0.70          # Varies by type
        }
        
        # Stricter context penalties
        self.context_penalties = {
            'test_file': 0.95,              # 95% reduction
            'test_value': 0.95,             # 95% reduction
            'import_statement': 0.90,       # 90% reduction
            'documentation': 0.80,          # 80% reduction
            'placeholder': 0.99             # 99% reduction
        }
    
    def calculate_asr(self, findings: List[Finding]) -> float:
        """Calculate optimized ASR score."""
        if not findings:
            return 0.0
            
        total_score = 0.0
        max_possible = 0.0
        
        for finding in findings:
            base_weight = self.vulnerability_weights.get(finding.category, 0.5)
            weighted_score = base_weight * finding.confidence
            
            total_score += weighted_score
            max_possible += base_weight
            
        return min(total_score / max_possible if max_possible > 0 else 0.0, 1.0)


class OptimizedScanner:
    """Optimized scanner with modular filtering."""
    
    def __init__(self):
        self.test_filter = TestContextFilter()
        self.placeholder_filter = PlaceholderFilter()
        self.import_filter = ImportFilter()
        self.asr_calculator = OptimizedASRCalculator()
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan with optimized false positive reduction."""
        start_time = time.time()
        
        print("Phase 1: Pattern detection...")
        raw_findings = self._pattern_scan(repo_path)
        
        print("Phase 2: Modular filtering...")
        filtered_findings = self._apply_filters(raw_findings)
        
        print("Phase 3: ASR calculation...")
        asr_score = self.asr_calculator.calculate_asr(filtered_findings)
        
        scan_time = time.time() - start_time
        file_count = self._count_files(repo_path)
        
        return {
            'scan_summary': {
                'files_scanned': file_count,
                'scan_time': scan_time,
                'vulnerabilities_found': len(filtered_findings),
                'raw_findings': len(raw_findings),
                'optimized_asr_score': asr_score,
                'false_positive_reduction': self._calculate_fp_reduction(raw_findings, filtered_findings),
                'severity_distribution': self._get_severity_distribution(filtered_findings)
            },
            'findings': [self._finding_to_dict(f) for f in filtered_findings],
            'optimization_metrics': {
                'test_filtered': len([f for f in raw_findings if self.test_filter.is_test_file(f.file_path)]),
                'placeholder_filtered': len([f for f in raw_findings if self.placeholder_filter.is_placeholder(f.code_snippet)]),
                'import_filtered': len([f for f in raw_findings if f.category == 'path_traversal' and self.import_filter.is_import_statement(f.code_snippet)])
            }
        }
    
    def _apply_filters(self, findings: List[Finding]) -> List[Finding]:
        """Apply modular filters in sequence."""
        filtered = []
        
        for finding in findings:
            confidence = finding.confidence
            
            # Apply test context filter
            if self.test_filter.is_test_file(finding.file_path):
                confidence *= 0.05
            if self.test_filter.is_test_value(finding.code_snippet):
                confidence *= 0.05
            if self.test_filter.has_test_framework_indicators(finding.code_snippet):
                confidence *= 0.1
                
            # Apply placeholder filter
            if self.placeholder_filter.is_placeholder(finding.code_snippet):
                confidence *= 0.01
                
            # Apply import filter
            if (finding.category == 'path_traversal' and 
                self.import_filter.is_import_statement(finding.code_snippet)):
                confidence *= 0.02
            
            # Update confidence and keep if above threshold
            if confidence >= 0.3:
                finding.confidence = confidence
                filtered.append(finding)
                
        return filtered
    
    def _pattern_scan(self, repo_path: str) -> List[Finding]:
        """Optimized pattern scanning."""
        findings = []
        repo_path = Path(repo_path)
        
        # Scan Python files
        for py_file in repo_path.rglob('*.py'):
            findings.extend(self._scan_python_file(py_file))
            
        # Scan TypeScript/JavaScript files  
        for ts_file in repo_path.rglob('*.ts'):
            findings.extend(self._scan_js_file(ts_file))
        for js_file in repo_path.rglob('*.js'):
            findings.extend(self._scan_js_file(js_file))
            
        return findings
    
    def _scan_python_file(self, file_path: Path) -> List[Finding]:
        """Scan Python file with refined patterns."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines, 1):
                line_lower = line.lower()
                
                # Refined hardcoded secrets (less aggressive)
                if any(secret in line_lower for secret in ['password="', 'secret="', 'key="', 'token="']):
                    if '=' in line and '"' in line and not line_lower.startswith('#'):
                        findings.append(Finding(
                            severity='HIGH',
                            category='hardcoded_secret',
                            description='Potential hardcoded secret detected',
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.7
                        ))
                
                # Path traversal (only non-import)
                if '../' in line and 'import' not in line_lower:
                    findings.append(Finding(
                        severity='HIGH',
                        category='path_traversal',
                        description='Path traversal pattern detected',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.6
                    ))
                
                # Command injection (high confidence only)
                if 'shell=true' in line_lower or ('subprocess.' in line_lower and 'shell' in line_lower):
                    findings.append(Finding(
                        severity='HIGH',
                        category='command_injection',
                        description='Potential command injection',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.9
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
                
                # Import path traversal (will be heavily filtered)
                if 'import' in line_lower and '../' in line:
                    findings.append(Finding(
                        severity='MEDIUM',
                        category='path_traversal',
                        description='Import path traversal detected',
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=0.3  # Low initial confidence
                    ))
                    
        except Exception:
            pass
            
        return findings
    
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
    
    def _calculate_fp_reduction(self, original: List[Finding], filtered: List[Finding]) -> float:
        """Calculate false positive reduction percentage."""
        if not original:
            return 0.0
        return ((len(original) - len(filtered)) / len(original)) * 100
    
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