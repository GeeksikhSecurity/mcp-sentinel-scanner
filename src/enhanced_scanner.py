"""
Enhanced MCP Scanner with CodeQL integration and improved ASR scoring.
"""

import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import time

from unified_scanner import UnifiedScanner
from core.vulnerability_finding import VulnerabilityFinding


@dataclass
class CodeQLResult:
    """CodeQL analysis result."""
    rule_id: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    severity: str
    confidence: float


class EnhancedASRCalculator:
    """Enhanced Attack Success Rate calculator with semantic analysis."""
    
    def __init__(self):
        self.vulnerability_weights = {
            'code_injection': 0.95,
            'command_injection': 0.90,
            'sql_injection': 0.87,
            'hardcoded_secret': 0.85,
            'path_traversal': 0.82,
            'xss': 0.80,
            'insecure_deserialization': 0.85,
            'weak_crypto': 0.70,
            'authentication_bypass': 0.92,
            'privilege_escalation': 0.88
        }
        
        self.context_modifiers = {
            'test_file': -0.4,
            'import_statement': -0.5,
            'placeholder_value': -0.6,
            'documentation': -0.3,
            'production_code': 0.1,
            'external_input': 0.2,
            'network_accessible': 0.15
        }
    
    def calculate_enhanced_asr(self, findings: List[VulnerabilityFinding], 
                             codeql_results: List[CodeQLResult] = None) -> float:
        """Calculate enhanced ASR with semantic context."""
        if not findings:
            return 0.0
            
        total_score = 0.0
        max_possible = 0.0
        
        for finding in findings:
            base_weight = self.vulnerability_weights.get(finding.category, 0.5)
            context_score = self._analyze_context(finding, codeql_results)
            
            # Semantic enhancement from CodeQL
            semantic_boost = self._get_semantic_boost(finding, codeql_results)
            
            final_score = base_weight * context_score * semantic_boost
            total_score += final_score
            max_possible += base_weight
            
        return min(total_score / max_possible if max_possible > 0 else 0.0, 1.0)
    
    def _analyze_context(self, finding: VulnerabilityFinding, 
                        codeql_results: List[CodeQLResult] = None) -> float:
        """Analyze finding context for accuracy."""
        context_score = 1.0
        
        # File path analysis
        if any(test_indicator in finding.file_path.lower() 
               for test_indicator in ['test', 'spec', '__tests__']):
            context_score += self.context_modifiers['test_file']
            
        # Code snippet analysis
        if finding.code_snippet:
            if any(import_pattern in finding.code_snippet 
                   for import_pattern in ['import ', 'from ', 'require(']):
                context_score += self.context_modifiers['import_statement']
                
            if any(placeholder in finding.code_snippet.lower()
                   for placeholder in ['your_', 'example_', 'placeholder', 'xxx']):
                context_score += self.context_modifiers['placeholder_value']
        
        return max(context_score, 0.1)  # Minimum threshold
    
    def _get_semantic_boost(self, finding: VulnerabilityFinding,
                           codeql_results: List[CodeQLResult] = None) -> float:
        """Get semantic boost from CodeQL analysis."""
        if not codeql_results:
            return 1.0
            
        # Check if CodeQL confirms this vulnerability
        for result in codeql_results:
            if (result.file_path == finding.file_path and 
                abs(result.start_line - finding.line_number) <= 2):
                return 1.3  # 30% boost for CodeQL confirmation
                
        return 1.0


class CodeQLIntegration:
    """CodeQL integration for semantic analysis."""
    
    def __init__(self):
        self.codeql_path = self._find_codeql()
        
    def _find_codeql(self) -> Optional[str]:
        """Find CodeQL CLI installation."""
        try:
            result = subprocess.run(['which', 'codeql'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def analyze_repository(self, repo_path: str) -> List[CodeQLResult]:
        """Analyze repository with CodeQL."""
        if not self.codeql_path:
            return []
            
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = Path(temp_dir) / "codeql-db"
                
                # Create database
                self._create_database(repo_path, str(db_path))
                
                # Run analysis
                return self._run_queries(str(db_path))
                
        except Exception as e:
            print(f"CodeQL analysis failed: {e}")
            return []
    
    def _create_database(self, repo_path: str, db_path: str):
        """Create CodeQL database."""
        language = self._detect_language(repo_path)
        
        cmd = [
            self.codeql_path, 'database', 'create',
            db_path,
            f'--language={language}',
            f'--source-root={repo_path}',
            '--overwrite'
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
    
    def _detect_language(self, repo_path: str) -> str:
        """Detect primary language."""
        path = Path(repo_path)
        
        if list(path.glob('**/*.py')):
            return 'python'
        elif list(path.glob('**/*.js')) or list(path.glob('**/*.ts')):
            return 'javascript'
        elif list(path.glob('**/*.java')):
            return 'java'
        else:
            return 'python'  # Default
    
    def _run_queries(self, db_path: str) -> List[CodeQLResult]:
        """Run CodeQL queries."""
        cmd = [
            self.codeql_path, 'database', 'analyze',
            db_path,
            '--format=json',
            '--output=-'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return []
            
        try:
            data = json.loads(result.stdout)
            return self._parse_results(data)
        except:
            return []
    
    def _parse_results(self, data: Dict) -> List[CodeQLResult]:
        """Parse CodeQL results."""
        results = []
        
        for run in data.get('runs', []):
            for result in run.get('results', []):
                for location in result.get('locations', []):
                    physical_location = location.get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    region = physical_location.get('region', {})
                    
                    results.append(CodeQLResult(
                        rule_id=result.get('ruleId', ''),
                        message=result.get('message', {}).get('text', ''),
                        file_path=artifact_location.get('uri', ''),
                        start_line=region.get('startLine', 0),
                        end_line=region.get('endLine', 0),
                        severity=self._map_severity(result.get('level', 'note')),
                        confidence=0.9  # CodeQL has high confidence
                    ))
                    
        return results
    
    def _map_severity(self, level: str) -> str:
        """Map CodeQL severity to our format."""
        mapping = {
            'error': 'HIGH',
            'warning': 'MEDIUM',
            'note': 'LOW'
        }
        return mapping.get(level, 'MEDIUM')


class EnhancedMCPScanner:
    """Enhanced MCP Scanner with CodeQL integration."""
    
    def __init__(self):
        self.unified_scanner = UnifiedScanner()
        self.codeql = CodeQLIntegration()
        self.asr_calculator = EnhancedASRCalculator()
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan repository with enhanced analysis."""
        start_time = time.time()
        
        # Phase 1: Traditional unified scan
        print("Phase 1: Running unified scan...")
        unified_results = self.unified_scanner.scan_directory(repo_path)
        
        # Phase 2: CodeQL semantic analysis
        print("Phase 2: Running CodeQL analysis...")
        codeql_results = self.codeql.analyze_repository(repo_path)
        
        # Phase 3: Enhanced result fusion
        print("Phase 3: Fusing results...")
        enhanced_findings = self._fuse_results(
            unified_results.get('findings', []),
            codeql_results
        )
        
        # Phase 4: Enhanced ASR calculation
        enhanced_asr = self.asr_calculator.calculate_enhanced_asr(
            enhanced_findings, codeql_results
        )
        
        scan_time = time.time() - start_time
        
        return {
            'scan_summary': {
                'files_scanned': unified_results.get('scan_summary', {}).get('files_scanned', 0),
                'scan_time': scan_time,
                'vulnerabilities_found': len(enhanced_findings),
                'enhanced_asr_score': enhanced_asr,
                'traditional_asr_score': unified_results.get('scan_summary', {}).get('asr_score', 0),
                'codeql_findings': len(codeql_results),
                'severity_distribution': self._calculate_severity_distribution(enhanced_findings)
            },
            'findings': [self._finding_to_dict(f) for f in enhanced_findings],
            'codeql_results': [self._codeql_to_dict(r) for r in codeql_results],
            'enhancement_metrics': {
                'false_positive_reduction': self._calculate_fp_reduction(
                    unified_results.get('findings', []), enhanced_findings
                ),
                'semantic_confirmations': len([r for r in codeql_results if r.confidence > 0.8])
            }
        }
    
    def _fuse_results(self, unified_findings: List[Dict], 
                     codeql_results: List[CodeQLResult]) -> List[VulnerabilityFinding]:
        """Fuse unified and CodeQL results."""
        findings = []
        
        # Convert unified findings
        for finding_dict in unified_findings:
            finding = VulnerabilityFinding(
                severity=finding_dict.get('severity', 'MEDIUM'),
                category=finding_dict.get('category', 'unknown'),
                description=finding_dict.get('description', ''),
                file_path=finding_dict.get('file_path', ''),
                line_number=finding_dict.get('line_number', 0),
                code_snippet=finding_dict.get('code_snippet', ''),
                recommendation=finding_dict.get('recommendation', ''),
                cwe_id=finding_dict.get('cwe_id', ''),
                confidence=finding_dict.get('confidence', 0.5)
            )
            
            # Enhance with CodeQL confirmation
            semantic_boost = self._get_codeql_confirmation(finding, codeql_results)
            finding.confidence = min(finding.confidence * semantic_boost, 1.0)
            
            # Filter out low-confidence findings
            if finding.confidence > 0.3:
                findings.append(finding)
        
        # Add unique CodeQL findings
        for codeql_result in codeql_results:
            if not self._is_duplicate(codeql_result, findings):
                finding = self._codeql_to_finding(codeql_result)
                findings.append(finding)
        
        return findings
    
    def _get_codeql_confirmation(self, finding: VulnerabilityFinding,
                                codeql_results: List[CodeQLResult]) -> float:
        """Get CodeQL confirmation boost."""
        for result in codeql_results:
            if (result.file_path.endswith(Path(finding.file_path).name) and
                abs(result.start_line - finding.line_number) <= 2):
                return 1.4  # 40% boost
        return 1.0
    
    def _is_duplicate(self, codeql_result: CodeQLResult,
                     findings: List[VulnerabilityFinding]) -> bool:
        """Check if CodeQL result is duplicate."""
        for finding in findings:
            if (finding.file_path.endswith(Path(codeql_result.file_path).name) and
                abs(finding.line_number - codeql_result.start_line) <= 2):
                return True
        return False
    
    def _codeql_to_finding(self, result: CodeQLResult) -> VulnerabilityFinding:
        """Convert CodeQL result to finding."""
        return VulnerabilityFinding(
            severity=result.severity,
            category='codeql_finding',
            description=f"CodeQL: {result.message}",
            file_path=result.file_path,
            line_number=result.start_line,
            code_snippet="",
            recommendation="Review CodeQL finding and apply recommended fix",
            cwe_id=result.rule_id,
            confidence=result.confidence
        )
    
    def _calculate_severity_distribution(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Calculate severity distribution."""
        distribution = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CRITICAL': 0}
        for finding in findings:
            distribution[finding.severity] = distribution.get(finding.severity, 0) + 1
        return distribution
    
    def _calculate_fp_reduction(self, original: List[Dict], 
                               enhanced: List[VulnerabilityFinding]) -> float:
        """Calculate false positive reduction percentage."""
        if not original:
            return 0.0
        return max(0.0, (len(original) - len(enhanced)) / len(original) * 100)
    
    def _finding_to_dict(self, finding: VulnerabilityFinding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'severity': finding.severity,
            'category': finding.category,
            'description': finding.description,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'code_snippet': finding.code_snippet,
            'recommendation': finding.recommendation,
            'cwe_id': finding.cwe_id,
            'confidence': finding.confidence
        }
    
    def _codeql_to_dict(self, result: CodeQLResult) -> Dict[str, Any]:
        """Convert CodeQL result to dictionary."""
        return {
            'rule_id': result.rule_id,
            'message': result.message,
            'file_path': result.file_path,
            'start_line': result.start_line,
            'end_line': result.end_line,
            'severity': result.severity,
            'confidence': result.confidence
        }