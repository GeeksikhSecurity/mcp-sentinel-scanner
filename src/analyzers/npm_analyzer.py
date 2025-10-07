"""npm package vulnerability analyzer."""
import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..mcp_sentinel_scanner import VulnerabilityFinding


class NpmAnalyzer:
    """Analyzer for npm package vulnerabilities."""
    
    def analyze(self, target: Path) -> List[VulnerabilityFinding]:
        """Analyze npm packages for vulnerabilities."""
        findings = []
        
        for package_json in self._find_package_files(target):
            findings.extend(self._analyze_package_json(package_json))
            findings.extend(self._run_npm_audit(package_json.parent))
        
        return findings
    
    def _find_package_files(self, target: Path) -> List[Path]:
        """Find package.json files."""
        if target.is_file() and target.name == "package.json":
            return [target]
        elif target.is_dir():
            return list(target.rglob("package.json"))
        return []
    
    def _analyze_package_json(self, package_json: Path) -> List[VulnerabilityFinding]:
        """Analyze package.json for issues."""
        findings = []
        
        try:
            data = json.loads(package_json.read_text())
            
            # Check for dependency confusion
            findings.extend(self._check_dependency_confusion(package_json, data))
            
            # Check for suspicious scripts
            findings.extend(self._check_suspicious_scripts(package_json, data))
            
        except (json.JSONDecodeError, OSError):
            pass
        
        return findings
    
    def _check_dependency_confusion(self, package_json: Path, data: dict) -> List[VulnerabilityFinding]:
        """Check for potential dependency confusion attacks."""
        findings = []
        suspicious_patterns = ["@internal/", "@company/", "@org/"]
        
        for dep_type in ["dependencies", "devDependencies"]:
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                if any(pattern in name for pattern in suspicious_patterns):
                    findings.append(VulnerabilityFinding(
                        severity="HIGH",
                        category="dependency_confusion",
                        description=f"Potential internal package in public registry: {name}",
                        file_path=str(package_json),
                        line_number=1,
                        code_snippet=f'"{name}": "{version}"',
                        recommendation="Verify package source and use private registry",
                        cwe_id="CWE-494",
                        confidence=0.7
                    ))
        
        return findings
    
    def _check_suspicious_scripts(self, package_json: Path, data: dict) -> List[VulnerabilityFinding]:
        """Check for suspicious npm scripts."""
        findings = []
        scripts = data.get("scripts", {})
        suspicious_commands = ["curl", "wget", "rm -rf", "eval", "exec"]
        
        for script_name, command in scripts.items():
            if any(cmd in command for cmd in suspicious_commands):
                findings.append(VulnerabilityFinding(
                    severity="MEDIUM",
                    category="suspicious_script",
                    description=f"Suspicious command in npm script: {script_name}",
                    file_path=str(package_json),
                    line_number=1,
                    code_snippet=f'"{script_name}": "{command}"',
                    recommendation="Review script for malicious commands",
                    cwe_id="CWE-78",
                    confidence=0.6
                ))
        
        return findings
    
    def _run_npm_audit(self, project_dir: Path) -> List[VulnerabilityFinding]:
        """Run npm audit for known vulnerabilities."""
        findings = []
        
        try:
            cmd = ["npm", "audit", "--json"]
            result = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return findings  # No vulnerabilities
            
            data = json.loads(result.stdout)
            vulnerabilities = data.get("vulnerabilities", {})
            
            for name, vuln in vulnerabilities.items():
                severity_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
                severity = severity_map.get(vuln.get("severity", "low"), "LOW")
                
                findings.append(VulnerabilityFinding(
                    severity=severity,
                    category="npm_vulnerability",
                    description=f"Known vulnerability in {name}: {vuln.get('title', 'Unknown')}",
                    file_path=str(project_dir / "package.json"),
                    line_number=1,
                    code_snippet=f"Vulnerable package: {name}",
                    recommendation=f"Update to version {vuln.get('fixAvailable', 'latest')}",
                    cwe_id="CWE-1104",
                    confidence=0.9
                ))
        
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        
        return findings