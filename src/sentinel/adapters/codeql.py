"""CodeQL database optimization for large codebases."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any

import psutil
import yaml


class CodeQLOptimizer:
    """Optimized CodeQL database creation and analysis."""
    
    def __init__(self):
        self.codeql_path = self._find_codeql()
        self.system_resources = self._detect_system_resources()
        
    def _find_codeql(self) -> Optional[str]:
        """Find CodeQL CLI installation."""
        try:
            result = subprocess.run(['which', 'codeql'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def _detect_system_resources(self) -> Dict[str, int]:
        """Detect optimal system resources."""
        memory_gb = psutil.virtual_memory().total // (1024**3)
        cpu_cores = psutil.cpu_count(logical=False) or 4
        
        return {
            'ram_mb': int(memory_gb * 0.75 * 1024),  # 75% of available RAM
            'threads': min(cpu_cores, 8),            # Max 8 threads
            'temp_space_gb': 10                      # Reserve 10GB temp space
        }
    
    def create_optimized_database(self, source_root: str, language: str = 'python') -> Optional[str]:
        """Create optimized CodeQL database."""
        if not self.codeql_path:
            print("CodeQL not found, skipping database creation")
            return None
            
        try:
            # Create temporary database directory on fast storage
            temp_dir = tempfile.mkdtemp(prefix='codeql_db_')
            db_path = Path(temp_dir) / 'database'
            
            # Optimized database creation command
            cmd = [
                self.codeql_path, 'database', 'create',
                str(db_path),
                f'--language={language}',
                f'--source-root={source_root}',
                f'--ram={self.system_resources["ram_mb"]}',
                f'--threads={self.system_resources["threads"]}',
                '--overwrite',
                '--quiet'
            ]
            
            print(f"Creating optimized database with {self.system_resources['threads']} threads, "
                  f"{self.system_resources['ram_mb']}MB RAM...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"Database created successfully: {db_path}")
                return str(db_path)
            else:
                print(f"Database creation failed: {result.stderr}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None
                
        except subprocess.TimeoutExpired:
            print("Database creation timed out (5 minutes)")
            return None
        except Exception as e:
            print(f"Database creation error: {e}")
            return None
    
    def run_targeted_analysis(self, db_path: str, query_suite: str = 'mcp-critical') -> List[Dict[str, Any]]:
        """Run targeted analysis with optimized query suite."""
        if not self.codeql_path or not db_path:
            return []
            
        try:
            # Use targeted query suite
            suite_path = self._get_query_suite_path(query_suite)
            if not suite_path:
                print(f"Query suite {query_suite} not found")
                return []
            
            cmd = [
                self.codeql_path, 'database', 'analyze',
                db_path,
                suite_path,
                '--format=json',
                '--output=-',
                f'--threads={self.system_resources["threads"]}',
                '--quiet'
            ]
            
            print(f"Running targeted analysis with {query_suite} suite...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout) if result.stdout else {}
                    return self._parse_codeql_results(data)
                except json.JSONDecodeError:
                    print("Failed to parse CodeQL results")
                    return []
            else:
                print(f"Analysis failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print("Analysis timed out (3 minutes)")
            return []
        except Exception as e:
            print(f"Analysis error: {e}")
            return []
    
    def _get_query_suite_path(self, suite_name: str) -> Optional[str]:
        """Get path to query suite."""
        suite_mapping = {
            'mcp-critical': 'javascript-security-extended.qls',
            'mcp-full': 'javascript-security-and-quality.qls',
            'python-security': 'python-security-extended.qls'
        }
        
        suite_file = suite_mapping.get(suite_name)
        if not suite_file:
            return None
            
        # Try to find the suite in CodeQL installation
        try:
            result = subprocess.run([
                self.codeql_path, 'resolve', 'queries',
                suite_file
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return suite_file
        except:
            pass
            
        return None
    
    def _parse_codeql_results(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse CodeQL SARIF results."""
        results = []
        
        for run in data.get('runs', []):
            for result in run.get('results', []):
                for location in result.get('locations', []):
                    physical_location = location.get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    region = physical_location.get('region', {})
                    
                    results.append({
                        'rule_id': result.get('ruleId', ''),
                        'message': result.get('message', {}).get('text', ''),
                        'file_path': artifact_location.get('uri', ''),
                        'start_line': region.get('startLine', 0),
                        'end_line': region.get('endLine', 0),
                        'severity': self._map_severity(result.get('level', 'note')),
                        'confidence': 0.9  # CodeQL has high confidence
                    })
                    
        return results
    
    def _map_severity(self, level: str) -> str:
        """Map CodeQL severity levels."""
        mapping = {
            'error': 'HIGH',
            'warning': 'MEDIUM', 
            'note': 'LOW'
        }
        return mapping.get(level, 'MEDIUM')
    
    def cleanup_database(self, db_path: str):
        """Clean up temporary database."""
        if db_path and Path(db_path).exists():
            try:
                shutil.rmtree(Path(db_path).parent, ignore_errors=True)
                print(f"Cleaned up database: {db_path}")
            except Exception as e:
                print(f"Cleanup error: {e}")


class CodeQLConfig:
    """CodeQL configuration for large codebases."""
    
    @staticmethod
    def create_exclusion_config(repo_path: str) -> str:
        """Create CodeQL exclusion configuration."""
        config = {
            "paths-ignore": [
                "node_modules/**",
                "venv/**", 
                "env/**",
                ".git/**",
                "dist/**",
                "build/**",
                "coverage/**",
                "**/*.min.js",
                "**/*.bundle.js",
                "**/test/**",
                "**/tests/**",
                "**/__tests__/**",
                "**/*.test.*",
                "**/*.spec.*"
            ],
            "queries": [
                {
                    "name": "MCP Critical Security",
                    "uses": "security-extended"
                }
            ]
        }
        
        config_path = Path(repo_path) / '.github' / 'codeql-config.yml'
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        return str(config_path)