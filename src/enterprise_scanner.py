"""Enterprise-scale MCP scanner for multiple large codebases."""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional
import psutil
import subprocess

from .optimized_scanner_v21 import OptimizedScannerV21
from .codeql_optimizer import CodeQLOptimizer


@dataclass
class RepositoryConfig:
    """Repository configuration for batch processing."""
    path: str
    name: str
    priority: int = 1  # 1=high, 2=medium, 3=low
    max_size_mb: int = 10000  # 10GB default limit
    languages: List[str] = None


@dataclass
class BatchResult:
    """Result from batch repository processing."""
    repository: str
    status: str  # success, failed, skipped
    findings_count: int
    scan_time_seconds: float
    error_message: Optional[str] = None


class EnterpriseScanner:
    """Enterprise-scale scanner for multiple MCP repositories."""
    
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.scanner = OptimizedScannerV21()
        self.codeql_optimizer = CodeQLOptimizer()
        self.system_resources = self._detect_system_resources()
        
    def _detect_system_resources(self) -> Dict[str, Any]:
        """Detect optimal system resources for batch processing."""
        memory_gb = psutil.virtual_memory().total // (1024**3)
        cpu_cores = psutil.cpu_count(logical=False) or 4
        
        return {
            'total_memory_gb': memory_gb,
            'available_memory_gb': psutil.virtual_memory().available // (1024**3),
            'cpu_cores': cpu_cores,
            'optimal_concurrent': min(self.max_concurrent, cpu_cores // 2),
            'memory_per_job_gb': max(2, memory_gb // self.max_concurrent)
        }
    
    def analyze_repository_batch(self, repositories: List[RepositoryConfig]) -> List[BatchResult]:
        """Analyze multiple repositories in parallel with resource management."""
        print(f"Starting batch analysis of {len(repositories)} repositories")
        print(f"System resources: {self.system_resources['cpu_cores']} cores, "
              f"{self.system_resources['total_memory_gb']}GB RAM")
        print(f"Concurrent jobs: {self.system_resources['optimal_concurrent']}")
        
        # Sort by priority (high priority first)
        repositories.sort(key=lambda r: r.priority)
        
        results = []
        start_time = time.time()
        
        # Process repositories in batches to manage resources
        batch_size = self.system_resources['optimal_concurrent']
        
        for i in range(0, len(repositories), batch_size):
            batch = repositories[i:i + batch_size]
            print(f"\nProcessing batch {i//batch_size + 1}: {len(batch)} repositories")
            
            batch_results = self._process_batch_parallel(batch)
            results.extend(batch_results)
            
            # Resource monitoring and cooldown
            self._monitor_system_resources()
            if i + batch_size < len(repositories):
                print("Cooling down between batches...")
                time.sleep(10)  # Brief cooldown
        
        total_time = time.time() - start_time
        self._print_batch_summary(results, total_time)
        
        return results
    
    def _process_batch_parallel(self, batch: List[RepositoryConfig]) -> List[BatchResult]:
        """Process a batch of repositories in parallel."""
        results = []
        
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            # Submit all jobs
            future_to_repo = {
                executor.submit(self._analyze_single_repository, repo): repo 
                for repo in batch
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    result = future.result(timeout=1800)  # 30 minute timeout
                    results.append(result)
                    print(f"✅ {repo.name}: {result.findings_count} findings "
                          f"({result.scan_time_seconds:.1f}s)")
                except Exception as e:
                    error_result = BatchResult(
                        repository=repo.name,
                        status="failed",
                        findings_count=0,
                        scan_time_seconds=0,
                        error_message=str(e)
                    )
                    results.append(error_result)
                    print(f"❌ {repo.name}: {str(e)}")
        
        return results
    
    def _analyze_single_repository(self, repo: RepositoryConfig) -> BatchResult:
        """Analyze a single repository with resource monitoring."""
        start_time = time.time()
        
        try:
            # Check repository size
            if not self._validate_repository(repo):
                return BatchResult(
                    repository=repo.name,
                    status="skipped",
                    findings_count=0,
                    scan_time_seconds=0,
                    error_message="Repository validation failed"
                )
            
            # Run optimized scan
            findings = self.scanner.scan_directory(repo.path)
            
            # Apply enterprise filtering
            filtered_findings = self._apply_enterprise_filters(findings, repo)
            
            scan_time = time.time() - start_time
            
            return BatchResult(
                repository=repo.name,
                status="success",
                findings_count=len(filtered_findings),
                scan_time_seconds=scan_time
            )
            
        except Exception as e:
            return BatchResult(
                repository=repo.name,
                status="failed",
                findings_count=0,
                scan_time_seconds=time.time() - start_time,
                error_message=str(e)
            )
    
    def _validate_repository(self, repo: RepositoryConfig) -> bool:
        """Validate repository before scanning."""
        repo_path = Path(repo.path)
        
        # Check if path exists
        if not repo_path.exists():
            print(f"Repository path does not exist: {repo.path}")
            return False
        
        # Check repository size
        try:
            size_mb = sum(f.stat().st_size for f in repo_path.rglob('*') if f.is_file()) / (1024 * 1024)
            if size_mb > repo.max_size_mb:
                print(f"Repository too large: {size_mb:.1f}MB > {repo.max_size_mb}MB")
                return False
        except Exception as e:
            print(f"Error checking repository size: {e}")
            return False
        
        return True
    
    def _apply_enterprise_filters(self, findings: List[Dict], repo: RepositoryConfig) -> List[Dict]:
        """Apply enterprise-specific filtering rules."""
        filtered = []
        
        for finding in findings:
            # Skip low-confidence findings in large codebases
            if finding.get('confidence', 0) < 0.7:
                continue
                
            # Skip findings in vendor/third-party code
            file_path = finding.get('file_path', '')
            if any(exclude in file_path for exclude in [
                'node_modules', 'vendor', '.git', 'build', 'dist'
            ]):
                continue
            
            # Enterprise severity threshold
            severity = finding.get('severity', 'LOW')
            if severity in ['LOW', 'INFO']:
                continue
                
            filtered.append(finding)
        
        return filtered
    
    def _monitor_system_resources(self):
        """Monitor system resources and warn if approaching limits."""
        memory_percent = psutil.virtual_memory().percent
        cpu_percent = psutil.cpu_percent(interval=1)
        
        if memory_percent > 85:
            print(f"⚠️  High memory usage: {memory_percent:.1f}%")
        
        if cpu_percent > 90:
            print(f"⚠️  High CPU usage: {cpu_percent:.1f}%")
    
    def _print_batch_summary(self, results: List[BatchResult], total_time: float):
        """Print comprehensive batch processing summary."""
        successful = [r for r in results if r.status == "success"]
        failed = [r for r in results if r.status == "failed"]
        skipped = [r for r in results if r.status == "skipped"]
        
        total_findings = sum(r.findings_count for r in successful)
        avg_scan_time = sum(r.scan_time_seconds for r in successful) / len(successful) if successful else 0
        
        print(f"\n{'='*60}")
        print(f"ENTERPRISE BATCH SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total repositories: {len(results)}")
        print(f"Successful scans: {len(successful)}")
        print(f"Failed scans: {len(failed)}")
        print(f"Skipped scans: {len(skipped)}")
        print(f"Total findings: {total_findings}")
        print(f"Total time: {total_time:.1f}s")
        print(f"Average scan time: {avg_scan_time:.1f}s")
        print(f"Repositories/hour: {len(results) / (total_time / 3600):.1f}")
        
        if failed:
            print(f"\nFailed repositories:")
            for result in failed:
                print(f"  ❌ {result.repository}: {result.error_message}")


class EnterpriseReportGenerator:
    """Generate enterprise-level security reports."""
    
    @staticmethod
    def generate_executive_summary(results: List[BatchResult]) -> Dict[str, Any]:
        """Generate executive summary for leadership."""
        successful = [r for r in results if r.status == "success"]
        total_findings = sum(r.findings_count for r in successful)
        
        return {
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "repositories_scanned": len(successful),
            "total_security_findings": total_findings,
            "average_findings_per_repo": total_findings / len(successful) if successful else 0,
            "scan_success_rate": len(successful) / len(results) * 100 if results else 0,
            "high_risk_repositories": len([r for r in successful if r.findings_count > 10]),
            "recommendations": [
                "Focus remediation on repositories with >10 findings",
                "Implement security training for high-risk teams",
                "Consider automated security gates in CI/CD"
            ]
        }
    
    @staticmethod
    def export_sarif_enterprise(results: List[BatchResult], output_path: str):
        """Export results in SARIF format for enterprise tools."""
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        
        for result in results:
            if result.status == "success":
                run_data = {
                    "tool": {
                        "driver": {
                            "name": "MCP Sentinel Scanner Enterprise",
                            "version": "3.0.0"
                        }
                    },
                    "results": [],
                    "properties": {
                        "repository": result.repository,
                        "scan_time": result.scan_time_seconds,
                        "findings_count": result.findings_count
                    }
                }
                sarif_data["runs"].append(run_data)
        
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)


if __name__ == "__main__":
    # Example usage
    repositories = [
        RepositoryConfig("/path/to/repo1", "mcp-server-1", priority=1),
        RepositoryConfig("/path/to/repo2", "mcp-server-2", priority=2),
        RepositoryConfig("/path/to/repo3", "mcp-server-3", priority=1),
    ]
    
    scanner = EnterpriseScanner(max_concurrent=5)
    results = scanner.analyze_repository_batch(repositories)
    
    # Generate executive report
    summary = EnterpriseReportGenerator.generate_executive_summary(results)
    print(json.dumps(summary, indent=2))