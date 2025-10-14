#!/usr/bin/env python3
"""
E-commerce Project Security Scanner
Combines CodeQL database creation with MCP Sentinel Scanner analysis
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

# Default project paths - can be overridden via environment variables
PROJECT_PATH = os.getenv('ECOMMERCE_PROJECT_PATH', "/Volumes/2TBSSD/Development/Git/Clients/hkchawla1-e-commerce-02f3ff23e870")
CODEQL_DB_PATH = os.getenv('CODEQL_DB_PATH', "/Volumes/2TBSSD/Development/Git/Clients/hkchawla1-e-commerce-codeql")
CUSTOM_QUERIES_PATH = os.getenv('CUSTOM_QUERIES_PATH', "/Volumes/2TBSSD/Development/Git/Work/codescan/queries")
CODESCAN_CONFIG = os.getenv('CODESCAN_CONFIG', "/Volumes/2TBSSD/Development/Git/Work/codescan/configs/codeql-config.yml")

class EcommerceScanner:
    """E-commerce security scanner combining CodeQL and MCP Sentinel analysis"""
    
    def __init__(self, project_path: Optional[str] = None, db_path: Optional[str] = None):
        self.project_path = Path(project_path or PROJECT_PATH)
        self.db_path = Path(db_path or CODEQL_DB_PATH)
        self.custom_queries_path = Path(CUSTOM_QUERIES_PATH)
        self.config_path = Path(CODESCAN_CONFIG)
        self.microservices = [
            'abandonedService', 'bneedService', 'categoryService', 
            'discountService', 'guestService', 'order-management',
            'posService', 'productService', 'reviewService',
            'shipping-aggregators', 'ShippingService'
        ]
        
    def validate_environment(self) -> bool:
        """Validate CodeQL CLI and project structure"""
        print("🔍 Validating environment...")
        
        # Check CodeQL CLI
        try:
            result = subprocess.run(['codeql', 'version'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("❌ CodeQL CLI not found. Please install CodeQL CLI.")
                return False
            print(f"✅ CodeQL CLI found: {result.stdout.strip()}")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"❌ CodeQL CLI error: {e}")
            return False
            
        # Check project exists
        if not self.project_path.exists():
            print(f"❌ Project path not found: {self.project_path}")
            return False
            
        # Check custom queries path
        if not self.custom_queries_path.exists():
            print(f"❌ Custom queries path not found: {self.custom_queries_path}")
            return False
            
        print(f"✅ Project found: {self.project_path}")
        print(f"✅ Custom queries found: {self.custom_queries_path}")
        return True
        
    def create_codeql_database(self) -> bool:
        """Create CodeQL database for the entire e-commerce project"""
        print(f"\n🏗️ Creating CodeQL database at: {self.db_path}")
        
        # Remove existing database safely
        if self.db_path.exists():
            print("🗑️ Removing existing database...")
            try:
                subprocess.run(['rm', '-rf', str(self.db_path)], check=True, timeout=30)
            except subprocess.TimeoutExpired:
                print("⚠️ Database removal timed out, continuing...")
            
        # Create database directory
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        print(f"📦 Found {len(self.microservices)} microservices to analyze")
        
        # Create unified database with comprehensive config
        cmd = [
            'codeql', 'database', 'create', str(self.db_path),
            '--language=javascript',
            f'--source-root={self.project_path}',
            '--overwrite',
            '--threads=4',
            '--ram=4096'
        ]
        
        print(f"🔧 Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, cwd=self.project_path, capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                print(f"❌ Database creation failed: {result.stderr}")
                return False
                
            print("✅ CodeQL database created successfully!")
            return True
            
        except subprocess.TimeoutExpired:
            print("❌ Database creation timed out after 30 minutes")
            return False
        except Exception as e:
            print(f"❌ Error creating database: {e}")
            return False
            
    def run_codeql_analysis(self) -> Dict:
        """Run comprehensive CodeQL security analysis with custom queries"""
        print("\n🔍 Running Comprehensive Node.js & Angular Security Scan...")
        
        results = {}
        
        # Compile custom queries first
        if self.custom_queries_path.exists():
            print("🔧 Compiling custom queries...")
            try:
                compile_cmd = ['codeql', 'query', 'compile', str(self.custom_queries_path), '--threads=4']
                result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print("✅ Custom queries compiled successfully")
                else:
                    print(f"⚠️ Custom queries compilation failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("⚠️ Query compilation timed out")
            except Exception as e:
                print(f"⚠️ Error compiling custom queries: {e}")
        
        # Define analysis configurations
        analyses = self._get_analysis_configurations()
        
        # Run analyses efficiently
        for analysis_name, query_paths in analyses:
            if not query_paths:
                continue
                
            success = self._run_single_analysis(analysis_name, query_paths)
            if success:
                results[analysis_name] = str(self.db_path / f"results-{analysis_name}.sarif")
                
        return results
    
    def _get_analysis_configurations(self) -> List[tuple]:
        """Get analysis configurations based on available query paths"""
        return [
            ('comprehensive-security', [str(self.custom_queries_path), 'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls']),
            ('custom-security', [f'{self.custom_queries_path}/security'] if (self.custom_queries_path / 'security').exists() else []),
            ('pci-compliance', [f'{self.custom_queries_path}/pci-compliance'] if (self.custom_queries_path / 'pci-compliance').exists() else []),
            ('performance', [f'{self.custom_queries_path}/performance'] if (self.custom_queries_path / 'performance').exists() else []),
            ('ai-security', [f'{self.custom_queries_path}/ai-security'] if (self.custom_queries_path / 'ai-security').exists() else [])
        ]
    
    def _run_single_analysis(self, analysis_name: str, query_paths: List[str]) -> bool:
        """Run a single CodeQL analysis"""
        output_file = self.db_path / f"results-{analysis_name}.sarif"
        
        cmd = [
            'codeql', 'database', 'analyze', str(self.db_path),
            *query_paths,
            '--format=sarif-latest',
            f'--output={output_file}',
            '--threads=4',
            '--ram=4096',
            '--timeout=3600'
        ]
        
        print(f"🔧 Running {analysis_name} analysis...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if result.returncode == 0:
                print(f"✅ {analysis_name} analysis completed")
                return True
            else:
                print(f"❌ {analysis_name} analysis failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ {analysis_name} analysis timed out")
            return False
        except Exception as e:
            print(f"❌ Error running {analysis_name}: {e}")
            return False
        
    def run_mcp_sentinel_scan(self) -> Optional[str]:
        """Run MCP Sentinel Scanner on the project"""
        print("\n🛡️ Running MCP Sentinel Scanner...")
        
        # Create output directory
        output_dir = self.db_path / "mcp-sentinel-results"
        output_dir.mkdir(exist_ok=True)
        
        # Run unified scan
        output_file = output_dir / "security-report.html"
        
        cmd = [
            'python', '-m', 'scripts.sentinel_cli',
            str(self.project_path),
            '--unified',
            '--format', 'html',
            '-o', str(output_file),
            '--exclude', 'node_modules', '*.d.ts', 'dist', '.git', 'codeql'
        ]
        
        try:
            print(f"🔧 Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  cwd=Path(__file__).parent.parent, timeout=1800)
            
            if result.returncode == 0:
                print("✅ MCP Sentinel scan completed successfully!")
                print(f"📊 Report generated: {output_file}")
                return str(output_file)
            else:
                print(f"❌ MCP Sentinel scan failed: {result.stderr}")
                if result.stdout:
                    print(f"stdout: {result.stdout}")
                return None
                
        except subprocess.TimeoutExpired:
            print("❌ MCP Sentinel scan timed out after 30 minutes")
            return None
        except Exception as e:
            print(f"❌ Error running MCP Sentinel scan: {e}")
            return None
            
    def generate_summary_report(self, codeql_results: Dict, mcp_report: Optional[str]) -> None:
        """Generate a comprehensive summary report"""
        print("\n📊 Generating summary report...")
        
        summary = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "project_path": str(self.project_path),
            "database_path": str(self.db_path),
            "codeql_results": codeql_results,
            "mcp_sentinel_report": mcp_report,
            "microservices_analyzed": self.microservices
        }
        
        summary_file = self.db_path / "scan-summary.json"
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
        except IOError as e:
            print(f"❌ Error writing summary file: {e}")
            return
            
        print(f"✅ Summary report saved: {summary_file}")
        
        # Print summary
        print("\n" + "="*60)
        print("🎯 SCAN SUMMARY")
        print("="*60)
        print(f"📁 Project: {self.project_path.name}")
        print(f"🗄️ Database: {self.db_path}")
        print(f"🔍 CodeQL Results: {len(codeql_results)} query suites")
        print(f"🛡️ MCP Sentinel: {'✅ Success' if mcp_report else '❌ Failed'}")
        print(f"📊 Summary: {summary_file}")
        print("="*60)
        
    def run_complete_scan(self) -> None:
        """Run the complete security scanning workflow"""
        print("🚀 Starting E-commerce Security Scan")
        print("="*60)
        
        if not self.validate_environment():
            sys.exit(1)
            
        if not self.create_codeql_database():
            sys.exit(1)
            
        codeql_results = self.run_codeql_analysis()
        mcp_report = self.run_mcp_sentinel_scan()
        
        self.generate_summary_report(codeql_results, mcp_report)
        
        print("\n🎉 Security scan completed successfully!")
        print(f"📁 All results saved to: {self.db_path}")

def main():
    scanner = EcommerceScanner()
    scanner.run_complete_scan()

if __name__ == "__main__":
    main()