#!/usr/bin/env python3
"""Comprehensive Security Scanner with SECURITY.md check."""

import json
import subprocess
import re
from pathlib import Path
from datetime import datetime

class ComprehensiveSecurityScanner:
    """Scanner with security policy detection and manual review."""
    
    def __init__(self):
        self.manual_review_dir = Path("manualreview")
        self.manual_review_dir.mkdir(exist_ok=True)
        
        # High-confidence credential patterns
        self.credential_patterns = {
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'openai_key': r'sk-[a-zA-Z0-9]{48}',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        }
        
        # Bug bounty indicators
        self.bounty_patterns = [
            r'bug.?bounty', r'responsible.?disclosure', r'security.?reward',
            r'vulnerability.?disclosure', r'hackerone', r'bugcrowd'
        ]
    
    def scan_existing_repos(self):
        """Scan existing repositories in scans/popular_mcps."""
        
        base_path = Path("scans/popular_mcps")
        if not base_path.exists():
            return []
        
        repos = [d for d in base_path.iterdir() if d.is_dir()]
        return [str(repo) for repo in repos[:10]]  # Limit to 10
    
    def check_security_policy(self, repo_path: str) -> dict:
        """Check for SECURITY.md and bug bounty information."""
        
        repo_path = Path(repo_path)
        security_info = {
            'has_security_md': False,
            'security_file_path': None,
            'has_bug_bounty': False,
            'bug_bounty_details': [],
            'contact_info': []
        }
        
        # Look for security files
        security_files = [
            'SECURITY.md', 'security.md', 'Security.md',
            '.github/SECURITY.md', 'docs/SECURITY.md'
        ]
        
        for sec_file in security_files:
            sec_path = repo_path / sec_file
            if sec_path.exists():
                security_info['has_security_md'] = True
                security_info['security_file_path'] = str(sec_path)
                
                try:
                    content = sec_path.read_text(encoding='utf-8', errors='ignore')
                    security_info.update(self._analyze_security_content(content))
                except:
                    pass
                break
        
        return security_info
    
    def _analyze_security_content(self, content: str) -> dict:
        """Analyze SECURITY.md content."""
        
        content_lower = content.lower()
        analysis = {
            'has_bug_bounty': False,
            'bug_bounty_details': [],
            'contact_info': []
        }
        
        # Check for bug bounty patterns
        for pattern in self.bounty_patterns:
            if re.search(pattern, content_lower):
                analysis['has_bug_bounty'] = True
                break
        
        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
        analysis['contact_info'].extend(emails)
        
        return analysis
    
    def scan_for_credentials(self, repo_path: str) -> dict:
        """Scan for high-confidence credentials."""
        
        repo_path = Path(repo_path)
        findings = []
        
        for file_path in repo_path.rglob('*.py'):
            # Skip test files
            if any(test in str(file_path).lower() for test in ['test', 'spec', 'mock']):
                continue
            
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')
                
                for pattern_name, pattern in self.credential_patterns.items():
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        # Skip comments and docstrings
                        if line_content.strip().startswith('#') or '"""' in line_content:
                            continue
                        
                        findings.append({
                            'type': pattern_name,
                            'file_path': str(file_path),
                            'line_number': line_num,
                            'code_snippet': line_content.strip()
                        })
            except:
                continue
        
        return {
            'repository': repo_path.name,
            'secrets_detected': len(findings),
            'findings': findings
        }
    
    def create_manual_review_entry(self, repo_name: str, scan_results: dict, security_info: dict):
        """Create manual review entry."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create entry if there are findings or security policy
        if scan_results['secrets_detected'] > 0 or security_info['has_security_md']:
            
            review_data = {
                'timestamp': timestamp,
                'repository': repo_name,
                'scan_results': scan_results,
                'security_policy': security_info,
                'review_status': 'pending',
                'priority': 'high' if security_info['has_bug_bounty'] else 'medium',
                'notes': []
            }
            
            # Add priority notes
            if scan_results['secrets_detected'] > 0:
                review_data['notes'].append(f"⚠️ {scan_results['secrets_detected']} potential secrets")
            
            if security_info['has_bug_bounty']:
                review_data['notes'].append("🎯 Bug bounty program - handle carefully")
            
            if security_info['has_security_md']:
                review_data['notes'].append("📋 Security policy available")
            
            # Save to manual review folder
            review_file = self.manual_review_dir / f"{repo_name}_{timestamp}.json"
            with open(review_file, 'w') as f:
                json.dump(review_data, f, indent=2)
            
            return str(review_file)
        
        return None
    
    def run_scan(self):
        """Run comprehensive security scan."""
        
        print("🔍 Comprehensive Security Analysis - Additional Repositories")
        print("=" * 65)
        
        # Get existing repositories
        repos = self.scan_existing_repos()
        print(f"\n📁 Found {len(repos)} repositories to analyze")
        
        results = []
        manual_reviews = []
        
        for repo_path in repos:
            repo_name = Path(repo_path).name
            print(f"\n🔍 Analyzing: {repo_name}")
            
            # Check security policy
            security_info = self.check_security_policy(repo_path)
            has_security = security_info['has_security_md']
            has_bounty = security_info['has_bug_bounty']
            
            print(f"   📋 SECURITY.md: {'✅' if has_security else '❌'}")
            print(f"   🎯 Bug bounty: {'✅' if has_bounty else '❌'}")
            
            # Scan for credentials
            scan_results = self.scan_for_credentials(repo_path)
            secrets_count = scan_results['secrets_detected']
            print(f"   🚨 Secrets: {secrets_count}")
            
            # Create manual review if needed
            review_file = self.create_manual_review_entry(repo_name, scan_results, security_info)
            if review_file:
                manual_reviews.append(review_file)
                print(f"   📝 Manual review: ✅")
            
            results.append({
                'repository': repo_name,
                'security_info': security_info,
                'scan_results': scan_results,
                'manual_review_file': review_file
            })
        
        # Generate summary
        self._generate_summary(results, manual_reviews)
        return results
    
    def _generate_summary(self, results: list, manual_reviews: list):
        """Generate summary report."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Statistics
        total_repos = len(results)
        repos_with_security = sum(1 for r in results if r['security_info']['has_security_md'])
        repos_with_bounty = sum(1 for r in results if r['security_info']['has_bug_bounty'])
        total_secrets = sum(r['scan_results']['secrets_detected'] for r in results)
        
        print(f"\n📊 COMPREHENSIVE ANALYSIS SUMMARY")
        print("=" * 45)
        print(f"📁 Repositories analyzed: {total_repos}")
        print(f"📋 With SECURITY.md: {repos_with_security}")
        print(f"🎯 With bug bounty: {repos_with_bounty}")
        print(f"🚨 Total secrets detected: {total_secrets}")
        print(f"📝 Manual reviews created: {len(manual_reviews)}")
        
        # Show repositories with security policies
        if repos_with_security > 0:
            print(f"\n📋 Repositories with SECURITY.md:")
            for result in results:
                if result['security_info']['has_security_md']:
                    bounty_indicator = " 🎯" if result['security_info']['has_bug_bounty'] else ""
                    print(f"   • {result['repository']}{bounty_indicator}")
        
        # Show repositories with secrets
        if total_secrets > 0:
            print(f"\n🚨 Repositories with potential secrets:")
            for result in results:
                if result['scan_results']['secrets_detected'] > 0:
                    count = result['scan_results']['secrets_detected']
                    print(f"   • {result['repository']}: {count} findings")
        
        # Save summary
        summary_file = f"security_analysis_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'summary': {
                    'total_repositories': total_repos,
                    'repositories_with_security_md': repos_with_security,
                    'repositories_with_bug_bounty': repos_with_bounty,
                    'total_secrets_detected': total_secrets,
                    'manual_reviews_created': len(manual_reviews)
                },
                'results': results
            }, f, indent=2)
        
        print(f"\n💾 Summary saved to: {summary_file}")
        print(f"📁 Manual reviews in: {self.manual_review_dir}/")

def main():
    """Run comprehensive security analysis."""
    scanner = ComprehensiveSecurityScanner()
    return scanner.run_scan()

if __name__ == '__main__':
    main()