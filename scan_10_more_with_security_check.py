#!/usr/bin/env python3
"""Scan 10 more repos with SECURITY.md check and manual review folder."""

import json
import subprocess
from pathlib import Path
from datetime import datetime
import re

class SecurityAwareScanner:
    """Scanner with security policy and bug bounty detection."""
    
    def __init__(self):
        self.manual_review_dir = Path("manualreview")
        self.manual_review_dir.mkdir(exist_ok=True)
        
        # Bug bounty indicators
        self.bounty_patterns = [
            r'bug.?bounty', r'responsible.?disclosure', r'security.?reward',
            r'vulnerability.?disclosure', r'hackerone', r'bugcrowd',
            r'reward.?program', r'bounty.?program'
        ]
    
    def clone_additional_repos(self):
        """Clone 10 additional MCP-related repositories."""
        
        additional_repos = [
            'https://github.com/punkpeye/mcp-youtube.git',
            'https://github.com/adhikasp/mcp-pandoc.git', 
            'https://github.com/rusiaaman/wcgw-mcp.git',
            'https://github.com/modelcontextprotocol/create-mcp-server.git',
            'https://github.com/modelcontextprotocol/docs.git',
            'https://github.com/wong2/mcp-server-github.git',
            'https://github.com/adhikasp/mcp-brave-search.git',
            'https://github.com/rusiaaman/mcp-simple-git-server.git',
            'https://github.com/adhikasp/mcp-arxiv.git',
            'https://github.com/punkpeye/mcp-linear.git'
        ]
        
        cloned_repos = []
        base_path = Path("scans/additional_repos")
        base_path.mkdir(parents=True, exist_ok=True)
        
        for repo_url in additional_repos:
            repo_name = self._extract_repo_name(repo_url)
            target_path = base_path / repo_name
            
            if target_path.exists():
                cloned_repos.append(str(target_path))
                continue
            
            try:
                subprocess.run(['git', 'clone', repo_url, str(target_path)], 
                             capture_output=True, timeout=60, check=True)
                cloned_repos.append(str(target_path))
                print(f"✅ Cloned: {repo_name}")
            except:
                print(f"❌ Failed: {repo_name}")
        
        return cloned_repos
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL."""
        parts = repo_url.rstrip('/').replace('.git', '').split('/')
        return f"{parts[-2]}-{parts[-1]}"
    
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
                
                # Analyze content
                try:
                    content = sec_path.read_text(encoding='utf-8', errors='ignore')
                    security_info.update(self._analyze_security_content(content))
                except:
                    pass
                break
        
        return security_info
    
    def _analyze_security_content(self, content: str) -> dict:
        """Analyze SECURITY.md content for bug bounty info."""
        
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
        
        # Extract contact information
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, content)
        analysis['contact_info'].extend(emails)
        
        # Extract bug bounty details
        if analysis['has_bug_bounty']:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if any(re.search(pattern, line.lower()) for pattern in self.bounty_patterns):
                    # Get context around the match
                    context_start = max(0, i-2)
                    context_end = min(len(lines), i+3)
                    context = '\n'.join(lines[context_start:context_end])
                    analysis['bug_bounty_details'].append(context.strip())
        
        return analysis
    
    def scan_with_final_scanner(self, repo_path: str) -> dict:
        """Scan repository using the final credential scanner."""
        
        from final_credential_scanner import FinalCredentialScanner
        scanner = FinalCredentialScanner()
        return scanner.scan_for_secrets(repo_path)
    
    def create_manual_review_entry(self, repo_name: str, scan_results: dict, security_info: dict):
        """Create manual review entry for high-confidence findings."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Only create entry if there are findings or security policy
        if scan_results['secrets_detected'] > 0 or security_info['has_security_md']:
            
            review_data = {
                'timestamp': timestamp,
                'repository': repo_name,
                'scan_results': scan_results,
                'security_policy': security_info,
                'review_status': 'pending',
                'notes': []
            }
            
            # Add notes based on findings
            if scan_results['secrets_detected'] > 0:
                review_data['notes'].append(f"⚠️ {scan_results['secrets_detected']} potential secrets detected")
            
            if security_info['has_bug_bounty']:
                review_data['notes'].append("🎯 Bug bounty program detected - handle with care")
            
            if security_info['has_security_md']:
                review_data['notes'].append("📋 Security policy available")
            
            # Save to manual review folder
            review_file = self.manual_review_dir / f"{repo_name}_{timestamp}.json"
            with open(review_file, 'w') as f:
                json.dump(review_data, f, indent=2)
            
            return str(review_file)
        
        return None
    
    def run_comprehensive_scan(self):
        """Run comprehensive scan of 10 additional repositories."""
        
        print("🔍 Comprehensive Security Scan - 10 Additional Repositories")
        print("=" * 70)
        
        # Clone repositories
        print("\n📥 Cloning repositories...")
        cloned_repos = self.clone_additional_repos()
        
        results = []
        manual_reviews = []
        
        print(f"\n🛡️ Scanning {len(cloned_repos)} repositories...")
        
        for repo_path in cloned_repos:
            repo_name = Path(repo_path).name
            print(f"\n🔍 Analyzing: {repo_name}")
            
            # Check security policy
            security_info = self.check_security_policy(repo_path)
            print(f"   📋 Security.md: {'✅' if security_info['has_security_md'] else '❌'}")
            print(f"   🎯 Bug bounty: {'✅' if security_info['has_bug_bounty'] else '❌'}")
            
            # Scan for secrets
            scan_results = self.scan_with_final_scanner(repo_path)
            print(f"   🚨 Secrets: {scan_results['secrets_detected']}")
            
            # Create manual review entry if needed
            review_file = self.create_manual_review_entry(repo_name, scan_results, security_info)
            if review_file:
                manual_reviews.append(review_file)
                print(f"   📝 Manual review: {Path(review_file).name}")
            
            results.append({
                'repository': repo_name,
                'path': repo_path,
                'security_info': security_info,
                'scan_results': scan_results,
                'manual_review_file': review_file
            })
        
        # Generate summary
        self._generate_summary(results, manual_reviews)
        
        return results
    
    def _generate_summary(self, results: list, manual_reviews: list):
        """Generate comprehensive summary."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Calculate statistics
        total_repos = len(results)
        repos_with_security = sum(1 for r in results if r['security_info']['has_security_md'])
        repos_with_bounty = sum(1 for r in results if r['security_info']['has_bug_bounty'])
        total_secrets = sum(r['scan_results']['secrets_detected'] for r in results)
        repos_with_secrets = sum(1 for r in results if r['scan_results']['secrets_detected'] > 0)
        
        print(f"\n📊 COMPREHENSIVE SCAN SUMMARY")
        print("=" * 50)
        print(f"📁 Repositories scanned: {total_repos}")
        print(f"📋 With SECURITY.md: {repos_with_security}")
        print(f"🎯 With bug bounty: {repos_with_bounty}")
        print(f"🚨 Total secrets found: {total_secrets}")
        print(f"⚠️  Repos with secrets: {repos_with_secrets}")
        print(f"📝 Manual reviews created: {len(manual_reviews)}")
        
        # Save comprehensive results
        summary_file = f"comprehensive_scan_summary_{timestamp}.json"
        summary_data = {
            'timestamp': timestamp,
            'total_repositories': total_repos,
            'repositories_with_security_md': repos_with_security,
            'repositories_with_bug_bounty': repos_with_bounty,
            'total_secrets_detected': total_secrets,
            'repositories_with_secrets': repos_with_secrets,
            'manual_reviews_created': len(manual_reviews),
            'detailed_results': results,
            'manual_review_files': manual_reviews
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        print(f"\n💾 Summary saved to: {summary_file}")
        print(f"📁 Manual reviews in: {self.manual_review_dir}")

def main():
    """Run comprehensive security scan."""
    scanner = SecurityAwareScanner()
    return scanner.run_comprehensive_scan()

if __name__ == '__main__':
    main()