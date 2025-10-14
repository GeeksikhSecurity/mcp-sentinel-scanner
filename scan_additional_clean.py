#!/usr/bin/env python3
"""Scan additional repositories using the unified scanner - clean version."""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append('src')

from unified_scanner import UnifiedMCPScanner

def main():
    """Scan additional MCP repositories."""
    
    additional_repos = [
        'scans/popular_mcps/modelcontextprotocol-servers',
        'scans/popular_mcps/modelcontextprotocol-typescript-sdk', 
        'scans/popular_mcps/modelcontextprotocol-python-sdk',
        'scans/popular_mcps/mcp-inspector',
        'scans/popular_mcps/mcp-obsidian',
        'scans/popular_mcps/filesystem-server',
        'scans/popular_mcps/git-server',
        'scans/popular_mcps/memory-server',
        'scans/popular_mcps/time-server',
        'scans/popular_mcps/official-servers'
    ]
    
    print("🛡️ MCP Sentinel Scanner - Additional Repository Analysis")
    print("=" * 60)
    
    scanner = UnifiedMCPScanner()
    all_results = []
    
    for repo_path in additional_repos:
        if not Path(repo_path).exists():
            print(f"⚠️  Repository not found: {repo_path}")
            continue
            
        repo_name = Path(repo_path).name
        print(f"\n🔍 Scanning: {repo_name}")
        
        try:
            result = scanner.scan_repository(repo_path)
            result['repository_name'] = repo_name
            all_results.append(result)
            
            findings = result.get('findings', [])
            total = len(findings)
            high = sum(1 for f in findings if f.get('severity') == 'HIGH')
            medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
            
            print(f"   📊 Total: {total}, High: {high}, Medium: {medium}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Generate summary
    generate_summary(all_results)
    return all_results

def generate_summary(results):
    """Generate analysis summary."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Calculate stats
    total_repos = len(results)
    all_findings = []
    for result in results:
        all_findings.extend(result.get('findings', []))
    
    total_findings = len(all_findings)
    high_severity = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
    medium_severity = sum(1 for f in all_findings if f.get('severity') == 'MEDIUM')
    
    # Categories
    categories = {}
    for finding in all_findings:
        cat = finding.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    print(f"\n📊 ANALYSIS SUMMARY")
    print("=" * 40)
    print(f"📁 Repositories: {total_repos}")
    print(f"🔍 Total findings: {total_findings}")
    print(f"🚨 High severity: {high_severity}")
    print(f"⚠️  Medium severity: {medium_severity}")
    
    if categories:
        print(f"\n🏷️  Top Categories:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   • {cat}: {count}")
    
    # Save results
    output_file = f"additional_scan_{timestamp}.json"
    summary_data = {
        'timestamp': timestamp,
        'repositories_scanned': total_repos,
        'total_findings': total_findings,
        'high_severity': high_severity,
        'medium_severity': medium_severity,
        'categories': categories,
        'detailed_results': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    
    # Generate markdown report
    generate_report(summary_data, output_file.replace('.json', '_report.md'))

def generate_report(data, output_file):
    """Generate markdown report."""
    
    report = [
        "# 🛡️ Additional MCP Repositories Security Scan",
        "",
        f"**Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Repositories Scanned**: {data['repositories_scanned']}",
        "",
        "## 📊 Summary",
        "",
        f"- **Total Findings**: {data['total_findings']}",
        f"- **High Severity**: {data['high_severity']}",
        f"- **Medium Severity**: {data['medium_severity']}",
        ""
    ]
    
    if data['categories']:
        report.extend([
            "## 🏷️ Categories",
            "",
            "| Category | Count |",
            "|----------|-------|"
        ])
        
        for cat, count in sorted(data['categories'].items(), key=lambda x: x[1], reverse=True):
            report.append(f"| {cat} | {count} |")
        
        report.append("")
    
    # Repository details
    report.extend([
        "## 📁 Repository Details",
        "",
        "| Repository | Findings | High | Medium |",
        "|------------|----------|------|--------|"
    ])
    
    for result in data['detailed_results']:
        name = result['repository_name']
        findings = result.get('findings', [])
        total = len(findings)
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        
        report.append(f"| {name} | {total} | {high} | {medium} |")
    
    report.extend([
        "",
        "---",
        f"*Generated by MCP Sentinel Scanner on {data['timestamp']}*"
    ])
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"📄 Report saved to: {output_file}")

if __name__ == '__main__':
    main()