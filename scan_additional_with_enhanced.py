#!/usr/bin/env python3
"""Scan additional repositories using the enhanced scanner."""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append('src')

from enhanced_mcp_scanner_v22 import EnhancedMCPScanner

def main():
    """Scan additional MCP repositories."""
    
    # Additional repositories to scan
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
    
    print("🛡️ MCP Sentinel Scanner v2.2 - Additional Repository Analysis")
    print("=" * 70)
    
    scanner = EnhancedMCPScanner()
    all_results = []
    
    for repo_path in additional_repos:
        if not Path(repo_path).exists():
            print(f"⚠️  Repository not found: {repo_path}")
            continue
            
        repo_name = Path(repo_path).name
        print(f"\n🔍 Scanning: {repo_name}")
        
        try:
            result = scanner.scan_repository(repo_path)
            result['repository_path'] = repo_path
            all_results.append(result)
            
            # Display summary
            total_findings = len(result.get('findings', []))
            high_severity = sum(1 for f in result.get('findings', []) if f.get('severity') == 'HIGH')
            
            print(f"   📊 Total findings: {total_findings}")
            print(f"   🚨 High severity: {high_severity}")
            
            if total_findings > 0:
                categories = {}
                for finding in result.get('findings', []):
                    cat = finding.get('category', 'unknown')
                    categories[cat] = categories.get(cat, 0) + 1
                
                print(f"   📋 Categories: {dict(list(categories.items())[:3])}")
            
        except Exception as e:
            print(f"   ❌ Error scanning {repo_name}: {e}")
            continue
    
    # Generate comprehensive summary
    generate_comprehensive_summary(all_results)
    
    return all_results

def generate_comprehensive_summary(results):
    """Generate comprehensive analysis summary."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Calculate statistics
    total_repos = len(results)
    total_findings = sum(len(r.get('findings', [])) for r in results)
    total_high_severity = sum(sum(1 for f in r.get('findings', []) if f.get('severity') == 'HIGH') for r in results)
    
    # Category analysis
    all_categories = {}
    for result in results:
        for finding in result.get('findings', []):
            cat = finding.get('category', 'unknown')
            all_categories[cat] = all_categories.get(cat, 0) + 1
    
    # File type analysis
    file_types = {}
    for result in results:
        for finding in result.get('findings', []):
            file_path = finding.get('file_path', '')
            ext = Path(file_path).suffix or 'no_extension'
            file_types[ext] = file_types.get(ext, 0) + 1
    
    print(f"\n📊 COMPREHENSIVE ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"📁 Repositories scanned: {total_repos}")
    print(f"🔍 Total findings: {total_findings}")
    print(f"🚨 High severity findings: {total_high_severity}")
    print(f"📈 Average findings per repo: {total_findings/total_repos:.1f}")
    
    print(f"\n🏷️  Top Categories:")
    for cat, count in sorted(all_categories.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   • {cat}: {count}")
    
    print(f"\n📄 File Types:")
    for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   • {ext}: {count}")
    
    # Save detailed results
    output_file = f"additional_repos_scan_{timestamp}.json"
    summary_data = {
        'scan_metadata': {
            'timestamp': timestamp,
            'scanner_version': '2.2_enhanced',
            'repositories_scanned': total_repos
        },
        'summary_statistics': {
            'total_findings': total_findings,
            'high_severity_findings': total_high_severity,
            'average_findings_per_repo': total_findings/total_repos if total_repos > 0 else 0,
            'categories': all_categories,
            'file_types': file_types
        },
        'detailed_results': results
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    # Generate markdown report
    generate_markdown_report(summary_data, output_file.replace('.json', '_report.md'))

def generate_markdown_report(data, output_file):
    """Generate markdown report."""
    
    timestamp = data['scan_metadata']['timestamp']
    stats = data['summary_statistics']
    
    report = [
        "# 🛡️ Additional MCP Repositories Security Scan Report",
        "",
        f"**Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Scanner Version**: {data['scan_metadata']['scanner_version']}",
        f"**Repositories Analyzed**: {data['scan_metadata']['repositories_scanned']}",
        "",
        "## 📊 Executive Summary",
        "",
        f"- **Total Security Findings**: {stats['total_findings']}",
        f"- **High Severity Issues**: {stats['high_severity_findings']}",
        f"- **Average Findings per Repository**: {stats['average_findings_per_repo']:.1f}",
        "",
        "## 🏷️ Finding Categories",
        "",
        "| Category | Count | Percentage |",
        "|----------|-------|------------|"
    ]
    
    total = stats['total_findings']
    for cat, count in sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        report.append(f"| {cat} | {count} | {pct:.1f}% |")
    
    report.extend([
        "",
        "## 📄 File Type Distribution",
        "",
        "| File Type | Findings |",
        "|-----------|----------|"
    ])
    
    for ext, count in sorted(stats['file_types'].items(), key=lambda x: x[1], reverse=True):
        report.append(f"| {ext} | {count} |")
    
    report.extend([
        "",
        "## 📁 Repository Details",
        "",
        "| Repository | Total Findings | High Severity | Top Category |",
        "|------------|----------------|---------------|--------------|"
    ])
    
    for result in data['detailed_results']:
        repo_name = Path(result['repository_path']).name
        total_findings = len(result.get('findings', []))
        high_sev = sum(1 for f in result.get('findings', []) if f.get('severity') == 'HIGH')
        
        # Find top category
        cats = {}
        for f in result.get('findings', []):
            cat = f.get('category', 'none')
            cats[cat] = cats.get(cat, 0) + 1
        top_cat = max(cats.items(), key=lambda x: x[1])[0] if cats else 'none'
        
        report.append(f"| {repo_name} | {total_findings} | {high_sev} | {top_cat} |")
    
    report.extend([
        "",
        "## 🎯 Key Insights",
        "",
        f"1. **Security Posture**: {stats['high_severity_findings']} critical issues identified across {data['scan_metadata']['repositories_scanned']} repositories",
        f"2. **Common Patterns**: Most findings relate to {max(stats['categories'].items(), key=lambda x: x[1])[0] if stats['categories'] else 'N/A'}",
        f"3. **File Types**: {max(stats['file_types'].items(), key=lambda x: x[1])[0] if stats['file_types'] else 'N/A'} files contain the most issues",
        "",
        "## 💡 Recommendations",
        "",
        "1. **Immediate Action**: Address all HIGH severity findings",
        "2. **Pattern Analysis**: Focus on the most common vulnerability categories",
        "3. **Preventive Measures**: Implement security scanning in CI/CD pipelines",
        "",
        "---",
        f"*Generated by MCP Sentinel Scanner v{data['scan_metadata']['scanner_version']} on {timestamp}*"
    ])
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"📄 Markdown report saved to: {output_file}")

if __name__ == '__main__':
    main()