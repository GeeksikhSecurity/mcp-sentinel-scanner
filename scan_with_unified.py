#!/usr/bin/env python3
"""Scan additional repositories using the proven unified scanner."""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append('src')

from unified_scanner import UnifiedMCPScanner

def main():
    """Scan additional MCP repositories with unified scanner."""
    
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
    
    print("🛡️ MCP Sentinel Scanner - Unified Analysis of Additional Repositories")
    print("=" * 75)
    
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
            result['repository_path'] = repo_path
            all_results.append(result)
            
            # Display summary
            findings = result.get('findings', [])
            total_findings = len(findings)
            high_severity = sum(1 for f in findings if f.get('severity') == 'HIGH')
            medium_severity = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
            
            print(f"   📊 Total findings: {total_findings}")
            print(f"   🚨 High severity: {high_severity}")
            print(f"   ⚠️  Medium severity: {medium_severity}")
            
            if total_findings > 0:
                # Show top categories
                categories = {}
                for finding in findings:
                    cat = finding.get('category', 'unknown')
                    categories[cat] = categories.get(cat, 0) + 1
                
                top_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]
                print(f"   📋 Top categories: {dict(top_cats)}")
            
        except Exception as e:
            print(f"   ❌ Error scanning {repo_name}: {e}")
            continue
    
    # Generate comprehensive analysis
    generate_analysis_report(all_results)
    
    return all_results

def generate_analysis_report(results):
    """Generate comprehensive analysis report."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Calculate comprehensive statistics
    total_repos = len(results)
    all_findings = []
    for result in results:
        all_findings.extend(result.get('findings', []))
    
    total_findings = len(all_findings)
    high_severity = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
    medium_severity = sum(1 for f in all_findings if f.get('severity') == 'MEDIUM')
    
    # Category breakdown
    categories = {}
    for finding in all_findings:
        cat = finding.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    # File type analysis
    file_extensions = {}
    for finding in all_findings:
        file_path = finding.get('file_path', '')
        ext = Path(file_path).suffix or 'no_extension'
        file_extensions[ext] = file_extensions.get(ext, 0) + 1
    
    # Repository ranking by findings
    repo_stats = []
    for result in results:
        findings = result.get('findings', [])
        repo_stats.append({
            'name': result['repository_name'],
            'total': len(findings),
            'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        })
    
    repo_stats.sort(key=lambda x: x['total'], reverse=True)
    
    print(f"\n📊 UNIFIED SCANNER ANALYSIS RESULTS")
    print("=" * 55)
    print(f"📁 Repositories analyzed: {total_repos}")
    print(f"🔍 Total security findings: {total_findings}")
    print(f"🚨 High severity: {high_severity}")
    print(f"⚠️  Medium severity: {medium_severity}")
    print(f"📈 Average per repository: {total_findings/total_repos:.1f}")
    
    if categories:
        print(f"\n🏷️  Top Vulnerability Categories:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
            pct = (count / total_findings * 100) if total_findings > 0 else 0\n            print(f\"   • {cat}: {count} ({pct:.1f}%)\")\n    \n    if file_extensions:\n        print(f\"\\n📄 Most Affected File Types:\")\n        for ext, count in sorted(file_extensions.items(), key=lambda x: x[1], reverse=True)[:5]:\n            print(f\"   • {ext}: {count} findings\")\n    \n    print(f\"\\n🏆 Repository Security Ranking:\")\n    for i, repo in enumerate(repo_stats[:5], 1):\n        print(f\"   {i}. {repo['name']}: {repo['total']} total ({repo['high']} high, {repo['medium']} medium)\")\n    \n    # Save comprehensive results\n    output_data = {\n        'scan_metadata': {\n            'timestamp': timestamp,\n            'scanner_type': 'unified',\n            'repositories_scanned': total_repos,\n            'scan_date': datetime.now().isoformat()\n        },\n        'summary_statistics': {\n            'total_findings': total_findings,\n            'high_severity_findings': high_severity,\n            'medium_severity_findings': medium_severity,\n            'average_findings_per_repo': total_findings/total_repos if total_repos > 0 else 0,\n            'vulnerability_categories': categories,\n            'file_type_distribution': file_extensions,\n            'repository_rankings': repo_stats\n        },\n        'detailed_scan_results': results\n    }\n    \n    # Save JSON results\n    json_file = f\"unified_additional_scan_{timestamp}.json\"\n    with open(json_file, 'w') as f:\n        json.dump(output_data, f, indent=2)\n    \n    print(f\"\\n💾 Comprehensive results saved to: {json_file}\")\n    \n    # Generate markdown report\n    md_file = json_file.replace('.json', '_report.md')\n    generate_markdown_summary(output_data, md_file)\n    \n    return output_data\n\ndef generate_markdown_summary(data, output_file):\n    \"\"\"Generate executive markdown summary.\"\"\"\n    \n    stats = data['summary_statistics']\n    meta = data['scan_metadata']\n    \n    report = [\n        \"# 🛡️ MCP Additional Repositories Security Analysis\",\n        \"\",\n        f\"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\",\n        f\"**Scanner**: Unified MCP Scanner\",\n        f\"**Repositories**: {meta['repositories_scanned']}\",\n        \"\",\n        \"## 🎯 Executive Summary\",\n        \"\",\n        f\"- **Total Security Findings**: {stats['total_findings']}\",\n        f\"- **Critical Issues (HIGH)**: {stats['high_severity_findings']}\",\n        f\"- **Medium Priority Issues**: {stats['medium_severity_findings']}\",\n        f\"- **Average Issues per Repository**: {stats['average_findings_per_repo']:.1f}\",\n        \"\"\n    ]\n    \n    # Vulnerability categories table\n    if stats['vulnerability_categories']:\n        report.extend([\n            \"## 🏷️ Vulnerability Categories\",\n            \"\",\n            \"| Category | Count | % of Total |\",\n            \"|----------|-------|------------|\"\n        ])\n        \n        total = stats['total_findings']\n        for cat, count in sorted(stats['vulnerability_categories'].items(), key=lambda x: x[1], reverse=True):\n            pct = (count / total * 100) if total > 0 else 0\n            report.append(f\"| {cat} | {count} | {pct:.1f}% |\")\n        \n        report.append(\"\")\n    \n    # Repository rankings\n    report.extend([\n        \"## 📊 Repository Security Assessment\",\n        \"\",\n        \"| Repository | Total Issues | High Severity | Medium Severity |\",\n        \"|------------|--------------|---------------|------------------|\"\n    ])\n    \n    for repo in stats['repository_rankings']:\n        report.append(f\"| {repo['name']} | {repo['total']} | {repo['high']} | {repo['medium']} |\")\n    \n    # Key insights\n    top_category = max(stats['vulnerability_categories'].items(), key=lambda x: x[1])[0] if stats['vulnerability_categories'] else 'N/A'\n    most_affected_repo = stats['repository_rankings'][0]['name'] if stats['repository_rankings'] else 'N/A'\n    \n    report.extend([\n        \"\",\n        \"## 🔍 Key Insights\",\n        \"\",\n        f\"1. **Primary Concern**: {top_category} vulnerabilities are most common\",\n        f\"2. **Most Affected**: {most_affected_repo} repository needs immediate attention\",\n        f\"3. **Overall Risk**: {stats['high_severity_findings']} critical issues require immediate remediation\",\n        \"\",\n        \"## 💡 Recommendations\",\n        \"\",\n        \"1. **Immediate**: Address all HIGH severity findings\",\n        \"2. **Short-term**: Implement security scanning in CI/CD pipelines\",\n        \"3. **Long-term**: Regular security audits and developer training\",\n        \"\",\n        \"---\",\n        f\"*Generated by MCP Sentinel Scanner on {meta['timestamp']}*\"\n    ])\n    \n    with open(output_file, 'w') as f:\n        f.write('\\n'.join(report))\n    \n    print(f\"📄 Executive summary saved to: {output_file}\")\n\nif __name__ == '__main__':\n    main()