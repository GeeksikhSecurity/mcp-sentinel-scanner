#!/usr/bin/env python3
"""Batch scan 10 additional repositories using enhanced scanner."""

import subprocess
import json
from pathlib import Path
from datetime import datetime

def main():
    """Batch scan additional repositories."""
    
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
    
    print("🛡️ MCP Sentinel Scanner - Batch Scanning Additional Repositories")
    print("=" * 70)
    
    results = []
    
    for repo_path in additional_repos:
        if not Path(repo_path).exists():
            print(f"⚠️  Repository not found: {repo_path}")
            continue
            
        repo_name = Path(repo_path).name
        output_file = f"{repo_name}-additional-scan.json"
        
        print(f"\n🔍 Scanning: {repo_name}")
        
        try:
            # Run enhanced scanner
            cmd = [
                'python3', '-m', 'scripts.enhanced_scan_cli',
                repo_path,
                '--format', 'json',
                '-o', output_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Load and process results
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                findings = scan_data.get('findings', [])
                total = len(findings)
                high = sum(1 for f in findings if f.get('severity') == 'HIGH')
                medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
                
                print(f"   ✅ Success: {total} findings ({high} high, {medium} medium)")
                
                results.append({
                    'repository': repo_name,
                    'scan_file': output_file,
                    'total_findings': total,
                    'high_severity': high,
                    'medium_severity': medium,
                    'scan_data': scan_data
                })
                
            else:
                print(f"   ❌ Failed: {result.stderr}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Generate comprehensive summary
    generate_batch_summary(results)
    
    return results

def generate_batch_summary(results):
    """Generate comprehensive batch summary."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Calculate overall statistics
    total_repos = len(results)
    total_findings = sum(r['total_findings'] for r in results)
    total_high = sum(r['high_severity'] for r in results)
    total_medium = sum(r['medium_severity'] for r in results)
    
    # Collect all findings for category analysis
    all_findings = []
    for result in results:
        all_findings.extend(result['scan_data'].get('findings', []))
    
    # Category breakdown
    categories = {}
    for finding in all_findings:
        cat = finding.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    # File type analysis
    file_types = {}
    for finding in all_findings:
        file_path = finding.get('file_path', '')
        ext = Path(file_path).suffix or 'no_extension'
        file_types[ext] = file_types.get(ext, 0) + 1
    
    print(f"\n📊 BATCH SCAN SUMMARY")
    print("=" * 50)
    print(f"📁 Repositories scanned: {total_repos}")
    print(f"🔍 Total findings: {total_findings}")
    print(f"🚨 High severity: {total_high}")
    print(f"⚠️  Medium severity: {total_medium}")
    print(f"📈 Average per repo: {total_findings/total_repos:.1f}")
    
    if categories:
        print(f"\n🏷️  Top Categories:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            print(f"   • {cat}: {count} ({pct:.1f}%)")
    
    if file_types:
        print(f"\n📄 File Types:")
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   • {ext}: {count}")
    
    print(f"\n🏆 Repository Rankings:")
    sorted_results = sorted(results, key=lambda x: x['total_findings'], reverse=True)
    for i, result in enumerate(sorted_results[:5], 1):
        print(f"   {i}. {result['repository']}: {result['total_findings']} ({result['high_severity']} high)")
    
    # Save comprehensive summary
    summary_data = {
        'batch_scan_metadata': {
            'timestamp': timestamp,
            'scan_date': datetime.now().isoformat(),
            'repositories_scanned': total_repos,
            'scanner_version': 'enhanced_v2.0'
        },
        'aggregate_statistics': {
            'total_findings': total_findings,
            'high_severity_findings': total_high,
            'medium_severity_findings': total_medium,
            'average_findings_per_repo': total_findings/total_repos if total_repos > 0 else 0,
            'vulnerability_categories': categories,
            'file_type_distribution': file_types
        },
        'repository_results': results
    }
    
    summary_file = f"batch_additional_scan_summary_{timestamp}.json"
    with open(summary_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    print(f"\n💾 Comprehensive summary saved to: {summary_file}")
    
    # Generate executive report
    generate_executive_report(summary_data, summary_file.replace('.json', '_report.md'))

def generate_executive_report(data, output_file):
    """Generate executive markdown report."""
    
    stats = data['aggregate_statistics']
    meta = data['batch_scan_metadata']
    
    report = [
        "# 🛡️ MCP Additional Repositories - Security Analysis Report",
        "",
        f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Scanner Version**: {meta['scanner_version']}",
        f"**Repositories Analyzed**: {meta['repositories_scanned']}",
        "",
        "## 🎯 Executive Summary",
        "",
        f"This comprehensive security analysis of {meta['repositories_scanned']} additional MCP repositories identified **{stats['total_findings']} security findings**, including **{stats['high_severity_findings']} high-severity issues** requiring immediate attention.",
        "",
        "### Key Metrics",
        f"- **Total Security Findings**: {stats['total_findings']}",
        f"- **Critical Issues (HIGH)**: {stats['high_severity_findings']}",
        f"- **Medium Priority Issues**: {stats['medium_severity_findings']}",
        f"- **Average Issues per Repository**: {stats['average_findings_per_repo']:.1f}",
        ""
    ]
    
    # Top vulnerabilities
    if stats['vulnerability_categories']:
        report.extend([
            "## 🏷️ Vulnerability Landscape",
            "",
            "| Vulnerability Type | Count | % of Total |",
            "|-------------------|-------|------------|"
        ])
        
        total = stats['total_findings']
        for cat, count in sorted(stats['vulnerability_categories'].items(), key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            report.append(f"| {cat} | {count} | {pct:.1f}% |")
        
        report.append("")
    
    # Repository assessment
    report.extend([
        "## 📊 Repository Security Assessment",
        "",
        "| Repository | Total Issues | High Risk | Medium Risk | Status |",
        "|------------|--------------|-----------|-------------|---------|"
    ])
    
    for result in sorted(data['repository_results'], key=lambda x: x['total_findings'], reverse=True):
        name = result['repository']
        total = result['total_findings']
        high = result['high_severity']
        medium = result['medium_severity']
        
        if high > 0:
            status = "🚨 Critical"
        elif medium > 0:
            status = "⚠️ Review"
        else:
            status = "✅ Clean"
        
        report.append(f"| {name} | {total} | {high} | {medium} | {status} |")
    
    # Risk assessment
    critical_repos = sum(1 for r in data['repository_results'] if r['high_severity'] > 0)
    clean_repos = sum(1 for r in data['repository_results'] if r['total_findings'] == 0)
    
    report.extend([
        "",
        "## 🔍 Risk Assessment",
        "",
        f"- **Critical Risk Repositories**: {critical_repos} ({critical_repos/meta['repositories_scanned']*100:.1f}%)",
        f"- **Clean Repositories**: {clean_repos} ({clean_repos/meta['repositories_scanned']*100:.1f}%)",
        f"- **Most Common Vulnerability**: {max(stats['vulnerability_categories'].items(), key=lambda x: x[1])[0] if stats['vulnerability_categories'] else 'N/A'}",
        "",
        "## 💡 Strategic Recommendations",
        "",
        "### Immediate Actions (0-30 days)",
        f"1. **Address Critical Issues**: Remediate all {stats['high_severity_findings']} high-severity findings",
        "2. **Security Review**: Conduct detailed review of repositories with critical risk status",
        "3. **Incident Response**: Establish monitoring for the most common vulnerability types",
        "",
        "### Short-term Improvements (1-3 months)",
        "1. **CI/CD Integration**: Implement automated security scanning in development pipelines",
        "2. **Developer Training**: Focus on preventing the most common vulnerability categories",
        "3. **Security Standards**: Establish coding standards based on findings",
        "",
        "### Long-term Strategy (3-12 months)",
        "1. **Security Culture**: Build security-first development practices",
        "2. **Continuous Monitoring**: Implement ongoing security assessment processes",
        "3. **Compliance Framework**: Establish security compliance requirements",
        "",
        "---",
        f"*Report generated by MCP Sentinel Scanner on {meta['timestamp']}*",
        "",
        "**Next Steps**: Review individual repository scan files for detailed findings and remediation guidance."
    ])
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"📄 Executive report saved to: {output_file}")

if __name__ == '__main__':
    main()