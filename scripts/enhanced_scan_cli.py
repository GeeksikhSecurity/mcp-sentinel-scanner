#!/usr/bin/env python3
"""
Enhanced MCP Scanner CLI with CodeQL integration.
Usage: python scripts/enhanced_scan_cli.py <path> [options]
"""

import sys
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from enhanced_scanner_standalone import SimplifiedScanner as EnhancedMCPScanner


def main():
    parser = argparse.ArgumentParser(description='Enhanced MCP Security Scanner')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--format', choices=['json', 'terminal'], 
                       default='terminal', help='Output format')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--compare', help='Compare with previous scan results')
    
    args = parser.parse_args()
    
    # Initialize enhanced scanner
    scanner = EnhancedMCPScanner()
    
    # Run enhanced scan
    print(f"🔍 Enhanced MCP Scanner v2.0 - Scanning {args.path}")
    print("=" * 60)
    
    results = scanner.scan_repository(args.path)
    
    # Display results
    if args.format == 'terminal':
        display_terminal_results(results)
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")
    
    # Compare with previous results
    if args.compare:
        compare_results(results, args.compare)


def display_terminal_results(results: dict):
    """Display results in terminal format."""
    summary = results['scan_summary']
    
    print(f"📊 Scan Summary:")
    print(f"   Files Scanned: {summary['files_scanned']}")
    print(f"   Scan Time: {summary['scan_time']:.2f}s")
    print(f"   Vulnerabilities: {summary['vulnerabilities_found']}")
    print(f"   Enhanced ASR: {summary['enhanced_asr_score']:.3f}")
    if 'traditional_asr_score' in summary:
        print(f"   Traditional ASR: {summary['traditional_asr_score']:.3f}")
    if 'codeql_findings' in summary:
        print(f"   CodeQL Findings: {summary['codeql_findings']}")
    
    # Enhancement metrics
    metrics = results['enhancement_metrics']
    print(f"\n🚀 Enhancement Metrics:")
    if 'false_positive_reduction' in metrics:
        print(f"   False Positive Reduction: {metrics['false_positive_reduction']:.1f}%")
    if 'context_filtered' in metrics:
        print(f"   Context Filtered: {metrics['context_filtered']}")
    if 'accuracy_improvement' in metrics:
        print(f"   Accuracy Improvement: {metrics['accuracy_improvement']:.1f}%")
    
    # Severity distribution
    severity = summary['severity_distribution']
    print(f"\n⚠️  Severity Distribution:")
    for level, count in severity.items():
        if count > 0:
            print(f"   {level}: {count}")
    
    # Top findings
    findings = results['findings'][:10]  # Top 10
    if findings:
        print(f"\n🔍 Top Findings:")
        for i, finding in enumerate(findings, 1):
            print(f"   {i}. {finding['severity']} - {finding['category']}")
            print(f"      {finding['file_path']}:{finding['line_number']}")
            print(f"      Confidence: {finding['confidence']:.2f}")


def compare_results(new_results: dict, old_file: str):
    """Compare with previous scan results."""
    try:
        with open(old_file, 'r') as f:
            old_results = json.load(f)
        
        print(f"\n📈 Comparison with {old_file}:")
        
        old_summary = old_results.get('scan_summary', {})
        new_summary = new_results['scan_summary']
        
        # Vulnerability count comparison
        old_vulns = old_summary.get('vulnerabilities_found', 0)
        new_vulns = new_summary['vulnerabilities_found']
        vuln_change = new_vulns - old_vulns
        
        print(f"   Vulnerabilities: {old_vulns} → {new_vulns} ({vuln_change:+d})")
        
        # ASR comparison
        old_asr = old_summary.get('asr_score', 0)
        new_asr = new_summary['enhanced_asr_score']
        asr_change = new_asr - old_asr
        
        print(f"   ASR Score: {old_asr:.3f} → {new_asr:.3f} ({asr_change:+.3f})")
        
        # False positive reduction
        if 'enhancement_metrics' in new_results:
            fp_reduction = new_results['enhancement_metrics']['false_positive_reduction']
            print(f"   False Positive Reduction: {fp_reduction:.1f}%")
        
    except Exception as e:
        print(f"❌ Comparison failed: {e}")


if __name__ == '__main__':
    main()