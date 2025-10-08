#!/usr/bin/env python3
"""
Optimized MCP Scanner v2.1 CLI with modular false positive reduction.
Usage: python scripts/optimized_scan_cli.py <path> [options]
"""

import sys
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from optimized_scanner_v21 import OptimizedScanner


def main():
    parser = argparse.ArgumentParser(description='Optimized MCP Security Scanner v2.1')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--format', choices=['json', 'terminal'], 
                       default='terminal', help='Output format')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--compare', help='Compare with previous scan results')
    parser.add_argument('--threshold', type=float, default=0.3,
                       help='Confidence threshold (default: 0.3)')
    
    args = parser.parse_args()
    
    # Initialize optimized scanner
    scanner = OptimizedScanner()
    
    # Run optimized scan
    print(f"🔍 Optimized MCP Scanner v2.1 - Scanning {args.path}")
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
    print(f"   Raw Findings: {summary['raw_findings']}")
    print(f"   Final Vulnerabilities: {summary['vulnerabilities_found']}")
    print(f"   Optimized ASR: {summary['optimized_asr_score']:.3f}")
    print(f"   False Positive Reduction: {summary['false_positive_reduction']:.1f}%")
    
    # Optimization metrics
    metrics = results['optimization_metrics']
    print(f"\n🚀 Optimization Metrics:")
    print(f"   Test Files Filtered: {metrics['test_filtered']}")
    print(f"   Placeholders Filtered: {metrics['placeholder_filtered']}")
    print(f"   Import Statements Filtered: {metrics['import_filtered']}")
    
    # Severity distribution
    severity = summary['severity_distribution']
    print(f"\n⚠️  Severity Distribution:")
    for level, count in severity.items():
        if count > 0:
            print(f"   {level}: {count}")
    
    # Top findings
    findings = results['findings'][:10]  # Top 10
    if findings:
        print(f"\n🔍 Top Findings (Confidence ≥ 0.3):")
        for i, finding in enumerate(findings, 1):
            print(f"   {i}. {finding['severity']} - {finding['category']}")
            print(f"      {finding['file_path']}:{finding['line_number']}")
            print(f"      Confidence: {finding['confidence']:.2f}")
    else:
        print(f"\n✅ No high-confidence vulnerabilities found!")


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
        old_asr = old_summary.get('asr_score', old_summary.get('enhanced_asr_score', 0))
        new_asr = new_summary['optimized_asr_score']
        asr_change = new_asr - old_asr
        
        print(f"   ASR Score: {old_asr:.3f} → {new_asr:.3f} ({asr_change:+.3f})")
        
        # False positive reduction
        fp_reduction = new_summary['false_positive_reduction']
        print(f"   False Positive Reduction: {fp_reduction:.1f}%")
        
        # Show improvement
        if vuln_change < 0 and asr_change > 0:
            print(f"   🎉 Improvement: {abs(vuln_change)} fewer findings, {asr_change:.3f} higher ASR")
        elif vuln_change < 0:
            print(f"   ✅ Noise Reduction: {abs(vuln_change)} fewer findings")
        elif asr_change > 0:
            print(f"   📈 Quality Improvement: {asr_change:.3f} higher ASR")
        
    except Exception as e:
        print(f"❌ Comparison failed: {e}")


if __name__ == '__main__':
    main()