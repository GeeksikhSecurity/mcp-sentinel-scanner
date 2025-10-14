#!/usr/bin/env python3
"""Run API Key Analysis on local scan results."""

import json
import sys
from pathlib import Path
from src.api_key_analyzer import APIKeyAnalyzer

def adapt_scan_results_for_analyzer(scan_data):
    """Adapt our scan results format to what the analyzer expects."""
    # Extract hardcoded_secret findings from our scan results
    api_keys = []
    
    for finding in scan_data.get('findings', []):
        if finding.get('category') == 'hardcoded_secret':
            api_keys.append({
                'category': finding.get('category'),
                'file_path': finding.get('file_path'),
                'line_number': finding.get('line_number'),
                'code_snippet': finding.get('code_snippet', ''),
                'confidence': finding.get('confidence', 0.0),
                'severity': finding.get('severity'),
                'description': finding.get('description')
            })
    
    # Return in the format the analyzer expects
    return {
        'repository_results': [{
            'repository': 'local_scan',
            'api_keys': {
                'findings': api_keys
            }
        }]
    }

def main():
    """Run API key analysis on available scan results."""
    analyzer = APIKeyAnalyzer()
    
    # Find available scan result files
    scan_files = [
        'fastmcp-scan.json',
        'enhanced-fastmcp-scan.json',
        'mcp-python-scan.json',
        'mcp-typescript-scan.json',
        'mcp-servers-scan.json'
    ]
    
    print("🔍 MCP Sentinel Scanner - API Key Analysis")
    print("=" * 50)
    
    for scan_file in scan_files:
        if Path(scan_file).exists():
            print(f"\n📊 Analyzing: {scan_file}")
            
            try:
                # Load scan results
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Adapt format for analyzer
                adapted_data = adapt_scan_results_for_analyzer(scan_data)
                
                # Save adapted data temporarily
                temp_file = f"temp_{scan_file}"
                with open(temp_file, 'w') as f:
                    json.dump(adapted_data, f, indent=2)
                
                # Run analysis
                analysis = analyzer.analyze_api_keys(temp_file)
                
                if 'error' in analysis:
                    print(f"❌ Error analyzing {scan_file}: {analysis['error']}")
                    continue
                
                # Print summary
                total_keys = analysis['total_keys']
                false_positives = analysis['false_positives']['total_false_positives']
                production_keys = analysis['by_context'].get('production', 0)
                
                print(f"  📈 Total API Keys: {total_keys}")
                print(f"  🎯 False Positives: {false_positives}")
                print(f"  🚨 Production Keys: {production_keys}")
                
                if total_keys > 0:
                    fp_percentage = (false_positives / total_keys) * 100
                    print(f"  📊 False Positive Rate: {fp_percentage:.1f}%")
                
                # Show context breakdown
                contexts = analysis['by_context']
                print(f"  📁 Context: Test={contexts.get('test', 0)}, Docs={contexts.get('documentation', 0)}, Prod={production_keys}")
                
                # Show top recommendations
                if analysis['recommendations']:
                    print("  💡 Top Recommendations:")
                    for rec in analysis['recommendations'][:2]:
                        print(f"    • {rec}")
                
                # Save detailed analysis
                output_file = f"api_analysis_{scan_file.replace('.json', '.json')}"
                with open(output_file, 'w') as f:
                    json.dump(analysis, f, indent=2)
                
                # Generate and save report
                report = analyzer.generate_detailed_report(analysis)
                report_file = f"api_analysis_{scan_file.replace('.json', '_report.md')}"
                with open(report_file, 'w') as f:
                    f.write(report)
                
                print(f"  📋 Detailed analysis saved to: {output_file}")
                print(f"  📄 Report saved to: {report_file}")
                
                # Clean up temp file
                Path(temp_file).unlink()
                
            except Exception as e:
                print(f"❌ Error processing {scan_file}: {e}")
                continue
    
    print("\n✅ API Key Analysis Complete!")

if __name__ == '__main__':
    main()