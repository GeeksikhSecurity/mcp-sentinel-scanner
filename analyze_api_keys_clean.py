#!/usr/bin/env python3
"""Clean API key analysis for additional repositories."""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append('src')

from api_key_analyzer import APIKeyAnalyzer

def main():
    """Analyze API keys from additional scans."""
    
    scan_files = [
        'modelcontextprotocol-servers-additional-scan.json',
        'modelcontextprotocol-python-sdk-additional-scan.json',
        'official-servers-additional-scan.json'
    ]
    
    print("🔑 API Key Analysis - Additional Repositories")
    print("=" * 50)
    
    analyzer = APIKeyAnalyzer()
    all_analyses = []
    
    for scan_file in scan_files:
        if not Path(scan_file).exists():
            continue
            
        repo_name = scan_file.replace('-additional-scan.json', '')
        print(f"\n🔍 Analyzing: {repo_name}")
        
        try:
            with open(scan_file, 'r') as f:
                scan_data = json.load(f)
            
            # Extract hardcoded secrets
            api_keys = []
            for finding in scan_data.get('findings', []):
                if finding.get('category') == 'hardcoded_secret':
                    api_keys.append({
                        'category': finding.get('category'),
                        'file_path': finding.get('file_path'),
                        'line_number': finding.get('line_number'),
                        'code_snippet': finding.get('code_snippet', ''),
                        'confidence': finding.get('confidence', 0.0)
                    })
            
            # Create adapted format
            adapted_data = {
                'repository_results': [{
                    'repository': repo_name,
                    'api_keys': {'findings': api_keys}
                }]
            }
            
            # Save temporarily
            temp_file = f"temp_{scan_file}"
            with open(temp_file, 'w') as f:
                json.dump(adapted_data, f, indent=2)
            
            # Analyze
            analysis = analyzer.analyze_api_keys(temp_file)
            
            if 'error' not in analysis:
                total = analysis['total_keys']
                fp = analysis['false_positives']['total_false_positives']
                prod = analysis['by_context'].get('production', 0)
                
                print(f"   📊 Total: {total}, FP: {fp}, Prod: {prod}")
                
                analysis['repository'] = repo_name
                all_analyses.append(analysis)
            
            Path(temp_file).unlink()
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Generate summary
    generate_summary(all_analyses)

def generate_summary(analyses):
    """Generate analysis summary."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    total_repos = len(analyses)
    total_keys = sum(a['total_keys'] for a in analyses)
    total_fp = sum(a['false_positives']['total_false_positives'] for a in analyses)
    total_prod = sum(a['by_context'].get('production', 0) for a in analyses)
    
    print(f"\n📊 SUMMARY")
    print("=" * 30)
    print(f"📁 Repositories: {total_repos}")
    print(f"🔑 Total keys: {total_keys}")
    print(f"🎯 False positives: {total_fp}")
    print(f"🚨 Production keys: {total_prod}")
    
    if total_keys > 0:
        fp_rate = (total_fp / total_keys) * 100
        print(f"📈 FP rate: {fp_rate:.1f}%")
    
    # Save results
    output_file = f"additional_api_analysis_{timestamp}.json"
    summary_data = {
        'timestamp': timestamp,
        'total_repositories': total_repos,
        'total_keys': total_keys,
        'total_false_positives': total_fp,
        'total_production_keys': total_prod,
        'analyses': analyses
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")

if __name__ == '__main__':
    main()