#!/usr/bin/env python3
"""API Key Analysis Tool for MCP Security Scanner Results."""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter

class APIKeyAnalyzer:
    """Analyze API keys from scan results to identify false positives."""
    
    def __init__(self):
        # Documentation/example patterns
        self.doc_patterns = [
            r'github\.com/.*blob/[a-f0-9]{40}',  # GitHub commit hashes in URLs
            r'modelcontextprotocol/blob/[a-f0-9]{40}',  # MCP spec commit hashes
            r'See \[MCP specification\]',  # Documentation references
            r'https://github\.com/.*/blob/',  # GitHub blob URLs
            r'/docs/.*\.mdx',  # Documentation files
        ]
        
        # Test file indicators
        self.test_indicators = [
            'test', 'spec', '__test__', '.test.', '.spec.',
            'testing', 'fixture', 'mock', 'demo', 'example'
        ]
        
        # Common false positive patterns
        self.false_positive_patterns = {
            'github_commit_hash': r'[a-f0-9]{40}',
            'uuid_like': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            'hex_32': r'[a-f0-9]{32}',
            'base64_like': r'[A-Za-z0-9+/]{20,}={0,2}',
        }
    
    def analyze_api_keys(self, scan_results_path: str) -> Dict[str, Any]:
        """Analyze API keys from scan results."""
        try:
            with open(scan_results_path, 'r') as f:
                data = json.load(f)
        except:
            return {'error': 'Could not load scan results'}
        
        # Extract all API key findings
        all_api_keys = []
        for repo_result in data.get('repository_results', []):
            repo_name = repo_result.get('repository', 'unknown')
            api_keys = repo_result.get('api_keys', {}).get('findings', [])
            
            for key in api_keys:
                key['repository'] = repo_name
                all_api_keys.append(key)
        
        # Analyze patterns
        analysis = {
            'total_keys': len(all_api_keys),
            'by_category': self._analyze_by_category(all_api_keys),
            'by_file_type': self._analyze_by_file_type(all_api_keys),
            'by_context': self._analyze_by_context(all_api_keys),
            'false_positives': self._identify_false_positives(all_api_keys),
            'documentation_keys': self._identify_documentation_keys(all_api_keys),
            'test_keys': self._identify_test_keys(all_api_keys),
            'recommendations': []
        }
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_by_category(self, api_keys: List[Dict]) -> Dict[str, int]:
        """Analyze API keys by category."""
        categories = Counter(key.get('category', 'unknown') for key in api_keys)
        return dict(categories)
    
    def _analyze_by_file_type(self, api_keys: List[Dict]) -> Dict[str, int]:
        """Analyze API keys by file type."""
        file_types = defaultdict(int)
        
        for key in api_keys:
            file_path = key.get('file_path', '')
            if file_path:
                suffix = Path(file_path).suffix or 'no_extension'
                file_types[suffix] += 1
        
        return dict(file_types)
    
    def _analyze_by_context(self, api_keys: List[Dict]) -> Dict[str, Any]:
        """Analyze API keys by context (test, docs, production)."""
        contexts = {'test': 0, 'documentation': 0, 'production': 0, 'package_lock': 0}
        
        for key in api_keys:
            file_path = key.get('file_path', '').lower()
            
            if 'package-lock.json' in file_path:
                contexts['package_lock'] += 1
            elif any(indicator in file_path for indicator in self.test_indicators):
                contexts['test'] += 1
            elif any(doc in file_path for doc in ['readme', 'docs', 'example', 'demo']):
                contexts['documentation'] += 1
            else:
                contexts['production'] += 1
        
        return contexts
    
    def _identify_false_positives(self, api_keys: List[Dict]) -> Dict[str, Any]:
        """Identify likely false positives."""
        false_positives = {
            'github_commit_hashes': [],
            'documentation_examples': [],
            'test_fixtures': [],
            'package_lock_hashes': [],
            'total_false_positives': 0
        }
        
        for key in api_keys:
            code_snippet = key.get('code_snippet', '')
            file_path = key.get('file_path', '')
            
            # GitHub commit hashes in documentation
            if any(re.search(pattern, code_snippet) for pattern in self.doc_patterns):
                false_positives['github_commit_hashes'].append({
                    'file': Path(file_path).name,
                    'line': key.get('line_number'),
                    'snippet': code_snippet[:100] + '...' if len(code_snippet) > 100 else code_snippet
                })
            
            # Package lock files
            elif 'package-lock.json' in file_path:
                false_positives['package_lock_hashes'].append({
                    'file': Path(file_path).name,
                    'line': key.get('line_number'),
                    'type': 'dependency_hash'
                })
            
            # Test files
            elif any(indicator in file_path.lower() for indicator in self.test_indicators):
                false_positives['test_fixtures'].append({
                    'file': Path(file_path).name,
                    'line': key.get('line_number'),
                    'context': 'test_file'
                })
            
            # Documentation examples
            elif any(doc in file_path.lower() for doc in ['readme', 'docs', 'example']):
                false_positives['documentation_examples'].append({
                    'file': Path(file_path).name,
                    'line': key.get('line_number'),
                    'context': 'documentation'
                })
        
        false_positives['total_false_positives'] = sum(
            len(fp_list) for key, fp_list in false_positives.items() 
            if key != 'total_false_positives'
        )
        
        return false_positives
    
    def _identify_documentation_keys(self, api_keys: List[Dict]) -> List[Dict]:
        """Identify keys that are documentation examples."""
        doc_keys = []
        
        for key in api_keys:
            code_snippet = key.get('code_snippet', '')
            file_path = key.get('file_path', '')
            
            # Check for documentation patterns
            is_doc_key = (
                'types.ts' in file_path and 'specification' in code_snippet.lower() or
                'github.com' in code_snippet and 'blob' in code_snippet or
                'See [MCP specification]' in code_snippet or
                '/docs/' in code_snippet
            )
            
            if is_doc_key:
                doc_keys.append({
                    'file': Path(file_path).name,
                    'line': key.get('line_number'),
                    'category': key.get('category'),
                    'snippet_preview': code_snippet[:80] + '...' if len(code_snippet) > 80 else code_snippet
                })
        
        return doc_keys
    
    def _identify_test_keys(self, api_keys: List[Dict]) -> List[Dict]:
        """Identify keys that are test fixtures."""
        test_keys = []
        
        for key in api_keys:
            file_path = key.get('file_path', '').lower()
            
            if any(indicator in file_path for indicator in self.test_indicators):
                test_keys.append({
                    'file': Path(key.get('file_path', '')).name,
                    'line': key.get('line_number'),
                    'category': key.get('category'),
                    'test_type': self._determine_test_type(file_path)
                })
        
        return test_keys
    
    def _determine_test_type(self, file_path: str) -> str:
        """Determine the type of test file."""
        if 'unit' in file_path:
            return 'unit_test'
        elif 'integration' in file_path:
            return 'integration_test'
        elif 'e2e' in file_path or 'end-to-end' in file_path:
            return 'e2e_test'
        elif '.test.' in file_path or '.spec.' in file_path:
            return 'standard_test'
        else:
            return 'test_file'
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        total_keys = analysis['total_keys']
        false_positives = analysis['false_positives']['total_false_positives']
        
        if false_positives > 0:
            fp_percentage = (false_positives / total_keys) * 100
            recommendations.append(
                f"🎯 {false_positives} ({fp_percentage:.1f}%) of API keys are likely false positives"
            )
        
        # Context-specific recommendations
        contexts = analysis['by_context']
        if contexts.get('package_lock', 0) > 0:
            recommendations.append(
                f"📦 {contexts['package_lock']} keys found in package-lock.json files (dependency hashes)"
            )
        
        if contexts.get('test', 0) > 0:
            recommendations.append(
                f"🧪 {contexts['test']} keys found in test files (expected test fixtures)"
            )
        
        if contexts.get('documentation', 0) > 0:
            recommendations.append(
                f"📚 {contexts['documentation']} keys found in documentation (example values)"
            )
        
        # Production keys
        production_keys = contexts.get('production', 0)
        if production_keys > 0:
            recommendations.append(
                f"🚨 {production_keys} keys found in production code (requires manual review)"
            )
        
        return recommendations
    
    def generate_detailed_report(self, analysis: Dict[str, Any]) -> str:
        """Generate a detailed analysis report."""
        report = []
        report.append("# 🔑 API Key Analysis Report")
        report.append("=" * 50)
        report.append(f"**Total API Keys Found**: {analysis['total_keys']}")
        report.append("")
        
        # False Positives Summary
        fp = analysis['false_positives']
        report.append("## 🎯 False Positive Analysis")
        report.append(f"**Total False Positives**: {fp['total_false_positives']}")
        report.append(f"**GitHub Commit Hashes**: {len(fp['github_commit_hashes'])}")
        report.append(f"**Package Lock Hashes**: {len(fp['package_lock_hashes'])}")
        report.append(f"**Test Fixtures**: {len(fp['test_fixtures'])}")
        report.append(f"**Documentation Examples**: {len(fp['documentation_examples'])}")
        report.append("")
        
        # Context Analysis
        report.append("## 📊 Context Distribution")
        contexts = analysis['by_context']
        for context, count in contexts.items():
            percentage = (count / analysis['total_keys']) * 100
            report.append(f"- **{context.title()}**: {count} ({percentage:.1f}%)")
        report.append("")
        
        # File Type Analysis
        report.append("## 📁 File Type Distribution")
        file_types = analysis['by_file_type']
        for file_type, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
            report.append(f"- **{file_type}**: {count}")
        report.append("")
        
        # Recommendations
        report.append("## 💡 Recommendations")
        for rec in analysis['recommendations']:
            report.append(f"- {rec}")
        report.append("")
        
        return "\n".join(report)

def main():
    """Analyze API keys from scan results."""
    analyzer = APIKeyAnalyzer()
    
    # Analyze the full scan results
    results_path = "../scans/results/mcp_security_analysis_full.json"
    
    print("🔍 Analyzing API keys from scan results...")
    analysis = analyzer.analyze_api_keys(results_path)
    
    if 'error' in analysis:
        print(f"❌ Error: {analysis['error']}")
        return
    
    # Generate detailed report
    report = analyzer.generate_detailed_report(analysis)
    
    # Save analysis results
    with open("../scans/results/api_key_analysis.json", "w") as f:
        json.dump(analysis, f, indent=2)
    
    with open("../scans/results/api_key_analysis_report.md", "w") as f:
        f.write(report)
    
    # Print summary
    print("📊 API Key Analysis Summary:")
    print(f"Total Keys: {analysis['total_keys']}")
    print(f"False Positives: {analysis['false_positives']['total_false_positives']}")
    print(f"Production Keys: {analysis['by_context'].get('production', 0)}")
    
    print("\n💡 Key Recommendations:")
    for rec in analysis['recommendations'][:3]:  # Show top 3
        print(f"  • {rec}")
    
    print(f"\n📋 Detailed analysis saved to:")
    print(f"  • api_key_analysis.json")
    print(f"  • api_key_analysis_report.md")

if __name__ == '__main__':
    main()