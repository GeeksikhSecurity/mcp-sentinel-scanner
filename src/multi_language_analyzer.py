"""Multi-language security analyzer for TypeScript, JavaScript, and Python."""

import ast
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import subprocess


class TypeScriptAnalyzer:
    """TypeScript/JavaScript security analyzer."""
    
    def __init__(self):
        self.react_patterns = self._load_react_patterns()
        self.node_patterns = self._load_node_patterns()
    
    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze TypeScript/JavaScript file for security issues."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # React-specific analysis
            if self._is_react_file(content):
                findings.extend(self._analyze_react_security(content, file_path))
            
            # Node.js-specific analysis
            if self._is_node_file(content):
                findings.extend(self._analyze_node_security(content, file_path))
            
            # General JavaScript security patterns
            findings.extend(self._analyze_js_patterns(content, file_path))
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _is_react_file(self, content: str) -> bool:
        """Check if file contains React code."""
        react_indicators = [
            'import React',
            'from "react"',
            'JSX.Element',
            'React.Component',
            'useState',
            'useEffect'
        ]
        return any(indicator in content for indicator in react_indicators)
    
    def _is_node_file(self, content: str) -> bool:
        """Check if file contains Node.js code."""
        node_indicators = [
            'require(',
            'module.exports',
            'process.env',
            '__dirname',
            'fs.readFile',
            'http.createServer'
        ]
        return any(indicator in content for indicator in node_indicators)
    
    def _analyze_react_security(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze React-specific security issues."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Dangerous dangerouslySetInnerHTML usage
            if 'dangerouslySetInnerHTML' in line and '__html:' in line:
                if not re.search(r'DOMPurify\.sanitize|xss\.filterXSS', line):
                    findings.append({
                        'rule_id': 'react-xss-dangerously-set-inner-html',
                        'message': 'Potential XSS: dangerouslySetInnerHTML without sanitization',
                        'file_path': file_path,
                        'start_line': i,
                        'end_line': i,
                        'severity': 'HIGH',
                        'confidence': 0.9
                    })
            
            # Unsafe ref usage
            if re.search(r'ref\.current\.(innerHTML|outerHTML)\s*=', line):
                findings.append({
                    'rule_id': 'react-unsafe-ref-html',
                    'message': 'Unsafe ref manipulation: potential XSS',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'HIGH',
                    'confidence': 0.85
                })
            
            # Unvalidated props in dangerous contexts
            if re.search(r'<(script|iframe|object|embed)[^>]*\{[^}]*props\.[^}]*\}', line):
                findings.append({
                    'rule_id': 'react-unvalidated-props-dangerous-tags',
                    'message': 'Unvalidated props in dangerous HTML tags',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'MEDIUM',
                    'confidence': 0.8
                })
        
        return findings
    
    # child_process discriminator (MCP bug-bounty lesson, docker-mcp-server
    # GHSA-j4p2-6qf7-754c-adjacent finding): exec()/execSync() always hand the
    # command to a shell, so ANY dynamic (template-literal or concatenated)
    # command string is a command-injection sink. spawn()/execFile()/
    # spawnSync()/execFileSync() pass argv straight to the OS and do NOT
    # invoke a shell -- that is the SAFE form -- unless the caller opts back
    # into shell parsing with `shell: true`, which collapses them back to
    # exec-equivalent. The prior rule flagged spawn() the same as exec()
    # whenever a template literal appeared anywhere in the call, which is
    # the textbook-SAFE usage (`spawn('docker', ['exec', `${id}`, 'ls'])`)
    # -- a false positive -- while missing string-concatenated exec() calls
    # with no template literal at all (a false negative).
    _EXEC_SINK_RE = re.compile(r'(?:child_process\.)?(?:exec|execSync)\s*\(')
    _ARGV_FUNC_RE = re.compile(
        r'(?:child_process\.)?(?:spawn|execFile|spawnSync|execFileSync)\s*\('
    )
    _DYNAMIC_COMMAND_RE = re.compile(r'\$\{.*?\}|["\']\s*\+|\+\s*["\']')
    _SHELL_OPTION_RE = re.compile(r'shell\s*:\s*true')

    def _analyze_node_security(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze Node.js-specific security issues."""
        findings = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # exec()/execSync() always run through a shell: any dynamic
            # command string (template literal OR string concatenation) is
            # command injection.
            if self._EXEC_SINK_RE.search(line) and self._DYNAMIC_COMMAND_RE.search(line):
                findings.append({
                    'rule_id': 'node-command-injection',
                    'message': 'Potential command injection in child_process.exec — dynamic '
                                'command string is interpreted by a shell',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'CRITICAL',
                    'confidence': 0.95
                })

            # spawn()/execFile() are argv-safe by default; they only become
            # exec-equivalent when the caller opts in with `shell: true`.
            elif self._ARGV_FUNC_RE.search(line) and self._SHELL_OPTION_RE.search(line):
                findings.append({
                    'rule_id': 'node-command-injection-shell-option',
                    'message': "child_process.spawn/execFile called with `shell: true` — "
                                "this re-enables shell parsing of argv, same risk as exec()",
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'CRITICAL',
                    'confidence': 0.9
                })
            
            # Path traversal
            if re.search(r'(fs\.readFile|fs\.writeFile|fs\.createReadStream).*\.\./.*', line):
                findings.append({
                    'rule_id': 'node-path-traversal',
                    'message': 'Potential path traversal vulnerability',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'HIGH',
                    'confidence': 0.9
                })
            
            # Prototype pollution
            if re.search(r'JSON\.parse.*req\.(body|query|params)', line):
                findings.append({
                    'rule_id': 'node-prototype-pollution',
                    'message': 'Potential prototype pollution via JSON.parse',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'HIGH',
                    'confidence': 0.8
                })
        
        return findings
    
    def _analyze_js_patterns(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze general JavaScript security patterns."""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # eval() usage
            if re.search(r'\beval\s*\(', line):
                findings.append({
                    'rule_id': 'js-eval-usage',
                    'message': 'Dangerous eval() usage detected',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'HIGH',
                    'confidence': 0.95
                })
            
            # document.write with variables
            if re.search(r'document\.write\(.*\$\{.*\}.*\)', line):
                findings.append({
                    'rule_id': 'js-document-write-xss',
                    'message': 'Potential XSS via document.write',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'MEDIUM',
                    'confidence': 0.8
                })
            
            # Weak random number generation
            if 'Math.random()' in line and any(crypto_context in content for crypto_context in [
                'password', 'token', 'secret', 'key', 'salt'
            ]):
                findings.append({
                    'rule_id': 'js-weak-random',
                    'message': 'Weak random number generation for security context',
                    'file_path': file_path,
                    'start_line': i,
                    'end_line': i,
                    'severity': 'MEDIUM',
                    'confidence': 0.7
                })
        
        return findings
    
    def _load_react_patterns(self) -> List[Dict]:
        """Load React security patterns."""
        return [
            {
                'pattern': r'dangerouslySetInnerHTML.*__html:.*\{.*\}',
                'message': 'Potential XSS via dangerouslySetInnerHTML',
                'severity': 'HIGH'
            },
            {
                'pattern': r'React\.createElement\(["\']script["\']',
                'message': 'Dynamic script tag creation',
                'severity': 'HIGH'
            }
        ]
    
    def _load_node_patterns(self) -> List[Dict]:
        """Load Node.js security patterns."""
        return [
            {
                'pattern': r'require\(["\']child_process["\'].*exec',
                'message': 'Command execution detected',
                'severity': 'HIGH'
            },
            {
                'pattern': r'fs\.(readFile|writeFile).*\.\.',
                'message': 'Potential path traversal',
                'severity': 'HIGH'
            }
        ]


class CrossLanguageTaintAnalyzer:
    """Cross-language taint analysis for multi-language codebases."""
    
    def __init__(self):
        self.taint_sources = self._load_taint_sources()
        self.taint_sinks = self._load_taint_sinks()
    
    def analyze_data_flow(self, files: List[str]) -> List[Dict[str, Any]]:
        """Analyze data flow across multiple languages."""
        findings = []
        
        # Build cross-language call graph
        call_graph = self._build_call_graph(files)
        
        # Trace taint from sources to sinks
        for source in self.taint_sources:
            taint_paths = self._trace_taint(source, call_graph)
            findings.extend(self._convert_paths_to_findings(taint_paths))
        
        return findings
    
    def _build_call_graph(self, files: List[str]) -> Dict[str, List[str]]:
        """Build call graph across languages."""
        call_graph = {}
        
        for file_path in files:
            if file_path.endswith('.py'):
                calls = self._extract_python_calls(file_path)
            elif file_path.endswith(('.ts', '.js', '.tsx', '.jsx')):
                calls = self._extract_js_calls(file_path)
            else:
                continue
                
            call_graph[file_path] = calls
        
        return call_graph
    
    def _extract_python_calls(self, file_path: str) -> List[str]:
        """Extract function calls from Python file."""
        calls = []
        
        try:
            with open(file_path, 'r') as f:
                tree = ast.parse(f.read())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.append(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        calls.append(f"{ast.unparse(node.func.value)}.{node.func.attr}")
        except:
            pass
        
        return calls
    
    def _extract_js_calls(self, file_path: str) -> List[str]:
        """Extract function calls from JavaScript/TypeScript file."""
        calls = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Simple regex-based extraction (could be enhanced with proper AST)
            call_patterns = [
                r'(\w+)\s*\(',
                r'(\w+\.\w+)\s*\(',
                r'await\s+(\w+)\s*\('
            ]
            
            for pattern in call_patterns:
                matches = re.findall(pattern, content)
                calls.extend(matches)
        except:
            pass
        
        return calls
    
    def _trace_taint(self, source: Dict, call_graph: Dict) -> List[List[str]]:
        """Trace taint from source through call graph."""
        paths = []
        
        # Simple taint tracing (could be enhanced with more sophisticated analysis)
        for file_path, calls in call_graph.items():
            if source['function'] in calls:
                for sink in self.taint_sinks:
                    if sink['function'] in calls:
                        paths.append([source['function'], sink['function']])
        
        return paths
    
    def _convert_paths_to_findings(self, paths: List[List[str]]) -> List[Dict[str, Any]]:
        """Convert taint paths to security findings."""
        findings = []
        
        for path in paths:
            if len(path) >= 2:
                findings.append({
                    'rule_id': 'cross-language-taint-flow',
                    'message': f'Taint flow detected: {" -> ".join(path)}',
                    'file_path': 'multiple',
                    'start_line': 0,
                    'end_line': 0,
                    'severity': 'HIGH',
                    'confidence': 0.8,
                    'taint_path': path
                })
        
        return findings
    
    def _load_taint_sources(self) -> List[Dict]:
        """Load taint sources across languages."""
        return [
            {'function': 'input', 'language': 'python', 'type': 'user_input'},
            {'function': 'sys.argv', 'language': 'python', 'type': 'command_line'},
            {'function': 'request.json', 'language': 'python', 'type': 'http_input'},
            {'function': 'req.body', 'language': 'javascript', 'type': 'http_input'},
            {'function': 'req.query', 'language': 'javascript', 'type': 'http_input'},
            {'function': 'process.argv', 'language': 'javascript', 'type': 'command_line'}
        ]
    
    def _load_taint_sinks(self) -> List[Dict]:
        """Load taint sinks across languages."""
        return [
            {'function': 'eval', 'language': 'python', 'type': 'code_execution'},
            {'function': 'exec', 'language': 'python', 'type': 'code_execution'},
            {'function': 'os.system', 'language': 'python', 'type': 'command_execution'},
            {'function': 'eval', 'language': 'javascript', 'type': 'code_execution'},
            {'function': 'Function', 'language': 'javascript', 'type': 'code_execution'},
            {'function': 'child_process.exec', 'language': 'javascript', 'type': 'command_execution'}
        ]


class MultiLanguageAnalyzer:
    """Unified multi-language security analyzer."""
    
    def __init__(self):
        self.ts_analyzer = TypeScriptAnalyzer()
        self.taint_analyzer = CrossLanguageTaintAnalyzer()
    
    def analyze_codebase(self, root_path: str) -> List[Dict[str, Any]]:
        """Analyze entire codebase across multiple languages."""
        findings = []
        
        # Collect all relevant files
        files = self._collect_files(root_path)
        
        # Language-specific analysis
        for file_path in files:
            if file_path.endswith(('.ts', '.tsx', '.js', '.jsx')):
                findings.extend(self.ts_analyzer.analyze_file(file_path))
        
        # Cross-language taint analysis
        findings.extend(self.taint_analyzer.analyze_data_flow(files))
        
        return findings
    
    def _collect_files(self, root_path: str) -> List[str]:
        """Collect all relevant source files."""
        extensions = ['.py', '.ts', '.tsx', '.js', '.jsx']
        files = []
        
        for ext in extensions:
            files.extend(str(p) for p in Path(root_path).rglob(f'*{ext}'))
        
        # Filter out common exclusions
        exclusions = ['node_modules', '.git', 'build', 'dist', '__pycache__']
        files = [f for f in files if not any(exc in f for exc in exclusions)]
        
        return files


if __name__ == "__main__":
    analyzer = MultiLanguageAnalyzer()
    findings = analyzer.analyze_codebase("/path/to/codebase")
    
    print(f"Found {len(findings)} security issues across multiple languages")
    for finding in findings[:5]:  # Show first 5
        print(f"- {finding['rule_id']}: {finding['message']}")