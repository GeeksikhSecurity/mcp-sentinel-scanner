#!/usr/bin/env python3
"""
Enhanced False Positive Filter for MCP Security Scanner
Advanced filtering with machine learning-inspired confidence scoring
"""

import re
import math
import json
from typing import Dict, List, Tuple, Optional, Set
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

@dataclass
class FilterResult:
    is_false_positive: bool
    confidence_score: float
    indicators: List[str]
    context: Dict[str, str]
    recommendation: str

class EnhancedFPFilter:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.fp_patterns = self._compile_patterns()
        self.context_analyzers = self._init_analyzers()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # Default configuration
        return {
            "entropy_thresholds": {
                "minimum_secret_entropy": 3.5,
                "minimum_token_entropy": 4.0,
                "minimum_key_entropy": 4.2
            },
            "confidence_thresholds": {
                "high_confidence": 0.8,
                "medium_confidence": 0.6,
                "low_confidence": 0.3
            },
            "context_weights": {
                "file_type_test": 0.2,
                "file_type_example": 0.3,
                "directory_type_test": 0.3,
                "code_type_test": 0.4
            }
        }
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for efficient matching"""
        patterns = {
            "test_indicators": [
                re.compile(r"test[_-]?key", re.IGNORECASE),
                re.compile(r"demo[_-]?secret", re.IGNORECASE),
                re.compile(r"example[_-]?token", re.IGNORECASE),
                re.compile(r"fake[_-]?api", re.IGNORECASE),
                re.compile(r"mock[_-]?auth", re.IGNORECASE),
                re.compile(r"placeholder", re.IGNORECASE),
                re.compile(r"your[_-]?key[_-]?here", re.IGNORECASE),
                re.compile(r"insert[_-]?token", re.IGNORECASE),
                re.compile(r"sample[_-]?credential", re.IGNORECASE),
                re.compile(r"dummy[_-]?password", re.IGNORECASE)
            ],
            "documentation_patterns": [
                re.compile(r"README\.md", re.IGNORECASE),
                re.compile(r"EXAMPLE", re.IGNORECASE),
                re.compile(r"TEMPLATE", re.IGNORECASE),
                re.compile(r"\.example", re.IGNORECASE),
                re.compile(r"docs/", re.IGNORECASE),
                re.compile(r"documentation/", re.IGNORECASE),
                re.compile(r"examples/", re.IGNORECASE),
                re.compile(r"samples/", re.IGNORECASE)
            ],
            "development_patterns": [
                re.compile(r"\.env\.example", re.IGNORECASE),
                re.compile(r"config\.example", re.IGNORECASE),
                re.compile(r"\.template", re.IGNORECASE),
                re.compile(r"development", re.IGNORECASE),
                re.compile(r"staging", re.IGNORECASE),
                re.compile(r"localhost", re.IGNORECASE),
                re.compile(r"127\.0\.0\.1", re.IGNORECASE)
            ],
            "sequential_patterns": [
                re.compile(r"key_?\d+", re.IGNORECASE),
                re.compile(r"token_?\d+", re.IGNORECASE),
                re.compile(r"secret_?\d+", re.IGNORECASE),
                re.compile(r"password_?\d+", re.IGNORECASE),
                re.compile(r"api_?\d+", re.IGNORECASE),
                re.compile(r"client_?\d+", re.IGNORECASE)
            ],
            "common_fake_values": [
                "abcdef123456", "your-api-key-here", "sk-test-123",
                "pk_test_", "rk_test_", "production_client_12345",
                "xxxxxxxxxxxxxxxx", "1234567890abcdef", "test-key-123"
            ]
        }
        return patterns
    
    def _init_analyzers(self) -> Dict[str, callable]:
        """Initialize analysis functions"""
        return {
            "entropy": self._calculate_entropy,
            "pattern_analysis": self._analyze_patterns,
            "file_context": self._analyze_file_context,
            "code_context": self._analyze_code_context,
            "semantic_context": self._analyze_semantic_context,
            "variable_context": self._analyze_variable_context,
            "comment_context": self._analyze_comment_context
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy for randomness assessment"""
        if not text or len(text) < 2:
            return 0.0
        
        # Remove common patterns that reduce entropy
        cleaned_text = re.sub(r'[_-]', '', text)
        
        counter = Counter(cleaned_text.lower())
        length = len(cleaned_text)
        
        if length == 0:
            return 0.0
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_patterns(self, content: str, file_path: str) -> Tuple[List[str], float]:
        """Analyze content for false positive patterns"""
        indicators = []
        penalty_score = 0.0
        
        # Test indicators
        for pattern in self.fp_patterns["test_indicators"]:
            if pattern.search(content):
                indicators.append(f"test_pattern:{pattern.pattern}")
                penalty_score += 0.2
        
        # Documentation patterns
        for pattern in self.fp_patterns["documentation_patterns"]:
            if pattern.search(file_path):
                indicators.append(f"doc_pattern:{pattern.pattern}")
                penalty_score += 0.3
        
        # Development patterns
        for pattern in self.fp_patterns["development_patterns"]:
            if pattern.search(content) or pattern.search(file_path):
                indicators.append(f"dev_pattern:{pattern.pattern}")
                penalty_score += 0.3
        
        # Sequential patterns
        for pattern in self.fp_patterns["sequential_patterns"]:
            if pattern.search(content):
                indicators.append(f"sequential:{pattern.pattern}")
                penalty_score += 0.4
        
        # Common fake values
        content_lower = content.lower()
        for fake_value in self.fp_patterns["common_fake_values"]:
            if fake_value.lower() in content_lower:
                indicators.append(f"fake_value:{fake_value}")
                penalty_score += 0.6
        
        return indicators, min(1.0, penalty_score)
    
    def _analyze_file_context(self, file_path: str) -> Dict[str, str]:
        """Analyze file path for context clues"""
        context = {}
        file_path_lower = file_path.lower()
        
        # File type classification
        if any(x in file_path_lower for x in ["test", "spec", "mock", "fixture"]):
            context["file_type"] = "test"
        elif any(x in file_path_lower for x in ["example", "demo", "sample", "template"]):
            context["file_type"] = "example"
        elif any(x in file_path_lower for x in ["doc", "readme", "guide", "tutorial"]):
            context["file_type"] = "documentation"
        elif any(x in file_path_lower for x in [".env.example", "config.example", ".template"]):
            context["file_type"] = "template"
        else:
            context["file_type"] = "production"
        
        # Directory analysis
        path_parts = file_path_lower.split('/')
        if any(x in path_parts for x in ["tests", "test", "__tests__", "spec", "__spec__"]):
            context["directory_type"] = "test"
        elif any(x in path_parts for x in ["examples", "samples", "demo", "docs", "documentation"]):
            context["directory_type"] = "example"
        elif any(x in path_parts for x in ["node_modules", "vendor", "third_party", "lib"]):
            context["directory_type"] = "dependency"
        else:
            context["directory_type"] = "production"
        
        # File extension analysis
        if file_path.endswith(('.test.py', '.spec.js', '.test.ts', '.spec.ts')):
            context["file_extension"] = "test"
        elif file_path.endswith(('.example.py', '.sample.js', '.demo.ts')):
            context["file_extension"] = "example"
        
        return context
    
    def _analyze_code_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze code context around the finding"""
        lines = content.split('\n')
        context = {}
        
        # Get surrounding lines for context
        start = max(0, line_number - 5)
        end = min(len(lines), line_number + 5)
        surrounding = '\n'.join(lines[start:end])
        
        # Check for test-related keywords in surrounding code
        test_keywords = ["test", "mock", "fixture", "example", "demo", "sample", "stub"]
        if any(keyword in surrounding.lower() for keyword in test_keywords):
            context["code_type"] = "test"
        
        # Check for function/class context
        func_patterns = [
            r"def\s+(test|mock|setup|teardown|fixture)",
            r"function\s+(test|mock|setup|teardown)",
            r"class\s+.*Test",
            r"describe\s*\(",
            r"it\s*\("
        ]
        
        for pattern in func_patterns:
            if re.search(pattern, surrounding, re.IGNORECASE):
                context["function_context"] = "test"
                break
        
        # Check for assertion patterns
        assertion_patterns = [
            r"assert", r"expect\(", r"should\.", r"\.toBe\(", r"\.toEqual\("
        ]
        
        for pattern in assertion_patterns:
            if re.search(pattern, surrounding, re.IGNORECASE):
                context["has_assertions"] = "true"
                break
        
        return context
    
    def _analyze_semantic_context(self, content: str) -> Dict[str, str]:
        """Semantic analysis for deeper context understanding"""
        context = {}
        
        # Variable naming analysis
        var_patterns = [
            r"(test|mock|fake|demo|example|sample)[_\w]*\s*=",
            r"\w*[_\-](test|mock|fake|demo|example|sample)\s*=",
            r"(TEST|MOCK|FAKE|DEMO|EXAMPLE|SAMPLE)[_\w]*\s*="
        ]
        
        for pattern in var_patterns:
            if re.search(pattern, content):
                context["variable_naming"] = "test_related"
                break
        
        # Import analysis
        import_patterns = [
            r"import.*test", r"from.*test", r"import.*mock",
            r"from.*mock", r"import.*fixture", r"from.*fixture"
        ]
        
        for pattern in import_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                context["imports"] = "test_related"
                break
        
        # Configuration analysis
        config_patterns = [
            r"config.*test", r"settings.*test", r"env.*test",
            r"development", r"staging", r"local"
        ]
        
        for pattern in config_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                context["configuration"] = "non_production"
                break
        
        return context
    
    def _analyze_variable_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze variable assignment context"""
        lines = content.split('\n')
        context = {}
        
        if line_number <= len(lines):
            current_line = lines[line_number - 1]
            
            # Check if it's a variable assignment
            if '=' in current_line:
                var_name = current_line.split('=')[0].strip()
                
                # Analyze variable name
                if any(x in var_name.lower() for x in ["test", "mock", "fake", "demo", "example"]):
                    context["variable_type"] = "test"
                elif any(x in var_name.lower() for x in ["prod", "production", "live"]):
                    context["variable_type"] = "production"
                else:
                    context["variable_type"] = "unknown"
        
        return context
    
    def _analyze_comment_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze comments for context clues"""
        lines = content.split('\n')
        context = {}
        
        # Check surrounding lines for comments
        start = max(0, line_number - 3)
        end = min(len(lines), line_number + 3)
        
        for i in range(start, end):
            if i < len(lines):
                line = lines[i]
                
                # Check for comment indicators
                comment_patterns = [
                    r"#.*fake", r"#.*test", r"#.*example", r"#.*demo",
                    r"//.*fake", r"//.*test", r"//.*example", r"//.*demo",
                    r"/\*.*fake", r"/\*.*test", r"/\*.*example", r"/\*.*demo"
                ]
                
                for pattern in comment_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        context["has_test_comment"] = "true"
                        return context
        
        return context
    
    def analyze_finding(self, content: str, file_path: str, line_number: int, 
                       vulnerability_type: str) -> FilterResult:
        """Comprehensive analysis of a security finding"""
        
        # Run all analyzers
        entropy = self._calculate_entropy(content)
        pattern_indicators, pattern_penalty = self._analyze_patterns(content, file_path)
        file_context = self._analyze_file_context(file_path)
        code_context = self._analyze_code_context(content, line_number)
        semantic_context = self._analyze_semantic_context(content)
        variable_context = self._analyze_variable_context(content, line_number)
        comment_context = self._analyze_comment_context(content, line_number)
        
        # Combine all context
        full_context = {
            **file_context,
            **code_context,
            **semantic_context,
            **variable_context,
            **comment_context
        }
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(
            entropy, pattern_penalty, full_context, vulnerability_type
        )
        
        # Determine if it's a false positive
        is_false_positive = self._determine_false_positive(
            confidence_score, full_context, pattern_indicators
        )
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            confidence_score, is_false_positive, full_context
        )
        
        return FilterResult(
            is_false_positive=is_false_positive,
            confidence_score=confidence_score,
            indicators=pattern_indicators,
            context=full_context,
            recommendation=recommendation
        )
    
    def _calculate_confidence_score(self, entropy: float, pattern_penalty: float,
                                  context: Dict[str, str], vuln_type: str) -> float:
        """Calculate confidence score using weighted factors"""
        
        base_score = 1.0
        
        # Entropy factor (vulnerability-specific thresholds)
        entropy_thresholds = self.config["entropy_thresholds"]
        
        if vuln_type == "hardcoded_secret":
            min_entropy = entropy_thresholds.get("minimum_secret_entropy", 3.5)
        elif vuln_type in ["token", "api_key"]:
            min_entropy = entropy_thresholds.get("minimum_token_entropy", 4.0)
        else:
            min_entropy = entropy_thresholds.get("minimum_key_entropy", 4.2)
        
        if entropy < min_entropy:
            entropy_factor = entropy / min_entropy
            base_score *= entropy_factor
        
        # Pattern penalty
        base_score *= (1.0 - pattern_penalty)
        
        # Context penalties
        context_weights = self.config["context_weights"]
        
        for context_key, weight in context_weights.items():
            if context_key in context:
                base_score *= weight
        
        # Additional context-specific penalties
        if context.get("file_type") == "test":
            base_score *= 0.2
        elif context.get("file_type") == "example":
            base_score *= 0.3
        elif context.get("file_type") == "documentation":
            base_score *= 0.1
        
        if context.get("directory_type") == "test":
            base_score *= 0.3
        elif context.get("directory_type") == "example":
            base_score *= 0.4
        
        if context.get("has_test_comment") == "true":
            base_score *= 0.5
        
        return max(0.0, min(1.0, base_score))
    
    def _determine_false_positive(self, confidence_score: float, 
                                context: Dict[str, str], 
                                indicators: List[str]) -> bool:
        """Determine if finding is likely a false positive"""
        
        # Very low confidence = likely false positive
        if confidence_score < self.config["confidence_thresholds"]["low_confidence"]:
            return True
        
        # Multiple strong indicators = likely false positive
        if len(indicators) > 2:
            return True
        
        # Test context with low confidence = likely false positive
        if (context.get("file_type") == "test" or 
            context.get("directory_type") == "test") and confidence_score < 0.7:
            return True
        
        # Documentation/example files = likely false positive
        if context.get("file_type") in ["documentation", "example"] and confidence_score < 0.8:
            return True
        
        return False
    
    def _generate_recommendation(self, confidence_score: float, 
                               is_false_positive: bool, 
                               context: Dict[str, str]) -> str:
        """Generate actionable recommendation"""
        
        if is_false_positive:
            return "IGNORE - Likely false positive based on context analysis"
        
        thresholds = self.config["confidence_thresholds"]
        
        if confidence_score >= thresholds["high_confidence"]:
            return "URGENT - High confidence vulnerability, immediate review required"
        elif confidence_score >= thresholds["medium_confidence"]:
            return "REVIEW - Medium confidence, manual verification recommended"
        else:
            return "LOW_PRIORITY - Low confidence, review when time permits"
    
    def batch_filter(self, findings: List[Dict]) -> List[Dict]:
        """Filter a batch of findings"""
        filtered_findings = []
        
        for finding in findings:
            result = self.analyze_finding(
                content=finding.get("content", ""),
                file_path=finding.get("file_path", ""),
                line_number=finding.get("line_number", 1),
                vulnerability_type=finding.get("vulnerability_type", "unknown")
            )
            
            # Add filter results to finding
            finding["filter_result"] = {
                "is_false_positive": result.is_false_positive,
                "confidence_score": result.confidence_score,
                "indicators": result.indicators,
                "context": result.context,
                "recommendation": result.recommendation
            }
            
            # Only include non-false positives
            if not result.is_false_positive:
                filtered_findings.append(finding)
        
        return filtered_findings