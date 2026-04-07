#!/usr/bin/env python3
"""
Enhanced False Positive Filter for MCP Security Scanner
Advanced filtering with machine learning-inspired confidence scoring.

Refactored for modularity (N): context rules, penalties, and recommendations
are data-driven; small pure functions replace long if/elif chains.
"""

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Data: file/directory context classification rules (increase N, single source)
# -----------------------------------------------------------------------------

FILE_TYPE_RULES: List[Tuple[List[str], str]] = [
    (["test", "spec", "mock", "fixture"], "test"),
    (["example", "demo", "sample", "template"], "example"),
    (["doc", "readme", "guide", "tutorial"], "documentation"),
    ([".env.example", "config.example", ".template"], "template"),
]

DIRECTORY_TYPE_RULES: List[Tuple[List[str], str]] = [
    (["tests", "test", "__tests__", "spec", "__spec__"], "test"),
    (["examples", "samples", "demo", "docs", "documentation"], "example"),
    (["node_modules", "vendor", "third_party", "lib"], "dependency"),
]

FILE_EXTENSION_TO_TYPE: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "test": ((".test.py", ".spec.js", ".test.ts", ".spec.ts"), "test"),
    "example": ((".example.py", ".sample.js", ".demo.ts"), "example"),
}

# Context key -> (value -> penalty multiplier). Used for confidence scoring.
CONTEXT_PENALTY_MULTIPLIERS: Dict[str, Dict[str, float]] = {
    "file_type": {"test": 0.2, "example": 0.3, "documentation": 0.1, "template": 0.25},
    "directory_type": {"test": 0.3, "example": 0.4},
    "has_test_comment": {"true": 0.5},
}

# Vuln type -> config key for minimum entropy threshold.
ENTROPY_CONFIG_KEY_BY_VULN: Dict[str, str] = {
    "hardcoded_secret": "minimum_secret_entropy",
    "token": "minimum_token_entropy",
    "api_key": "minimum_token_entropy",
}
DEFAULT_ENTROPY_CONFIG_KEY = "minimum_key_entropy"

# (min_confidence, message) for recommendation bands (high to low).
RECOMMENDATION_BANDS: List[Tuple[float, str]] = [
    (0.8, "URGENT - High confidence vulnerability, immediate review required"),
    (0.6, "REVIEW - Medium confidence, manual verification recommended"),
    (0.3, "LOW_PRIORITY - Low confidence, review when time permits"),
]

# -----------------------------------------------------------------------------
# Pure helpers: classify by rules (single responsibility, testable)
# -----------------------------------------------------------------------------


def _classify_by_keywords(
    text: str, rules: List[Tuple[List[str], str]], default: str
) -> str:
    """Return first rule value whose keywords appear in text, else default."""
    text_lower = text.lower()
    for keywords, value in rules:
        if any(kw in text_lower for kw in keywords):
            return value
    return default


def _classify_path_parts(path_parts: List[str], rules: List[Tuple[List[str], str]], default: str) -> str:
    """Return first rule value whose keywords appear in path_parts, else default."""
    for keywords, value in rules:
        if any(kw in path_parts for kw in keywords):
            return value
    return default


def _classify_file_extension(file_path: str) -> Optional[str]:
    """Return 'test' or 'example' from extension, else None."""
    for _suffixes, context_type in FILE_EXTENSION_TO_TYPE.values():
        if file_path.endswith(_suffixes):
            return context_type
    return None


def _get_entropy_threshold(vuln_type: str, config: Dict) -> float:
    """Return minimum entropy threshold for the given vulnerability type."""
    key = ENTROPY_CONFIG_KEY_BY_VULN.get(
        vuln_type, DEFAULT_ENTROPY_CONFIG_KEY
    )
    thresholds = config.get("entropy_thresholds", {})
    defaults = {
        "minimum_secret_entropy": 3.5,
        "minimum_token_entropy": 4.0,
        "minimum_key_entropy": 4.2,
    }
    return thresholds.get(key, defaults.get(key, 4.2))


def _apply_context_penalties(base_score: float, context: Dict[str, str]) -> float:
    """Apply all context-based penalty multipliers to base_score."""
    for context_key, value_to_multiplier in CONTEXT_PENALTY_MULTIPLIERS.items():
        value = context.get(context_key)
        if value is not None and value in value_to_multiplier:
            base_score *= value_to_multiplier[value]
    return base_score


def _recommendation_for_confidence(confidence_score: float) -> str:
    """Return recommendation message for given score using RECOMMENDATION_BANDS."""
    for min_confidence, message in RECOMMENDATION_BANDS:
        if confidence_score >= min_confidence:
            return message
    return "LOW_PRIORITY - Low confidence, review when time permits"


# -----------------------------------------------------------------------------
# Default config and pattern definitions (data only)
# -----------------------------------------------------------------------------

def _default_config() -> Dict:
    return {
        "entropy_thresholds": {
            "minimum_secret_entropy": 3.5,
            "minimum_token_entropy": 4.0,
            "minimum_key_entropy": 4.2,
        },
        "confidence_thresholds": {
            "high_confidence": 0.8,
            "medium_confidence": 0.6,
            "low_confidence": 0.3,
        },
        "context_weights": {
            "file_type_test": 0.2,
            "file_type_example": 0.3,
            "directory_type_test": 0.3,
            "code_type_test": 0.4,
        },
    }


def _build_fp_patterns() -> Dict:
    """Compile regex patterns and fake-value list for FP detection."""
    return {
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
            re.compile(r"dummy[_-]?password", re.IGNORECASE),
        ],
        "documentation_patterns": [
            re.compile(r"README\.md", re.IGNORECASE),
            re.compile(r"EXAMPLE", re.IGNORECASE),
            re.compile(r"TEMPLATE", re.IGNORECASE),
            re.compile(r"\.example", re.IGNORECASE),
            re.compile(r"docs/", re.IGNORECASE),
            re.compile(r"documentation/", re.IGNORECASE),
            re.compile(r"examples/", re.IGNORECASE),
            re.compile(r"samples/", re.IGNORECASE),
        ],
        "development_patterns": [
            re.compile(r"\.env\.example", re.IGNORECASE),
            re.compile(r"config\.example", re.IGNORECASE),
            re.compile(r"\.template", re.IGNORECASE),
            re.compile(r"development", re.IGNORECASE),
            re.compile(r"staging", re.IGNORECASE),
            re.compile(r"localhost", re.IGNORECASE),
            re.compile(r"127\.0\.0\.1", re.IGNORECASE),
        ],
        "sequential_patterns": [
            re.compile(r"key_?\d+", re.IGNORECASE),
            re.compile(r"token_?\d+", re.IGNORECASE),
            re.compile(r"secret_?\d+", re.IGNORECASE),
            re.compile(r"password_?\d+", re.IGNORECASE),
            re.compile(r"api_?\d+", re.IGNORECASE),
            re.compile(r"client_?\d+", re.IGNORECASE),
        ],
        "common_fake_values": [
            "abcdef123456", "your-api-key-here", "sk-test-123",
            "pk_test_", "rk_test_", "production_client_12345",
            "xxxxxxxxxxxxxxxx", "1234567890abcdef", "test-key-123",
        ],
    }


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

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
        self.fp_patterns = _build_fp_patterns()

    def _load_config(self, config_path: Optional[str]) -> Dict:
        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                return json.load(f)
        return _default_config()

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy for randomness assessment."""
        if not text or len(text) < 2:
            return 0.0
        cleaned_text = re.sub(r"[_-]", "", text)
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
        """Analyze content for false positive patterns."""
        indicators = []
        penalty_score = 0.0
        pattern_penalties = [
            (self.fp_patterns["test_indicators"], 0.2, content, "test_pattern"),
            (self.fp_patterns["documentation_patterns"], 0.3, file_path, "doc_pattern"),
            (self.fp_patterns["development_patterns"], 0.3, content + " " + file_path, "dev_pattern"),
            (self.fp_patterns["sequential_patterns"], 0.4, content, "sequential"),
        ]
        for patterns, penalty, target, prefix in pattern_penalties:
            for pattern in patterns:
                if pattern.search(target):
                    indicators.append(f"{prefix}:{pattern.pattern}")
                    penalty_score += penalty
        content_lower = content.lower()
        for fake_value in self.fp_patterns["common_fake_values"]:
            if fake_value.lower() in content_lower:
                indicators.append(f"fake_value:{fake_value}")
                penalty_score += 0.6
        return indicators, min(1.0, penalty_score)

    def _analyze_file_context(self, file_path: str) -> Dict[str, str]:
        """Analyze file path for context clues (data-driven classification)."""
        file_path_lower = file_path.lower()
        path_parts = file_path_lower.split("/")

        context = {
            "file_type": _classify_by_keywords(file_path_lower, FILE_TYPE_RULES, "production"),
            "directory_type": _classify_path_parts(path_parts, DIRECTORY_TYPE_RULES, "production"),
        }
        ext_type = _classify_file_extension(file_path)
        if ext_type is not None:
            context["file_extension"] = ext_type
        return context

    def _analyze_code_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze code context around the finding."""
        lines = content.split("\n")
        context = {}
        start = max(0, line_number - 5)
        end = min(len(lines), line_number + 5)
        surrounding = "\n".join(lines[start:end]).lower()

        test_keywords = ["test", "mock", "fixture", "example", "demo", "sample", "stub"]
        if any(kw in surrounding for kw in test_keywords):
            context["code_type"] = "test"

        func_patterns = [
            r"def\s+(test|mock|setup|teardown|fixture)",
            r"function\s+(test|mock|setup|teardown)",
            r"class\s+.*Test",
            r"describe\s*\(",
            r"it\s*\(",
        ]
        for pattern in func_patterns:
            if re.search(pattern, surrounding, re.IGNORECASE):
                context["function_context"] = "test"
                break

        assertion_patterns = [r"assert", r"expect\(", r"should\.", r"\.toBe\(", r"\.toEqual\("]
        for pattern in assertion_patterns:
            if re.search(pattern, surrounding, re.IGNORECASE):
                context["has_assertions"] = "true"
                break
        return context

    def _analyze_semantic_context(self, content: str) -> Dict[str, str]:
        """Semantic analysis for deeper context understanding."""
        context = {}
        var_patterns = [
            r"(test|mock|fake|demo|example|sample)[_\w]*\s*=",
            r"\w*[_\-](test|mock|fake|demo|example|sample)\s*=",
            r"(TEST|MOCK|FAKE|DEMO|EXAMPLE|SAMPLE)[_\w]*\s*=",
        ]
        for pattern in var_patterns:
            if re.search(pattern, content):
                context["variable_naming"] = "test_related"
                break
        import_patterns = [
            r"import.*test", r"from.*test", r"import.*mock",
            r"from.*mock", r"import.*fixture", r"from.*fixture",
        ]
        for pattern in import_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                context["imports"] = "test_related"
                break
        config_patterns = [
            r"config.*test", r"settings.*test", r"env.*test",
            r"development", r"staging", r"local",
        ]
        for pattern in config_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                context["configuration"] = "non_production"
                break
        return context

    def _analyze_variable_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze variable assignment context."""
        lines = content.split("\n")
        context = {}
        if line_number <= len(lines) and line_number >= 1:
            current_line = lines[line_number - 1]
            if "=" in current_line:
                var_name = current_line.split("=")[0].strip().lower()
                if any(x in var_name for x in ["test", "mock", "fake", "demo", "example"]):
                    context["variable_type"] = "test"
                elif any(x in var_name for x in ["prod", "production", "live"]):
                    context["variable_type"] = "production"
                else:
                    context["variable_type"] = "unknown"
        return context

    def _analyze_comment_context(self, content: str, line_number: int) -> Dict[str, str]:
        """Analyze comments for context clues."""
        lines = content.split("\n")
        context = {}
        start = max(0, line_number - 3)
        end = min(len(lines), line_number + 3)
        comment_patterns = [
            r"#.*fake", r"#.*test", r"#.*example", r"#.*demo",
            r"//.*fake", r"//.*test", r"//.*example", r"//.*demo",
            r"/\*.*fake", r"/\*.*test", r"/\*.*example", r"/\*.*demo",
        ]
        for i in range(start, end):
            if i < len(lines):
                line = lines[i]
                for pattern in comment_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        context["has_test_comment"] = "true"
                        return context
        return context

    def analyze_finding(
        self,
        content: str,
        file_path: str,
        line_number: int,
        vulnerability_type: str,
    ) -> FilterResult:
        """Comprehensive analysis of a security finding."""
        entropy = self._calculate_entropy(content)
        pattern_indicators, pattern_penalty = self._analyze_patterns(content, file_path)
        file_context = self._analyze_file_context(file_path)
        code_context = self._analyze_code_context(content, line_number)
        semantic_context = self._analyze_semantic_context(content)
        variable_context = self._analyze_variable_context(content, line_number)
        comment_context = self._analyze_comment_context(content, line_number)

        full_context = {
            **file_context,
            **code_context,
            **semantic_context,
            **variable_context,
            **comment_context,
        }

        confidence_score = self._calculate_confidence_score(
            entropy, pattern_penalty, full_context, vulnerability_type
        )
        is_false_positive = self._determine_false_positive(
            confidence_score, full_context, pattern_indicators
        )
        recommendation = self._generate_recommendation(
            confidence_score, is_false_positive, full_context
        )

        return FilterResult(
            is_false_positive=is_false_positive,
            confidence_score=confidence_score,
            indicators=pattern_indicators,
            context=full_context,
            recommendation=recommendation,
        )

    def _calculate_confidence_score(
        self,
        entropy: float,
        pattern_penalty: float,
        context: Dict[str, str],
        vuln_type: str,
    ) -> float:
        """Calculate confidence score using weighted factors (data-driven penalties)."""
        base_score = 1.0

        min_entropy = _get_entropy_threshold(vuln_type, self.config)
        if entropy < min_entropy:
            base_score *= entropy / min_entropy

        base_score *= 1.0 - pattern_penalty

        for context_key, weight in self.config.get("context_weights", {}).items():
            if context_key in context:
                base_score *= weight

        base_score = _apply_context_penalties(base_score, context)
        return max(0.0, min(1.0, base_score))

    def _determine_false_positive(
        self,
        confidence_score: float,
        context: Dict[str, str],
        indicators: List[str],
    ) -> bool:
        """Determine if finding is likely a false positive."""
        low = self.config["confidence_thresholds"].get("low_confidence", 0.3)
        if confidence_score < low:
            return True
        if len(indicators) > 2:
            return True
        if (
            context.get("file_type") == "test" or context.get("directory_type") == "test"
        ) and confidence_score < 0.7:
            return True
        if context.get("file_type") in ["documentation", "example"] and confidence_score < 0.8:
            return True
        return False

    def _generate_recommendation(
        self,
        confidence_score: float,
        is_false_positive: bool,
        context: Dict[str, str],
    ) -> str:
        """Generate actionable recommendation (data-driven bands)."""
        if is_false_positive:
            return "IGNORE - Likely false positive based on context analysis"
        return _recommendation_for_confidence(confidence_score)

    def batch_filter(self, findings: List[Dict]) -> List[Dict]:
        """Filter a batch of findings."""
        filtered_findings = []
        for finding in findings:
            result = self.analyze_finding(
                content=finding.get("content", ""),
                file_path=finding.get("file_path", ""),
                line_number=finding.get("line_number", 1),
                vulnerability_type=finding.get("vulnerability_type", "unknown"),
            )
            finding["filter_result"] = {
                "is_false_positive": result.is_false_positive,
                "confidence_score": result.confidence_score,
                "indicators": result.indicators,
                "context": result.context,
                "recommendation": result.recommendation,
            }
            if not result.is_false_positive:
                filtered_findings.append(finding)
        return filtered_findings
