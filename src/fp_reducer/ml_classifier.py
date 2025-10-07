"""ML-based false positive classifier."""
import math
from typing import Dict, List, Tuple

from ..mcp_sentinel_scanner import VulnerabilityFinding


class MLClassifier:
    """Simple ML-based false positive classifier."""

    def __init__(self):
        # Simple rule-based weights (simulating ML model)
        self.feature_weights = {
            "is_test_file": -1.5,
            "has_test_prefix": -1.2,
            "high_entropy": 0.3,
            "in_comment": -2.0,
            "severity_critical": 0.2,
            "confidence_high": 0.1,
        }
        self.threshold = 0.5

    def predict_false_positive(
        self, finding: VulnerabilityFinding, context: Dict[str, bool]
    ) -> Tuple[bool, float]:
        """Predict if finding is false positive with confidence."""
        features = self._extract_features(finding, context)
        score = self._calculate_score(features)
        confidence = abs(score)  # Use absolute score as confidence

        is_fp = score < 0  # Negative score means false positive
        return is_fp, confidence

    def _extract_features(
        self, finding: VulnerabilityFinding, context: Dict[str, bool]
    ) -> Dict[str, float]:
        """Extract features for ML classification."""
        return {
            "is_test_file": 1.0 if context.get("is_test_file", False) else 0.0,
            "has_test_prefix": 1.0 if context.get("has_test_prefix", False) else 0.0,
            "high_entropy": 1.0 if self._calculate_entropy(finding.code_snippet) > 4.0 else 0.0,
            "in_comment": 1.0 if context.get("in_comment", False) else 0.0,
            "severity_critical": 1.0 if finding.severity == "CRITICAL" else 0.0,
            "confidence_high": 1.0 if finding.confidence > 0.8 else 0.0,
        }

    def _calculate_score(self, features: Dict[str, float]) -> float:
        """Calculate weighted score."""
        score = 0.0
        for feature, value in features.items():
            weight = self.feature_weights.get(feature, 0.0)
            score += weight * value
        return score

    def _sigmoid(self, x: float) -> float:
        """Sigmoid activation function."""
        return 1 / (1 + math.exp(-x))

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)

        return entropy

    def filter_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Filter findings using ML classifier."""
        filtered = []

        for finding in findings:
            context = {
                "is_test_file": "test" in finding.file_path.lower(),
                "has_test_prefix": any(
                    prefix in finding.code_snippet for prefix in ["MOCK_", "TEST_", "EXAMPLE_"]
                ),
                "in_comment": finding.code_snippet.strip().startswith("#"),
            }

            is_fp, confidence = self.predict_false_positive(finding, context)
            if not is_fp:
                filtered.append(finding)

        return filtered
