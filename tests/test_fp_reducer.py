"""Tests for false positive reduction."""

from src.fp_reducer import ContextAnalyzer, MLClassifier
from src.mcp_sentinel_scanner import VulnerabilityFinding


class TestContextAnalyzer:
    """Test context-aware false positive analyzer."""

    def test_is_test_file_detection(self):
        """Test test file detection."""
        analyzer = ContextAnalyzer()

        assert analyzer._is_test_file("src/component.test.js")
        assert analyzer._is_test_file("tests/unit/helper.py")
        assert analyzer._is_test_file("__tests__/app.spec.ts")
        assert analyzer._is_test_file("stories/Button.stories.js")
        assert not analyzer._is_test_file("src/component.js")
        assert not analyzer._is_test_file("lib/utils.py")

    def test_has_test_prefix_detection(self):
        """Test test prefix detection."""
        analyzer = ContextAnalyzer()

        assert analyzer._has_test_prefix("const MOCK_API_KEY = 'test'")
        assert analyzer._has_test_prefix("TEST_SECRET = 'value'")
        assert analyzer._has_test_prefix("EXAMPLE_TOKEN = 'abc123'")
        assert not analyzer._has_test_prefix("const API_KEY = 'real'")

    def test_test_context_detection(self):
        """Test test context detection in file content."""
        analyzer = ContextAnalyzer()

        file_content = """
describe('Auth service', () => {
    it('should authenticate user', () => {
        const API_KEY = 'test-key-123';
        expect(auth.login(API_KEY)).toBe(true);
    });
});
"""

        finding = VulnerabilityFinding(
            severity="HIGH",
            category="hardcoded_secret",
            description="Test",
            file_path="test.js",
            line_number=4,
            code_snippet="const API_KEY = 'test-key-123';",
            recommendation="Test",
        )

        assert analyzer._is_test_context(finding, file_content)

    def test_nosec_comment_detection(self):
        """Test nosec comment detection."""
        analyzer = ContextAnalyzer()

        finding = VulnerabilityFinding(
            severity="HIGH",
            category="hardcoded_secret",
            description="Test",
            file_path="test.js",
            line_number=1,
            code_snippet="const API_KEY = 'secret'; // nosec",
            recommendation="Test",
        )

        assert analyzer.is_likely_false_positive(finding)

    def test_filter_findings(self, tmp_path):
        """Test filtering findings."""
        # Create test file
        test_file = tmp_path / "component.test.js"
        test_file.write_text(
            """
describe('Component', () => {
    const MOCK_SECRET = 'test-secret-123';
});
"""
        )

        findings = [
            VulnerabilityFinding(
                severity="HIGH",
                category="hardcoded_secret",
                description="Test finding",
                file_path=str(test_file),
                line_number=3,
                code_snippet="const MOCK_SECRET = 'test-secret-123';",
                recommendation="Test",
            ),
            VulnerabilityFinding(
                severity="HIGH",
                category="hardcoded_secret",
                description="Real finding",
                file_path="src/config.js",
                line_number=1,
                code_snippet="const API_KEY = 'real-secret';",
                recommendation="Test",
            ),
        ]

        analyzer = ContextAnalyzer()
        filtered = analyzer.filter_findings(findings)

        # Should filter out test file finding
        assert len(filtered) == 1
        assert filtered[0].file_path == "src/config.js"


class TestMLClassifier:
    """Test ML-based false positive classifier."""

    def test_feature_extraction(self):
        """Test feature extraction."""
        classifier = MLClassifier()

        finding = VulnerabilityFinding(
            severity="CRITICAL",
            category="hardcoded_secret",
            description="Test",
            file_path="test.js",
            line_number=1,
            code_snippet="const SECRET = 'abcdef123456';",
            recommendation="Test",
            confidence=0.9,
        )

        context = {"is_test_file": True, "has_test_prefix": False, "in_comment": False}

        features = classifier._extract_features(finding, context)

        assert features["is_test_file"] == 1.0
        assert features["has_test_prefix"] == 0.0
        assert features["severity_critical"] == 1.0
        assert features["confidence_high"] == 1.0

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        classifier = MLClassifier()

        # High entropy string (random)
        high_entropy = classifier._calculate_entropy("aB3$kL9@mN2#")

        # Low entropy string (repeated)
        low_entropy = classifier._calculate_entropy("aaaaaaaaaa")

        assert high_entropy > low_entropy
        assert high_entropy > 3.0
        assert low_entropy < 2.0

    def test_sigmoid_function(self):
        """Test sigmoid activation function."""
        classifier = MLClassifier()

        assert classifier._sigmoid(0) == 0.5
        assert classifier._sigmoid(10) > 0.9
        assert classifier._sigmoid(-10) < 0.1

    def test_false_positive_prediction(self):
        """Test false positive prediction."""
        classifier = MLClassifier()

        # Test file finding (likely FP)
        test_finding = VulnerabilityFinding(
            severity="HIGH",
            category="hardcoded_secret",
            description="Test",
            file_path="component.test.js",
            line_number=1,
            code_snippet="const MOCK_SECRET = 'test';",
            recommendation="Test",
            confidence=0.8,
        )

        context = {"is_test_file": True, "has_test_prefix": True, "in_comment": False}

        is_fp, confidence = classifier.predict_false_positive(test_finding, context)
        assert is_fp  # Should be classified as false positive
        assert confidence > 0.5

        # Production finding (likely real)
        prod_finding = VulnerabilityFinding(
            severity="CRITICAL",
            category="hardcoded_secret",
            description="Real secret",
            file_path="src/config.js",
            line_number=1,
            code_snippet="const API_KEY = 'sk-real-secret';",
            recommendation="Fix",
            confidence=0.95,
        )

        context = {"is_test_file": False, "has_test_prefix": False, "in_comment": False}

        is_fp, confidence = classifier.predict_false_positive(prod_finding, context)
        assert not is_fp  # Should not be classified as false positive

    def test_filter_findings(self):
        """Test filtering findings with ML classifier."""
        classifier = MLClassifier()

        findings = [
            VulnerabilityFinding(
                severity="HIGH",
                category="hardcoded_secret",
                description="Test finding",
                file_path="component.test.js",
                line_number=1,
                code_snippet="const MOCK_SECRET = 'test';",
                recommendation="Test",
            ),
            VulnerabilityFinding(
                severity="CRITICAL",
                category="hardcoded_secret",
                description="Real finding",
                file_path="src/config.js",
                line_number=1,
                code_snippet="const API_KEY = 'real-secret';",
                recommendation="Fix",
            ),
        ]

        filtered = classifier.filter_findings(findings)

        # Should filter out test finding
        assert len(filtered) == 1
        assert filtered[0].file_path == "src/config.js"
