"""Regression fixture: quoted secret value -> hardcoded_secret."""
# Intentionally present for scanner regression (real-looking secret in quotes)
CLIENT_SECRET = "sk_test_FAKE_abc123def456789012345"  # noqa: S105 — intentional test fixture
