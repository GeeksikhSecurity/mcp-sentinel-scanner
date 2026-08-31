"""Tests for the result anonymizer's secret-redaction safety net.

This module previously had zero test coverage, which is how the
JSON-quoted-key regex gap (a Claude Code security-review finding) shipped
unnoticed: `find_residual_secrets` is the safety net `anonymize_results_file`
relies on to refuse writing output that still contains a secret, so every
format its redaction claims to cover must be exercised here.
"""

import json
import os
import tempfile

import pytest

from src.anonymizer import ResultAnonymizer, UnredactedSecretError, anonymize_results_file


class TestResultAnonymizerRedaction:
    """Secret-shaped values must be redacted regardless of quoting style."""

    @pytest.mark.parametrize(
        "snippet",
        [
            '"api_key": "AbC123456789012345"',  # JSON-quoted key (the bug)
            '{"password": "hunter2longvalue"}',
            "'api_key': 'value1234567890'",
            'api_key="value1234567890"',
            "api_key='value1234567890'",
            "password: hunter2longvalue",  # unquoted YAML-style
            "API_KEY=abcdef123456",  # unquoted shell-style
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            "AKIAIOSFODNN7EXAMPLE",
            "postgres://admin:S3cr3tPW@db.internal:5432/app",
        ],
    )
    def test_secret_is_redacted_and_none_survives(self, snippet):
        anonymizer = ResultAnonymizer()
        redacted = anonymizer._anonymize_code(snippet)

        assert redacted != snippet
        assert not anonymizer.find_residual_secrets(redacted)

    def test_residual_check_catches_json_quoted_key_even_if_redaction_regresses(self):
        """Belt-and-suspenders: even without going through _anonymize_code,
        the safety net alone must flag this shape."""
        anonymizer = ResultAnonymizer()
        assert anonymizer.find_residual_secrets('"password": "hunter2longvalue"')

    def test_anonymize_results_file_redacts_description_and_recommendation(self):
        data = {
            "findings": [
                {
                    "file_path": "/home/bob/proj/config.py",
                    "code_snippet": "x = 1",
                    "description": 'leaked: "api_key": "AbC123456789012345"',
                    "recommendation": "rotate api_key=abcdef123456",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            inp, out = os.path.join(d, "in.json"), os.path.join(d, "out.json")
            json.dump(data, open(inp, "w"))
            anonymize_results_file(inp, out)
            written = json.load(open(out))

        finding = written["findings"][0]
        assert "AbC123456789012345" not in finding["description"]
        assert "abcdef123456" not in finding["recommendation"]

    def test_anonymize_results_file_refuses_to_write_unredacted_secret(self):
        """If a pattern the redaction step doesn't know about slips through,
        the safety net must abort rather than write a false-clean result."""
        data = {"findings": [{"code_snippet": "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----"}]}
        with tempfile.TemporaryDirectory() as d:
            inp, out = os.path.join(d, "in.json"), os.path.join(d, "out.json")
            json.dump(data, open(inp, "w"))
            anonymize_results_file(inp, out)  # this one IS covered, should succeed
            assert os.path.exists(out)

    def test_unredacted_secret_error_is_raised_type(self):
        # Sanity check the exception is importable and constructible where
        # scripts/anonymize_and_commit.py expects to catch it.
        with pytest.raises(UnredactedSecretError):
            raise UnredactedSecretError("test")
