"""
Result anonymizer for safe GitHub commits.
Removes sensitive paths and code snippets while preserving security analysis.
"""

import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Any


class ResultAnonymizer:
    """Anonymizes scan results for safe public sharing."""
    
    def __init__(self):
        self.path_mapping = {}
        self.code_mapping = {}
        
    def anonymize_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize complete scan results."""
        anonymized = results.copy()
        
        # Anonymize findings
        if 'findings' in anonymized:
            anonymized['findings'] = [
                self._anonymize_finding(finding) 
                for finding in anonymized['findings']
            ]
            
        # Anonymize scan summary paths
        if 'scan_summary' in anonymized:
            anonymized['scan_summary'] = self._anonymize_summary(
                anonymized['scan_summary']
            )
            
        return anonymized
    
    # Free-text fields that may echo scanned (third-party) source back to the
    # caller and must go through the same redaction as code_snippet before
    # this result is ever committed to a public repo.
    _TEXT_FIELDS = ('code_snippet', 'description', 'recommendation', 'message', 'raw')

    def _anonymize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize individual finding."""
        anonymized = finding.copy()

        # Anonymize file path
        if 'file_path' in anonymized:
            anonymized['file_path'] = self._anonymize_path(anonymized['file_path'])

        # Anonymize every free-text field that could carry a verbatim secret,
        # not just code_snippet.
        for field in self._TEXT_FIELDS:
            if field in anonymized and isinstance(anonymized[field], str):
                anonymized[field] = self._anonymize_code(anonymized[field])

        return anonymized
    
    def _anonymize_path(self, file_path: str) -> str:
        """Convert file path to anonymous format."""
        if file_path in self.path_mapping:
            return self.path_mapping[file_path]
            
        # Extract components
        path_obj = Path(file_path)
        parts = path_obj.parts
        
        # Generate anonymous path
        anonymous_parts = []
        for i, part in enumerate(parts):
            if i == 0:  # Root
                anonymous_parts.append('/anonymous')
            elif part in ['src', 'lib', 'app', 'components']:
                anonymous_parts.append(part)
            elif part.endswith('.py'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.py')
            elif part.endswith('.js'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.js')
            elif part.endswith('.ts'):
                anonymous_parts.append(f'file_{self._hash_string(part)[:8]}.ts')
            else:
                anonymous_parts.append(f'dir_{self._hash_string(part)[:8]}')
                
        anonymous_path = '/'.join(anonymous_parts)
        self.path_mapping[file_path] = anonymous_path
        return anonymous_path
    
    def _anonymize_code(self, code_snippet: str) -> str:
        """Anonymize code snippet while preserving vulnerability pattern."""
        if code_snippet in self.code_mapping:
            return self.code_mapping[code_snippet]
            
        anonymized = code_snippet

        for pattern, replacement in self.SENSITIVE_PATTERNS:
            anonymized = pattern.sub(replacement, anonymized)

        self.code_mapping[code_snippet] = anonymized
        return anonymized

    # Patterns are compiled once and shared across instances. Both single-
    # and double-quoted assignments are covered (the previous version only
    # matched `key="value"`), along with common vendor secret formats and
    # other value shapes that show up verbatim in scanned (third-party) code
    # snippets and must never reach a public commit.
    # Shared alternation for secret-shaped field names, reused by both the
    # redaction patterns and the residual-secret safety net below so they
    # can't silently drift apart.
    _SECRET_KEY_NAMES = (
        r'client_secret|api[_-]?key|secret[_-]?key|password|passwd|'
        r'token|access[_-]?token|auth[_-]?token|private[_-]?key'
    )

    SENSITIVE_PATTERNS = [
        # key="value" / key='value' / "key": "value" (JSON) / 'key': 'value'
        # assignments for common secret-shaped names. The optional \1?/\4?
        # quote pair handles the key name itself being quoted (as in JSON),
        # not just the value — a bare `\s*[:=]\s*` right after the key name
        # (no optional quote) misses `"api_key": "..."` entirely because the
        # key's own closing quote sits between the name and the colon.
        (re.compile(
            r'(?i)(["\'])?\b(' + _SECRET_KEY_NAMES + r')\b\1?'
            r'(\s*[:=]\s*)(["\'])[^"\']*\4'
        ), r'\1\2\1\3\4<REDACTED>\4'),
        # Unquoted assignments (YAML/env/shell style), e.g. `password: hunter2`
        # or `API_KEY=abcdef123456`. Bounded to 6+ chars to avoid mangling
        # short type annotations like `token: str`; over-redaction here is
        # the safe failure mode, under-redaction is the one that leaks.
        (re.compile(
            r'(?i)\b(' + _SECRET_KEY_NAMES + r')\b(\s*[:=]\s*)'
            r'(?!["\'])([A-Za-z0-9_\-./+]{6,})'
        ), r'\1\2<REDACTED>'),
        # Authorization / Bearer headers
        (re.compile(r'(?i)\bauthorization["\']?\s*[:=]\s*["\']?Bearer\s+\S+'),
         'Authorization: Bearer <REDACTED>'),
        (re.compile(r'(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer <REDACTED>'),
        # Vendor-specific secret prefixes (OpenAI, GitHub, Slack, AWS, Stripe)
        (re.compile(r'\bsk-[A-Za-z0-9]{16,}\b'), '<REDACTED_API_KEY>'),
        (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b'), '<REDACTED_GITHUB_TOKEN>'),
        (re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'), '<REDACTED_SLACK_TOKEN>'),
        (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '<REDACTED_AWS_KEY_ID>'),
        (re.compile(r'(?i)\baws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
         'aws_secret_access_key=<REDACTED>'),
        (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), '<REDACTED_GOOGLE_KEY>'),
        # PEM-style private key blocks
        (re.compile(
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
            re.DOTALL,
        ), '<REDACTED_PRIVATE_KEY>'),
        # Connection strings with embedded credentials, e.g. postgres://user:pass@host
        (re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s:@]+@'),
         r'\1<REDACTED_CREDENTIALS>@'),
        (re.compile(r'/home/[^/\s]*'), '/home/<USER>'),
        (re.compile(r'/Users/[^/\s]*'), '/Users/<USER>'),
        (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), '<EMAIL>'),
        (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '<IP_ADDRESS>'),
    ]

    # Residual-secret checks run after redaction as a last-resort safety net
    # before results are ever committed publicly.
    _RESIDUAL_SECRET_CHECKS = [
        re.compile(r'\bsk-[A-Za-z0-9]{16,}\b'),
        re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b'),
        re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
        re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
        re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
        # Same key-name set and quoted-key handling as SENSITIVE_PATTERNS
        # above — this check exists specifically to catch what redaction
        # missed, so it must not share redaction's blind spots.
        re.compile(
            r'(?i)(["\'])?\b(' + _SECRET_KEY_NAMES + r')\b\1?'
            r'(\s*[:=]\s*)(["\'])(?!<REDACTED)[^"\']{4,}\4'
        ),
        re.compile(
            r'(?i)\b(' + _SECRET_KEY_NAMES + r')\b(\s*[:=]\s*)'
            r'(?!["\'])(?!<REDACTED\b)([A-Za-z0-9_\-./+]{6,})'
        ),
    ]

    def find_residual_secrets(self, text: str) -> List[str]:
        """Return any secret-shaped substrings that survived redaction."""
        hits = []
        for pattern in self._RESIDUAL_SECRET_CHECKS:
            hits.extend(m.group(0) for m in pattern.finditer(text))
        return hits
    
    def _anonymize_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize scan summary."""
        anonymized = summary.copy()
        
        # Remove or anonymize sensitive summary data
        if 'scan_path' in anonymized:
            anonymized['scan_path'] = '/anonymous/project'
            
        return anonymized
    
    def _hash_string(self, text: str) -> str:
        """Generate consistent hash for string."""
        # Not used for security (no secrets, no integrity/signature check) —
        # just a stable short identifier for anonymized filenames. Flagged
        # by bandit (B324) regardless, so mark intent explicitly.
        return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


class UnredactedSecretError(RuntimeError):
    """Raised when secret-shaped content survives anonymization."""


def anonymize_results_file(input_file: str, output_file: str) -> None:
    """Anonymize results file for safe sharing.

    Raises UnredactedSecretError instead of writing output_file if anything
    secret-shaped survives redaction — this file may be committed to a
    public repo, so a false "clean" result here would leak live credentials
    found in scanned (third-party) code.
    """
    anonymizer = ResultAnonymizer()

    with open(input_file, 'r') as f:
        results = json.load(f)

    anonymized = anonymizer.anonymize_scan_results(results)

    serialized = json.dumps(anonymized, indent=2)
    residual = anonymizer.find_residual_secrets(serialized)
    if residual:
        preview = ', '.join(sorted(set(residual))[:5])
        raise UnredactedSecretError(
            f"Refusing to write {output_file}: {len(residual)} secret-shaped "
            f"value(s) survived anonymization (e.g. {preview}). Extend the "
            "redaction patterns in ResultAnonymizer before committing."
        )

    with open(output_file, 'w') as f:
        f.write(serialized)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python result_anonymizer.py <input_file> <output_file>")
        sys.exit(1)
        
    anonymize_results_file(sys.argv[1], sys.argv[2])