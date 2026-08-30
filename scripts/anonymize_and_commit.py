#!/usr/bin/env python3
"""
Script to anonymize scan results and commit safely to GitHub.
Usage: python scripts/anonymize_and_commit.py <scan_results.json>
"""

import sys
import json
import subprocess
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from anonymizer import UnredactedSecretError, anonymize_results_file


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/anonymize_and_commit.py <scan_results.json>")
        sys.exit(1)

    input_file = sys.argv[1]

    # Generate output filename
    input_path = Path(input_file)
    output_file = f"anonymous_{input_path.name}"

    # Anonymize results. This raises UnredactedSecretError instead of
    # writing output_file if anything secret-shaped survives redaction —
    # never fall through to committing partially-redacted results.
    print(f"Anonymizing {input_file} -> {output_file}")
    try:
        anonymize_results_file(input_file, output_file)
    except UnredactedSecretError as e:
        print(f"❌ Refusing to commit: {e}")
        sys.exit(1)

    # Load anonymized results for commit message
    with open(output_file, 'r') as f:
        results = json.load(f)

    # Generate commit message
    summary = results.get('scan_summary', {})
    files_scanned = summary.get('files_scanned', 0)
    vulnerabilities = summary.get('vulnerabilities_found', 0)

    commit_msg = f"Add anonymized scan results: {vulnerabilities} findings across {files_scanned} files"

    # Git operations. Deliberately not "git add -f": output_file lives
    # alongside scan results that .gitignore excludes by design (e.g.
    # */results/*, security_research/) — forcing past that ignore rule is
    # how raw findings have leaked into commits before. If output_file is
    # ignored, fix the .gitignore rule or move it, don't force-add.
    try:
        subprocess.run(['git', 'add', output_file], check=True)
        subprocess.run(['git', 'commit', '-m', commit_msg], check=True)
        print(f"✅ Committed anonymized results: {output_file}")
        print(f"📊 Summary: {vulnerabilities} vulnerabilities in {files_scanned} files")
    except subprocess.CalledProcessError as e:
        print(f"❌ Git operation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()