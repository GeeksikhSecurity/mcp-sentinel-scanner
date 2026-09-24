#!/usr/bin/env python3
"""Zero-dependency check that the CRA-friendly checklist artifacts exist and stay honest.

Fails (exit 1) when a required file is missing, a GitHub Action is not pinned to a
40-hex commit SHA, the checklist loses its disclaimer, or security-insights.yml
drifts from the v2 top-level layout. Schema validity is checked separately with
`cue vet` (see CRA-CHECKLIST.md).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["SECURITY.md", "CONTRIBUTING.md", "LICENSE", "CHANGELOG.md",
            "CRA-CHECKLIST.md", "security-insights.yml"]
DISCLAIMER = "have no obligations under the EU CRA"
V2_TOP_LEVEL = {"header", "project", "repository"}
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
SHA = re.compile(r"@[0-9a-f]{40}(\s|$)")

errors = []


def err(path, line, msg):
    errors.append(f"{path}:{line}: {msg}")


for name in REQUIRED:
    if not (ROOT / name).is_file():
        err(name, 0, "required file is missing")

for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
    for n, text in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
        m = USES.match(text)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if not SHA.search(text):
            err(wf.relative_to(ROOT), n, f"action not pinned to a commit SHA: {ref}")

checklist = ROOT / "CRA-CHECKLIST.md"
if checklist.is_file() and DISCLAIMER not in checklist.read_text(encoding="utf-8"):
    err("CRA-CHECKLIST.md", 0, "voluntary-disclosure disclaimer is missing")

insights = ROOT / "security-insights.yml"
if insights.is_file():
    text = insights.read_text(encoding="utf-8")
    top = set(re.findall(r"^([A-Za-z][\w-]*):", text, re.M))
    if top - V2_TOP_LEVEL:
        err("security-insights.yml", 0,
            f"non-v2 top-level keys: {sorted(top - V2_TOP_LEVEL)}")
    if not re.search(r"^\s+schema-version:\s*2\.\d+\.\d+\s*$", text, re.M):
        err("security-insights.yml", 0, "schema-version must be a 2.x.y release")

if errors:
    print("\n".join(errors), file=sys.stderr)
    print(f"\n{len(errors)} problem(s)", file=sys.stderr)
    sys.exit(1)
print("cra-checklist: ok")
