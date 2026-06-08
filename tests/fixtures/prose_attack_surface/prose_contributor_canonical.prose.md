---
name: prose-contributor
kind: system
---

# Prose Contributor (Canonical Defensively-Shaped Target)

Given completed OpenProse runs, turn real run friction into a small reviewable contribution.

### Services

- contribution-context
- evidence-collector
- opportunity-selector
- patch-author
- verifier
- pr-opener

### Requires

- subjects: run[] — completed runs that contain evidence for the contribution
- repository: path — local checkout
- scope: contribution scope (one of std | skills | docs | examples | platform)
- base-branch: target branch for the PR (default: main)
- pr-approval: explicit user approval to create a branch, push it, and open a PR

### Ensures

- contribution: structured report containing evidence, selected_opportunity, files_changed, verification, branch, pull_request, follow_ups
- pull_request: opened as draft unless user explicitly requests ready-for-review
- if no evidence-backed PR-sized improvement exists: no branch is pushed and no PR is opened

### Errors

- approval-required: pr-approval is absent or ambiguous
- no-actionable-improvement: subjects do not support a concrete small contribution
- repository-not-found: repository path is missing or is not a git checkout
- dirty-worktree: repository contains unrelated uncommitted changes
- gh-unavailable: GitHub CLI is unavailable or not authenticated
- verification-failed: validation failed
- pr-create-failed: branch pushed but PR creation failed

### Invariants

- never push directly to the base branch
- never open a pull request without explicit user approval for this specific contribution
- never batch unrelated improvements into one PR
- never modify files outside the selected scope unless the PR body names and justifies the exception
- never move language semantics into the CLI, or harness mechanics into the skill/specs
- never turn hosted product or subscription strategy into OSS language surface without a minimal public-runtime need
- never hide failed validation; if verification fails, stop before opening the PR unless the user explicitly asks for a failing draft PR
- never ask for more than one giving-back action in the same run

### Strategies

- before selecting a change: read CONTRIBUTING.md, README.md, AGENTS.md, SKILL.md, tenets.md, authoring.md
- prefer the smallest change that helps a future agent
- ground every change in evidence from the provided runs; do not invent improvements
- open draft PRs by default; ready-for-review PRs require explicit user direction
