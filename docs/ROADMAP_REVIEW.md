# Roadmap Review

**Date:** March 2026  
**Scope:** All roadmap and “next steps” content under `docs/` and repo root.

---

## 1. Where roadmap content lives

| Document | Location | Role |
|----------|----------|------|
| **ROADMAP.md** | Repo root | 12‑month phased plan (v1.0 → v4.0); Oct 2025; “Planning”. Phases 1–4 with P0/P1/P2 items, deliverables, resources, budget. |
| **IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md** | docs/ | **Active** status doc: what’s done (1.1–1.6), resumed work, **planned next steps** (5 items), corpus quick ref, blog index. |
| **repo-enhancement-plan.md** | docs/ | Feature backlog: Arcanum/sec-context/Garak/PyRIT/CT logs, Nuclei, multi-agent, SARIF, etc. Phased timeline (weeks 1–4, months 2–3). |
| **PRD_UNIFIED_SCANNER.md** | docs/ | Implementation roadmap (Phase 1–4 MVP→Enterprise); checkmarks on Phase 1–2; product-level. |
| **KENT_BECK_AND_CUSTOM_RULES_ANALYSIS.md** | docs/ | Code-quality “next steps”: tree consolidation, CLI extraction; some items already done. |
| **OPENSSF_SCORECARD.md** | docs/ | Improvement roadmap table + link to Enterprise Roadmap. |
| **archive/ENTERPRISE_SCALING_ROADMAP.md** | docs/archive/ | v3.0 enterprise scaling (multi-repo, CodeQL, TS/JS, dashboard, supply chain). |
| **archive/ROADMAP_V21_IMPLEMENTATION.md** | docs/archive/ | v2.1 implementation report (retrospective). |
| **CODEQL_INTEGRATION_PRD.md** | docs/ | CodeQL PRD with “Next Steps” (approve PRD, Phase 1). |
| **software-factory-claude-rules.md** | docs/ | References “sentinel-roadmap.md” in auto-memory; not the roadmap content itself. |
| **INFOGRAPHIC.html** | docs/ | “Development Roadmap: Future Enhancements” section (visual). |

---

## 2. Gaps and issues

### 2.1 No single source of truth

- **Near-term work** is split across:
  - **IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md** (§3 Planned Next Steps): full test suite, pin nightly refs, repo debloat, optional corpus/STATUS.
  - **ROADMAP.md** (root): P0/P1/P2 (CLI, CI, config, tests, rules, docs, perf) — older, some likely done.
  - **KENT_BECK_AND_CUSTOM_RULES_ANALYSIS.md**: tree consolidation, CLI extraction.
- **Feature backlog** is in **repo-enhancement-plan.md** (Arcanum, Garak, Nuclei, etc.); not clearly sequenced with the phased ROADMAP.md or with “planned next steps.”
- **Enterprise / v3.0** is in **archive/ENTERPRISE_SCALING_ROADMAP.md**; OPENSSF links to it. Relationship to root ROADMAP Phase 4 and PRD Phase 4 is implicit.

### 2.2 Staleness

- **ROADMAP.md**: “Last Updated: October 4, 2025”, “Status: Planning”. Many P0/P1 items (CLI entry point, CI running tests, error-handling tests, config integration) appear **done** (per IMPLEMENTATION_RESULTS and current code). The doc is not updated to reflect that.
- **PRD_UNIFIED_SCANNER.md**: Phase 1–2 marked ✅ but no date; unclear if it’s the canonical “what’s shipped” vs IMPLEMENTATION_RESULTS.
- **Version**: IMPLEMENTATION_RESULTS says “Version: 1.5.0”; ROADMAP targets v1.5 at end of Phase 1. No single “current version / current phase” statement that’s updated everywhere.

### 2.3 Overlap and duplication

- **Phase 1 (Foundation)** appears in both ROADMAP.md and PRD (MVP + FP reduction). Same themes (CLI, tests, config, SARIF) in both; details differ.
- **SARIF**: in ROADMAP Phase 2, PRD Phase 1 (✅), repo-enhancement-plan #11. Unclear if “SARIF for GitHub” is done or still backlog.
- **Corpus/tiers**: well described only in IMPLEMENTATION_RESULTS (§1, §4). ROADMAP and PRD don’t mention smoke/full/nightly.

### 2.4 What’s missing

- **Explicit mapping**: “Planned next steps” (IMPLEMENTATION_RESULTS) ↔ P0/P1 (ROADMAP) ↔ repo-enhancement-plan items. No table or section that says “these 5 items are the current sprint” or “ROADMAP P1.2 = done, P1.5 = next.”
- **Decision log**: Repo debloat (scans/, test_repos/) is “deferred” with a recommended path; that decision isn’t in a single “decisions” or “backlog” section.
- **Ownership / dates**: Most docs don’t assign owners or target dates for next steps.

---

## 3. Recommendations

### 3.1 One operational “what’s next” doc

- **Keep IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md** as the **primary** place for:
  - What’s done (with version and date).
  - **Planned next steps** (short list with optional target dates).
  - Corpus quick reference and pointers to blog/docs.
- Add a **short “Roadmap index”** at the top or in a dedicated subsection:
  - Link to ROADMAP.md for the 12‑month product vision.
  - Link to repo-enhancement-plan.md for the feature backlog (Arcanum, Garak, Nuclei, etc.).
  - Link to KENT_BECK_AND_CUSTOM_RULES_ANALYSIS.md for code-quality and refactor items.
  - Link to archive/ENTERPRISE_SCALING_ROADMAP.md for v3.0 / enterprise.

### 3.2 Refresh ROADMAP.md

- Update **“Last Updated”** and **“Status”** (e.g. “Phase 1 in progress” or “Phase 1 complete”).
- Mark **completed** items (e.g. P0.1–P0.3, P1.1–P1.2 if done) and add a one-line “Current state” that matches IMPLEMENTATION_RESULTS (e.g. “v1.5.0; corpus smoke/nightly; FP reduction on by default”).
- Add a **“See also”** at the top: link to IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md for detailed status and immediate next steps.

### 3.3 One-line “current roadmap” in README or STATUS

- If README or STATUS.md exists, add one sentence plus link, e.g.  
  **Current focus:** [link to IMPLEMENTATION_RESULTS §3] (full test suite, pin nightly refs, repo debloat). Full roadmap: [ROADMAP.md]. Feature backlog: [repo-enhancement-plan.md].

### 3.4 Optional: backlog table

- In IMPLEMENTATION_RESULTS or a new **docs/BACKLOG.md**, add a small table:
  - **Source** (e.g. “ROADMAP P1.5”, “repo-enhancement #2”, “Kent Beck §6”).
  - **Item** (one line).
  - **Status** (Backlog / Next / In progress / Done).
  - **Notes** (optional).
- Update when items are completed or reprioritized.

---

## 4. Summary

| Issue | Recommendation |
|-------|----------------|
| Multiple “next steps” locations | Treat IMPLEMENTATION_RESULTS_AND_NEXT_STEPS.md as the single operational “what’s next”; add a roadmap index there. |
| ROADMAP.md out of date | Refresh status and completion; link to IMPLEMENTATION_RESULTS; mark done items. |
| Backlog vs phased plan | Keep repo-enhancement-plan as feature backlog; ROADMAP as 12‑month product plan; document the link in the index. |
| No “current version/phase” | State current version and phase in IMPLEMENTATION_RESULTS and at top of ROADMAP.md. |
| Enterprise / v3.0 | Keep in archive; linked from OPENSSF and from the new roadmap index. |

Applying these will give a clear “roadmap in docs”: one place for **what to do next** (IMPLEMENTATION_RESULTS), one place for **product phases** (ROADMAP.md), one for **feature ideas** (repo-enhancement-plan), and explicit links between them.
