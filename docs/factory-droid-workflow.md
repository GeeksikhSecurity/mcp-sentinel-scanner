# Factory Droid Workflow — SecurityLeader.ai + Sayva Research

**Version:** 1.2 (2026-04-17)

**Context:** Using Factory Droids as your thinking partner + blindspot finder instead of Claude Max/Gemini for research validation, distillation, and git project completion.

**Scope:** Strategy layer only — problem framing, why-Droid reasoning, and status. All copy-paste Linear issue bodies live in `factory-droid-linear-templates.md`. Each Use Case below points to the matching template. Use cases without templates (SAY-126, SAY-106) are explicitly marked — promote them to templates when ready.

---

## **Use Case 1: Blog Publishing + Research Validation (SAY-70, SAY-65, SAY-66)**

### SAY-70: "Promptfoo vs. MCP Sentinel: Complementary, Not Competing"
**Status:** Written, build-tested, ready for GitHub push
**What's blocking:** Final validation pass before deploy
**Why Droid (Supervised):** Validation is a checklist + numeric rubric — bounded, binary output. Human sees the scoring before any merge.
**Template:** `factory-droid-linear-templates.md` → Template 1

---

## **Use Case 2: Research Distillation (SAY-124, SAY-126, SAY-127)**

### SAY-124: Apply Vicky Zhao "Input to Output" Frameworks to ContentPipeline
**Problem:** You research security topics at depth but stall at distillation. Three posts sit in Todo.
**Frameworks used:** Visible Expertise Workshop · 3 Week Input→Output Sprint · 4 Steps to Clarity Workshop — these directly solve the research-depth → actionable-insight bottleneck.
**Why Droid (Supervised):** The framework is explicit. Droid runs the framework mechanically; you judge whether the distilled thesis is correct.
**Template:** `factory-droid-linear-templates.md` → Template 2

---

### SAY-126: Complexity-to-Clarity Visual Dashboard — ⚠️ Strategy only, no template yet
**Problem:** Expertise trapped in depth (40-page analysis vs. 1-2 next steps)
**Goal:** Visual dashboard that distills PCI/AppSec/supply chain for CISO audience
**Why no template yet:** Output format (Mermaid vs. React component vs. Figma) isn't decided. Promote to Template 6 once the visual medium is chosen. Full draft task body retained below.

**Droid Task (draft — not yet dispatched):**
```yaml
Title: "Design Complexity-to-Clarity dashboard: 3 security domains → 1 visual"
Description: |
  Problem: You write deep SecurityLeader.ai posts (8 components, long-form).
  Audience needs: "Here's what I do Monday."
  
  Three domains to distill:
  1. PCI DSS compliance (reduce to 3 control families, 5 actions)
  2. Application security (reduce to SSDLC + 3 gates)
  3. Supply chain attacks (reduce to 4 risk vectors, 2 immediate defenses)
  
  Task:
  1. Read your 3 most-read SecurityLeader.ai posts on each domain
  2. Extract the "So What" for each (1 sentence per domain)
  3. Design a visual (Mermaid or React component outline):
     - Input: "I'm a CISO, I have [problem]"
     - Output: "Your next 2 steps are..."
  4. Propose what goes in each quadrant/node
  5. Suggest metrics (email opens, time-to-decision, etc.)
  
  Output: Design doc (Markdown + Mermaid) + React component skeleton
  Autonomy: Supervised (show mock design, request feedback)
```

---

### SAY-127: Known-Unknown Matrix Triage
**Problem:** Can't distinguish "genuinely blocking" from "avoidance dressed as research."
**Framework:** Known-Unknown Matrix (per CLAUDE.md global rules).
**Why Droid (Autonomous):** Classification is rule-based once the matrix definitions are given. Autonomous execution is safe because the output is advisory — you review the spreadsheet before acting on any reclassification.
**Template:** `factory-droid-linear-templates.md` → Template 4

---

## **Use Case 3: Git Completion + Research Assistant (SAY-91, SAY-106, SAY-105)**

### SAY-91: Implement Vercel AI Gateway + use-workflow
**Context:** whatsonmybill.com 2-phase Claude API pipeline (PII redaction → bill analysis) streams 30–60 sec/session with uncontrolled cost.
**Status:** Documented, partially scoped, no code yet
**Why Droid (Supervised):** Code implementation with clear acceptance criteria. PII handling means security guardrails must be enforced by the template — not delegated to Droid judgment. Supervised so the PR gets human review before merge.
**Template:** `factory-droid-linear-templates.md` → Template 3 (security guardrails are non-negotiable — confirm they are present in the Linear issue before dispatching)

---

### SAY-106: SBOM Ingestion Bridge + CLAUDE.md Rules Pyramid — ⚠️ BLOCKED, no template yet
**Context:** Extends SAY-105 (OSSF Scorecard) + production sbom-debt pipeline (APA internal).
**Status:** Partially scoped. Not dispatchable.

#### Why this is blocked (both a mechanical and a framework problem)

**Mechanical:** Factory Droids work by cloning a repo and operating inside it. The scoping note currently says `Repo: TBD — new repo or extend existing?`. No repo means the Droid cannot even start; the first precondition (clone) fails.

**Framework:** "TBD" is not a neutral placeholder — it silently punts an org-structure decision to an executor that cannot make it. The task sits in Todo forever. This is the SAY-122 avoidance pattern in miniature: the decision feels heavy, so it gets delegated, so it never happens.

#### Known-Unknown Matrix diagnosis

The right quadrant depends on *who actually holds the answer*. Probe in this order — the first one that fits is the classification:

1. **Shared Context — most likely, most dangerous.** You already know which repo you'd use. You just haven't written it down. Resolution: 2 minutes. This is the quadrant that masquerades as the others; rule it out first.
2. **Cross-Functional Input.** The APA internal `sbom-debt` tool's license, IP boundaries, or team ownership govern whether it can be extended externally. If true, the blocker is *one email to the APA owner*, not a research project.
3. **Research Gap.** "New repo vs. extend" is a genuine architecture question with unclear trade-offs (module boundaries, dependency sprawl, release cadence). If true, timebox a 1-week spike — *do not* dispatch a Droid into an undecided architecture.
4. **Collective Unknown.** Unlikely. This is a scoping decision, not a frontier problem. If you find yourself here, you've misclassified.

My prior note ("Cross-Functional Input per Known-Unknown Matrix") was too confident — it assumed the APA ownership question is the real blocker. In practice, Shared Context is the more common diagnosis for TBD fields, so the order above matters.

#### Before a template can exist

- [ ] Decide repo: new `unified-security-scanner` under SecurityLeader.ai org, OR extend APA's `sbom-debt`
- [ ] If extending APA: confirm in writing that IP/license permits external extension (one email, logged in Linear)
- [ ] Define the four Rules Pyramid tiers (Critical/High/Medium/Low) with one worked example each
- [ ] Confirm OSV.dev rate limits will hold for the expected repo count
- [ ] Promote to `factory-droid-linear-templates.md` as Template 6

Draft scope (for reference when promoting): ingest CycloneDX + SPDX, enrich via OSV.dev, emit a Rules Pyramid `.mdc` file consumable by Claude Code. Extends SAY-105 patterns. Autonomy: Supervised (architecture review first).

---

## **Weekly Collision Sprint (SAY-123) — Enhanced with Droid**

**Current:** Manual cross-domain QMD queries (45 min/week)
**Enhanced:** Droid runs the sprint; surfaces patterns you'd miss.
**Why Droid (Autonomous):** Recurring pattern-match task with a time-boxed three-part structure. You read the summary and decide — no destructive actions, so autonomous is safe.
**Template:** `factory-droid-linear-templates.md` → Template 5 (recurring)

---

## **How to Invoke These with Factory Droid**

Invocation mechanics (Linear, CLI, IDE) live in `factory-droid-linear-templates.md` → "How to Invoke These" section. Single source of truth; see there.

---

## **Cost Model: Factory vs. Claude Max vs. Perplexity**

> ⚠️ The "Free (bonus)" column assumes Factory bonus credits are still active. Verify current balance before large tasks — once bonus is exhausted, Factory's post-bonus pricing applies and this table must be re-run.

| Task | Claude Max | Perplexity API | Factory Droid (bonus active) |
|------|-----------|----------------|------------------------------|
| Blog validation (SAY-70) | $0.20/use | $0.10/use | Free (bonus) |
| Research distillation (SAY-124) | $2–3/post | $1–2/post | Free (bonus) |
| Matrix triage (SAY-127) | $5–8 | $3–5 | Free (bonus) |
| Git completion (SAY-91) | $10–15 | $5–10 | Free (bonus) |
| **Weekly collision sprint** | $2–3/week | $1–2/week | Free (bonus) |
| **Monthly spend** | **~$20–30** | **~$15–20** | **~$0 while bonus lasts** |

---

## **Next Steps**

1. **Pick one task above** (recommend: SAY-70 blog validation)
2. **Invoke Droid** via Linear issue or CLI
3. **Set autonomy level** (start with `supervised`)
4. **Review output** — this teaches you how Droid reasons
5. **Iterate** on the task description if output misses the mark

**Your advantage:** You already know what "good" looks like. Droid is the apprentice who learns your standards.

---

## **References**
- Factory Docs: https://docs.factory.ai
- Linear Workspace: https://linear.app/sayvainc
- Your QMD Index: `/Volumes/2TBSSD/Development/Git/Forks/qmd` (9 collections, 50K vectors)
- SecurityLeader.ai Brand Voice: `/mnt/skills/user/brand-voice/SKILL.md`
- Vicky Zhao Frameworks: Notion → "Thinking Toolkit" (your collection)
