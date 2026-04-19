# Factory Droid Linear Issue Templates
Copy-paste these into your Sayva Inc Linear workspace and assign to a Droid.

**Version:** 1.2 (2026-04-17)

**Scope:** Operational layer — copy-paste Linear issue bodies. For strategic context (why this task, quadrant classification, related work), see `factory-droid-workflow.md`.

## Pre-flight Checklist (apply to every template before dispatch)
- [ ] Repo confirmed and accessible to the Droid (no TBD)
- [ ] Autonomy level set: `Supervised` or `Autonomous`
- [ ] Labels applied: `#factory-droid` + one workflow sub-label (see Label Taxonomy below)
- [ ] Secrets guardrail: no credentials, no raw PII, no production data in non-production
- [ ] Success criteria are binary (gate passes or fails) — no subjective "good enough"

## Label Taxonomy (canonical)
Always apply `#factory-droid` + exactly one of:
- `#droid-validate` — gate checks, brand voice, compliance passes
- `#droid-thinking` — research distillation, framework application
- `#droid-build` — code changes, PRs, implementation
- `#droid-analyze` — triage, classification, pattern-finding
- `#droid-discovery` — cross-domain queries, recurring sprints

---

## **Template 1: Blog Publication Validation (SAY-70 variant)**

```
Title: [DROID] Validate SAY-70 blog post + publish gate check

Description:

### Task: Final validation pass for "Promptfoo vs. MCP Sentinel" blog

Read: `/posts/promptfoo-vs-mcp-sentinel.md` in securityleaderai-blog repo

**Checklist:**

✓ Brand Voice Compliance
- [ ] Italic hook present after H1?
- [ ] Executive Summary blockquote formatted correctly?
- [ ] All sources have APA citations?
- [ ] "Your Next Move" section is 1–2 concrete actions?
- [ ] "Board Talking Points" present (3–4 bullet items)?

✓ Weapons Check Gate (both must be ≥8 to publish)
- [ ] **Novelty:** Is this genuinely new insight vs. recap? (1–10 scale)
- [ ] **Intensity:** Will this land hard with security leaders? (1–10 scale)

**Rubric (use these definitions, do not invent your own):**
- Novelty 10 = thesis not published anywhere in the last 12 months; 8 = new synthesis of known parts; 5 = competent recap; ≤4 = already said better elsewhere
- Intensity 10 = CISO forwards to board same day; 8 = CISO saves and cites in next decision; 5 = reader finishes the post; ≤4 = skim-and-close

**Output:**
If ✓: "APPROVED FOR MERGE — ready for `git push`"
If ✗: List 3–5 specific fixes needed before approval

**Autonomy Level:** Supervised  
**Repo:** securityleaderai-blog  
**Branch:** `feature/say-70-publish`  
**Timeline:** 30 min

Labels: #blog-publication #droid-validate
```

---

## **Template 2: Research Distillation (SAY-124 variant)**

```
Title: [DROID] Apply Vicky Zhao "Input→Output" to 3 stalled blog posts

Description:

### Task: Unblock SAY-65, SAY-66 using Visible Expertise + 4 Steps to Clarity frameworks

**Context:**
You've purchased three Vicky Zhao courses. They directly solve the bottleneck: research depth → actionable insight.

SAY-65: "NIST Is Grading Your AI's Code"
SAY-66: "Anatomy of Government AI Evaluation Pipeline"

**What to do:**

For each post (SAY-65 + SAY-66):

1. Read the outline / partial draft in Notion (linked below)
2. Map it to "So What" framework:
   - What insight am *I* uniquely positioned to deliver?
   - Who benefits + how do they use it in the next 24 hours?
   - One-sentence thesis?
3. Output for each post:
   - Revised "Your Next Move" (1–2 concrete actions)
   - "Why This Matters to Your Role" (for Board Talking Points)
   - Any research gaps identified

**Output Format:**
Markdown with frontmatter (ready to commit to repo)

**Autonomy Level:** Supervised (show thinking, don't auto-merge)  
**Timeline:** 2 hours per post

References:
- SAY-65: https://linear.app/sayvainc/issue/SAY-65
- SAY-66: https://linear.app/sayvainc/issue/SAY-66
- Vicky Zhao courses: Notion → "Thinking Toolkit"

Labels: #research-distillation #droid-thinking
```

---

## **Template 3: Git Completion (SAY-91 variant)**

```
Title: [DROID] Implement Vercel AI Gateway + use-workflow for whatsonmybill cost control

Description:

### Task: Add cost control layer to whatsonmybill 2-phase Claude API pipeline

**Problem:**
Current Claude API calls (PII redaction → bill analysis) stream for 30–60 sec/session.
Uncontrolled cost exposure.

**Solution:**
Vercel AI SDK (current stable major) + AI Gateway ($5/mo free credit, zero markup).

**Security guardrails (non-negotiable):**
- Never log raw bill content or redacted PII payloads — log token counts + metadata only
- Never commit sample bills, fixtures, or real redaction output to the repo
- API keys via Vercel env vars only; no keys in code, tests, or README examples
- If the fallback path sends data to a second provider (GPT), confirm the data-processing terms match Claude's before routing production traffic

**What to build:**

1. Install Vercel AI SDK — pin to the current stable major at the time of the PR and record the exact version in the PR description
2. Wrap existing Claude API calls in AI Gateway:
   - Route PII redaction phase through gateway
   - Route bill analysis phase through gateway
   - Enable fallback to GPT (don't use, just test)
3. Add cost tracking middleware
4. Deploy to staging on Vercel
5. Test with 10 sample bills (measure token reduction)

**Acceptance Criteria:**
- ✓ AI Gateway routes both phases
- ✓ Cost tracking logs visible in Vercel dashboard
- ✓ Fallback to GPT tested (staging only)
- ✓ README updated with cost-monitoring instructions
- ✓ PR ready for review (not merged)

**Autonomy Level:** Supervised (PR → human review before merge)  
**Repo:** whatsonmybill.com (singhs-kaurs team)  
**Timeline:** 4–6 hours

References:
- Vercel AI SDK: https://sdk.vercel.ai
- SAY-91 context: https://linear.app/sayvainc/issue/SAY-91
- whatsonmybill repo structure: `/app` (Next.js 15+)

Labels: #git-completion #cost-control #droid-build
```

---

## **Template 4: Known-Unknown Matrix Triage (SAY-127 variant)**

```
Title: [DROID] Apply Known-Unknown Matrix to all 10 Linear projects

Description:

### Task: Surface avoidance patterns + distinguish "blocking" from "busy work"

**Framework:**

| Category | Definition | Action |
|----------|-----------|--------|
| **Shared Context** | You + stakeholders both know this | SHIP IT — stop re-analyzing |
| **Insight Sharing** | You know it, others don't | PACKAGE + DELIVER — this is your moat |
| **Research Gap** | Neither you nor stakeholders know | RUN EXPERIMENT (1 week, constrained) |
| **Collective Unknown** | Nobody knows + can't find out | DECIDE + MOVE (gut call) |

**What to do:**

For each of your 10 Linear projects:
1. Sample 3 "blocked" or "todo" issues
2. Classify each using matrix above
3. For "Shared Context" issues: What's the real blocker? (Usually: dignity, attention, unclear success metric)
4. For "Insight Sharing" issues: Where should it be packaged? (Blog? Board doc? Slack?)
5. For "Research Gap" issues: Define a 1-week experiment to close it
6. For "Collective Unknown" issues: Write 1 decision paragraph (gut call)

**Output:**
Spreadsheet (CSV or Notion table):
| Issue ID | Title | Category | Real Blocker / Action | Priority |
|----------|-------|----------|----------------------|----------|
| SAY-122 | Financial admin avoidance... | Shared Context | Add dignity layer (automation) | P1 |

**Autonomy Level:** Autonomous (output for your review)  
**Timeline:** 90 min

Projects to scan:
First call `linear.list_projects` scoped to the Sayvainc team. Apply the matrix to every active project returned by that query — do not hardcode the list, as project membership changes.

Labels: #factory-droid #droid-analyze #workflow-intelligence #avoidance-detection
```

---

## **Template 5: Weekly Collision Sprint (Recurring)**

```
Title: [DROID] Weekly Blip Collision Sprint — QMD cross-domain discovery

Description:

### Recurring Task (Every Sunday, 45 min)

**Part 1: Cross-Domain Collision (20 min)**
- Run 3 QMD queries using concept from Domain A against Domain B
- Domains: SecurityLeader.ai research / whatsonmybill.com strategy / GAISS education
- Flag surprising connections (your blindspots)

Example:
- Query: "OAuth supply chain attacks" (SecurityLeader domain) → search QMD for "payment fraud" (whatsonmybill domain)
- Result: "Hmm, stolen merchant API keys could mirror PII redaction failures"

**Part 2: Avoidance Pattern Check (15 min)**
- Scan all 10 Linear projects for issues with >14-day age + no movement
- Apply Known-Unknown Matrix to each
- Flag "Shared Context" issues (pure avoidance — these need dignity refactoring)

**Part 3: Summary Output (10 min)**
- Top 3 cross-domain insights
- Top 3 avoidance patterns
- 1 recommended action per pattern

**Output Format:**
Markdown summary (ready to paste into Linear comment or Notion)

**Autonomy Level:** Autonomous (you read + decide)  
**Schedule:** Every Sunday, 45 min (can batch if needed)

QMD Collections:
- gdrive-jasgur (2,268 files)
- gdrive-jasgur-library (5,402 files)
- gdrive-personal (1,803 files indexed, 5,188 on disk)
- iCloud (587 files)
- iCloud-consolidated
- notion-thinking-toolkit
- notion-ai-prompt-library
- notion-research-dashboard
- notion-publishing-dashboard

Labels: #workflow-intelligence #recurring #droid-discovery
```

---

## **Template 6: MCP Server Batch Validation (mcp-sentinel-scanner)**

```
Title: [DROID] Validate <N> MCP servers against mcp-sentinel-scanner security rubric

Description:

### Task: Run mcp-sentinel-scanner against a batch of MCP server repos and classify each

**Context:**
mcp-sentinel-scanner orchestrates Semgrep (with custom .semgrep.yml rules for MCP/AI patterns) + TruffleHog + npm audit + mcp-scan. The rubric below is binary, so the Droid does not need architectural judgment — just mechanical execution.

Repo: https://github.com/GeeksikhSecurity/mcp-sentinel-scanner
Wrapper: `scripts/factory-droid-validate.sh` (emits a JSON verdict on stdout)

**MCP repos to validate:**
- <repo-url-1>
- <repo-url-2>
- ...

(Alternative: read one URL per line from `docs/mcp-validation-targets.txt` in the scanner repo.)

**What to do:**

1. Clone mcp-sentinel-scanner if not already present:
   `git clone https://github.com/GeeksikhSecurity/mcp-sentinel-scanner.git`
2. Verify tooling is installed (`semgrep`, `trufflehog` at minimum). Install via `pip install semgrep` / `brew install trufflehog` if missing.
3. For each target repo URL, run:
   `./scripts/factory-droid-validate.sh <repo-url> --name <repo-name>`
4. Capture wrapper stdout (JSON) + exit code (0=APPROVE, 1=FIX, 2=ERROR).

**Rubric (do not invent your own):**
- **APPROVE**: 0 CRITICAL findings AND ≤1 HIGH findings
- **FIX**: anything else — reasons are already populated in `fix_reasons`
- **ERROR**: clone/scan failed — flag for human, do not retry with credentials

**Output:**

Post one markdown table as a Linear comment:

| Repo | Verdict | CRIT | HIGH | MCP rule hits | Action |
|------|---------|------|------|---------------|--------|
| example-mcp | FIX | 0 | 3 | mcp-prompt-leakage, yaml-unsafe-load | Reduce HIGH to ≤1; fix prompt leakage |

Then attach the per-repo wrapper JSON (only for repos in FIX or ERROR state).

**Security guardrails (non-negotiable):**
- Never commit cloned target repos back to the scanner repo
- Never publish verified-secret values from TruffleHog output — redact or reference by file:line only
- If a repo fails to clone (private, deleted, rate-limited), mark as ERROR and continue
- Do not modify `.semgrep.yml` or the rubric in the wrapper to make repos pass

**Acceptance Criteria:**
- ✓ Every repo has a verdict (APPROVE / FIX / ERROR)
- ✓ FIX reasons cite the severity counts and (where present) the MCP-specific rule hits
- ✓ Summary table posted as Linear comment
- ✓ No secret values leaked

**Autonomy Level:** Supervised (human reviews the table; any follow-up PRs go through review)
**Timeline:** ~5 min per repo (scan time dominates)

Labels: #factory-droid #droid-validate #mcp-security
```

---

## **How to Invoke These**

### Option A: Paste into Linear (Recommended)
1. Go to https://linear.app/sayvainc
2. Create new issue
3. Copy-paste template above
4. Add label: `#droid` or `#factory-droid`
5. (Optional) Assign to a team member or Droid

### Option B: Use Factory CLI
```bash
factory run --linear "Apply Known-Unknown Matrix to SAY-127"
# Droid reads the title, queries your Linear context, kicks off task
```

### Option C: Invoke from VS Code
If you have Factory installed in VS Code:
```
/droid:delegate [DROID] SAY-91 — Vercel AI Gateway
```

---

## **Success Metrics (Per Droid Task)**

| Task | "Done" Looks Like | Time | Cost |
|------|------------------|------|------|
| SAY-70 (blog validation) | Checklist complete + approval/fixes | 30 min | Free (bonus) |
| SAY-124 (research distillation) | 2 revised posts ready to draft | 2 hrs | Free (bonus) |
| SAY-91 (Vercel AI Gateway) | PR staged on Vercel + cost tracking logs | 4–6 hrs | Free (bonus) |
| SAY-127 (Known-Unknown Matrix) | Spreadsheet with 30 issues classified | 90 min | Free (bonus) |
| Weekly collision sprint | 3 insights + 3 actions identified | 45 min/week | Free (bonus) |
| Template 6 (MCP batch validation) | Table of APPROVE/FIX verdicts per repo | ~5 min/repo | Free (bonus) |

---

## **Quick Reference: Your Droid Workflow**

```
Linear Issue Created
  ↓
Factory Droid reads issue + clones your repos
  ↓
Droid executes task (autonomy level: you set)
  ↓
Output: PR / analysis / summary
  ↓
You review + feedback
  ↓
Iterate or merge
```

**Cost:** ~$0/month *while Factory bonus credits remain — verify current balance before each large task. Once bonus is exhausted, re-run the cost comparison table against Claude Max and Perplexity.*
**Time to first Droid task:** 5 minutes (copy-paste template above)
**Time to ROI:** After 2–3 tasks (~4 hours), you'll know if Droid is your missing layer
