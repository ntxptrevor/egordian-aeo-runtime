# Handoff: "AEO — the Assignment Estimate Operator" (Claude Artifact)

**Source artifact:** https://claude.ai/code/artifact/6e40e750-0c7b-490f-ab60-89aa5ad35dac?open_in_browser=1&via=user_open&org=2733ff44-246c-4894-84af-023f6a7822b1
**Artifact title:** AEO — Assignment Estimate Operator for eGordian
**Owner:** Trevor Hopkins (private artifact, 1 version, updated ~11 min before inspection)
**Doc metadata (top-right badge):** `BLUEPRINT · v0.1 · 2026-08-07`
**Doc metadata (top-left badge):** `NTXP · Frontier Process Architecture`
**Footer tagline (verbatim):** *"NTXP · Frontier Process Architecture — Determinism Ladder · Evidence spans on every fact · No manifest, no deliverable. Blueprint for review; not yet a production pipeline."*

> ⚠️ **Important caveat on artifact type:** This is **not** a multi-file code artifact. It is a single rendered HTML/design "one-pager" (a product/architecture blueprint pitch, rendered inside Claude's sandboxed `claudeusercontent.com` artifact iframe). There is **no visible source-code panel, no file tree, and no download/export button** anywhere in the UI (checked the title dropdown: only Rename / Duplicate / Share / Version history / Report artifact / Delete artifact — no "view code" or "export" option). The artifact's DOM is cross-origin-sandboxed from the parent `claude.ai` page (confirmed via `SecurityError` on `contentDocument` access, and the accessibility tree treats the iframe as an opaque leaf node), so no raw HTML/CSS/JS source could be extracted programmatically. **All content below was captured by full visual read-through (scrolling + screenshots) of the rendered page — there is no underlying source file to download.** No download action was available or taken; nothing was modified, published, or submitted.

---

## 1. Executive summary / positioning

**Category tag:** "SELF-DRIVING AGENT OPERATOR · EGORDIAN JOC PLATFORM"

**Headline:** "AEO — the Assignment Estimate Operator"

**Tagline:** "An orchestration layer and autonomous operator that takes a JOC consulting assignment from intake to a submitted, defensible *Price Proposal* in eGordian — end to end, on its own — while an estimator reviews only the 5–10% it flags."

**Top-line stats (4 stat cards):**
| Stat | Label |
|---|---|
| 10 | API — eGordian modules wired as the integration spine |
| 3-tier | Determinism ladder governs every stage |
| <2% | Target residual error vs. 5–10% manual fatigue error |
| 5–10% | Of each estimate routed to a human, not 100% |

## 2. The thesis ("Why this wins: variance is engineered out, not prompted out")

> "Competitors won't automate high-stakes estimating because they can't control AI variance. AEO can — because state, math, and pricing are owned by code; the LLM only *perceives* and every perception is evidence-anchored and gated; and a named human owns every judgment. The eGordian Help page is the unlock: it exposes a full **JOC Service Web API**, so AEO reads the assignment and writes the proposal through a real integration — not brittle screen-scraping."

**Three-tier card summary:**
1. **TIER 1 · DETERMINISTIC — "Code owns it"** — Arithmetic, rollups, coefficient math, catalog lookups, SLA clocks, state transitions. *"If a stage can be code, it must be code."* → reproducibility → 100%.
2. **TIER 2 · PERCEPTION — "LLM extracts, code verifies"** — Reading drawings & specs, classifying scope, matching descriptions to catalog lines. Output is a *candidate* — schema-constrained, evidence-anchored, range-checked, consensus-tested. → N-run consensus → flag the 4%.
3. **TIER 3 · JUDGMENT — "Human decides, AI drafts"** — Risk pricing, scope-gap calls, coefficient strategy, anything owner-facing. AEO prepares the decision package with full evidence; the estimator signs, timestamped. → "the audit defense."

## 3. Architecture — "Three layers, cleanly separated"

Section intro: *"Directives say **what** to do, orchestration decides **how** to route each assignment, execution runs deterministic scripts and specialist skills. The operator never mixes the probabilistic and the deterministic in one step."*

| Layer | Description |
|---|---|
| **DIRECTIVE** — "The estimating SOP, as versioned rules" | Acceptance gates, coefficient policy, division-coverage rules, catalog edition, model IDs, prompt hashes — pinned and versioned. "A proposal is only valid alongside its manifest." |
| **ORCHESTRATION** — "The self-driving control loop" | Polls eGordian for new assignments, drives each through the state machine, chooses which specialist skill runs next, fires consensus runs on bid-critical numbers, and queues exceptions. "This is the only layer that 'decides.'" |
| **EXECUTION** — "Deterministic scripts + NTXP specialist skills" | Phase-1 intake, Phase-2 takeoff, UPB crosswalk, RSMeans check, API read/write. Each returns structured, schema-valid output; code — never an LLM — advances state and does the math. |

## 4. The Operator Loop — "Intake → Proven QTO → Crosswalk → Price Proposal → Submit"

Intro: *"Each stage is classified on the determinism ladder and bound to the exact eGordian API module and NTXP skill that executes it. Numbers denote real sequence, not decoration."*

Numbered pipeline stages (each shown as a step card with tier badge + linked API modules/skills):

| # | Stage | Tier | Description | eGordian API modules / skills referenced |
|---|---|---|---|---|
| 0 | **Detect & authenticate** | TIER 1 | Poll for new assignments on a schedule; open an authenticated session; start the SLA clock. | `AccessToken`, `JobRequests`, `TrackingDatesV1` |
| 1 | **Assemble the assignment dossier** | TIER 1 | Pull the job order, scope of work, drawings, specs, photos, notes, and contacts into one provenance-stamped package. | `JobOrdersV1`, `FilesV1`, `PicturesV1`, `NotesV1`, `ContactsV1` |
| 2 | **Build the knowledge base** | TIER 2 | OCR and index every document; extract tables, schedules, rooms, areas, scales — each fact carries a page + span. Bad input (low OCR score, missing scale) is rejected before the model estimates. | skill: `ntxp-estimating-phase-1-intake`; input gate: OCR score |
| 3 | **Quantify takeoff (proven)** | TIER 2 + TIER 1 | Quantify all scope; every quantity traces to sheet + coordinates + method. Bid-critical numbers run **N=5 consensus**; disagreements go to the exception queue with evidence side-by-side. | skill: `ntxp-estimating-phase2`; consensus N=5; proof chain |
| 4 | **Crosswalk scope → CTC catalog** | TIER 1 + TIER 2 | Map each scope item to an eGordian Construction Task Catalog line via the versioned translation memory — compiled once, reused forever. Only *new* items hit the LLM; the rest are a deterministic lookup. **"This seam is the IP."** | `ConstructionTaskCatalogV1`; skill: `upb-crosswalk` |
| 5 | **Assemble the price proposal** | TIER 1 | Quantity × catalog unit price × coefficient → line items → draft proposal. Pure arithmetic, done in code. Dual-book reconciliation (RSMeans as a secondary check) flags mispriced lines. | `PriceProposalsV1` (draft); skill: `rsmeans-estimate-generator` (check) |
| 6 | **Self-check & confidence-tier** | TIER 1 | Range checks, cross-foots, coefficient math, division coverage, catalog validity. Every line gets a confidence tier; only low-confidence and disagreement lines surface for review. | acceptance gates; exception queue |
| 7 | **Human gate** | TIER 3 | The estimator reviews the flagged 5–10% with evidence attached, adjusts judgment lines, and approves. Named human, timestamped — the block on anything reaching a dollar commitment. | named approver; blast-radius stop |
| 8 | **Submit & log** | TIER 1 | Write the final proposal through the API, post an audit note, stamp the milestone date, and emit the run manifest (versions + gates + evidence). "No manifest, no deliverable." | `PriceProposalsV1` (submit); `NotesV1`; `TrackingDatesV1` |

## 5. Variance control — "The control points that make it safer than a human"

Intro: *"Human takeoffs run 5–10% fatigue error. AEO places a measured control on each failure mode until residual risk is provably below that baseline."*

| Control | Badge | Description |
|---|---|---|
| **Input rejection** | GATE | Scale verification, OCR quality scoring, legend extraction — bad input is rejected before the model ever estimates from it. |
| **Consensus protocol** | N=5 | Bid-critical quantities run five times. Agree → auto-accept. Majority → accept + flag. Disagree → human queue with evidence spans. |
| **Dual-book reconciliation** | ×2 | CTC catalog priced, RSMeans checked. Divergence beyond tolerance is a built-in error detector, not a rounding note. |
| **Version manifest** | PIN | Model ID, prompt hash, schema version, catalog edition, coefficient policy — pinned per run. "Reproducible or it doesn't ship." |
| **Golden-set harness** | ≥98% | Real NTXP projects with verified ground truth. Gate deployment on field agreement across runs; rerun on any model or catalog change. |
| **Full audit trail** | LOG | Inputs, versions, evidence, approvals — the artifact that wins the dispute later. Overhead only until you need it. |

## 6. Integration surface — "eGordian JOC Service Web API — the spine"

Intro: *"Every module the Help page exposes, mapped to its role in the operator. Read for intake, write for the proposal, the rest for context and audit."*

**Full API module table (10 modules — matches the "10 API" stat):**

| API Module | Role in AEO | Direction |
|---|---|---|
| `AccessToken` | Authenticated session for every operator run | auth |
| `JobRequests` | New-assignment trigger; request counting & creation | read |
| `JobOrdersV1` | The assignment + scope-of-work — primary intake object | read / write |
| `FilesV1` | Drawings, specs, and linked documents | read |
| `PicturesV1` | Site photos attached to the job order | read |
| `ConstructionTaskCatalogV1` | The CTC / Gordian UPB — catalog, categories, task search | read |
| `PriceProposalsV1` | The estimate itself — draft and submit the priced proposal | read / write |
| `NotesV1` | Audit notes and operator status, with visibility controls | write |
| `ContactsV1` | Owner & job-order roles for routing and approvals | read |
| `TrackingDatesV1` | Milestone dates — the SLA clock | read / write |
| `OwnersV1` · `UsersV1` | Owner catalog scoping, permissions, requestor validation | read |

(Note: the table lists 11 named entries but the last row bundles two modules — `OwnersV1` and `UsersV1` — together, consistent with the "10 API modules" headline stat.)

## 7. Build sequence — "Four phases to a self-driving operator"

Intro: *"Each phase ships something usable and gated by its own harness before the next begins. We can start Phase 1 immediately — the API is already documented."*

| Phase | Title | Contents | Duration |
|---|---|---|---|
| **Phase 1** | API connector + read spine | AccessToken auth + client; Pull job order, files, catalog; Provenance-stamped dossier; Golden set from real jobs | ≈ week 1 |
| **Phase 2** | Estimate engine (assisted) | Wire Phase-1/2 skills; Crosswalk → CTC catalog; Draft proposals, human-reviewed; Variance harness live | ≈ weeks 2–3 |
| **Phase 3** | Write-back + gates | PriceProposalsV1 submit; Confidence-tiered review UI; Consensus + reconciliation; Audit trail + manifest | ≈ weeks 4–5 |
| **Phase 4** | Self-driving loop | Scheduled polling; State machine + SLA clocks; Auto-route by confidence; Compile to a permanent skill | ≈ weeks 6+ |

## 8. Closing call-to-action / open decision block

Highlighted callout box (amber/gold), verbatim:

> **"The one decision that gates the build"**
> "AEO's write path needs **API credentials and the write scopes** for `PriceProposalsV1` and `JobOrdersV1` on your eGordian owner account. Confirm credential access and whether we start in **assisted mode** (drafts only, human submits) or go straight to **gated auto-submit**, and I'll stand up the Phase 1 connector."

## 9. What was NOT accessible / not present

- **No source code files** (no `.py`, `.js`, `.json`, `.yaml`, prompt files, etc.) are exposed anywhere in the artifact UI — this is a rendered marketing/architecture one-pager, not a code bundle.
- **No "view code" / split-view / raw-source toggle** exists in this artifact's UI (verified via the title-bar dropdown menu and toolbar — only Rename, Duplicate, Share, Version history (1 version), Report artifact, Delete artifact, plus the standard You/Share/Full-screen icons were present).
- **No export/download button** was found anywhere on the page or in menus, so **no file was downloaded** and none exists to download.
- **Underlying HTML/CSS/JS of the rendered page** could not be extracted: the artifact renders inside a cross-origin sandboxed iframe (`https://6e40e750-0c7b-490f-ab60-89aa5ad35dac.frame.claudeusercontent.com/...`) that throws `SecurityError` on any `contentDocument`/`contentWindow` access from the parent `claude.ai` frame, and the accessibility tree exposes it only as an opaque `Iframe "User-generated artifact content"` leaf node with no children. Attempting to open the iframe's own `src` URL directly in a new tab simply redirected back into the same `claude.ai` nested-frame wrapper, not a same-origin raw view.
- **No literal prompts, model configuration, JSON schemas, or code snippets are shown** in the visible content — the document describes *that* prompt hashes, schema versions, model IDs, and coefficient policy are pinned in a "version manifest," but does not display their actual values/contents anywhere on the page.
- **Version history** shows "1 version" only (no prior revisions to diff against).

## 10. Integration notes for the eGordian Proposal Generator (stateless MCP service)

Distilled implications for wiring this into an existing stateless MCP service, based only on what's stated in the artifact (no external assumptions added):

- **API surface to mirror/wrap as MCP tools:** the 10 modules in §6 above — at minimum `AccessToken` (auth), `JobRequests`/`JobOrdersV1` (intake), `FilesV1`/`PicturesV1` (evidence), `ConstructionTaskCatalogV1` (pricing catalog), `PriceProposalsV1` (draft + submit — the only write-critical path), `NotesV1`/`TrackingDatesV1` (audit/SLA), `ContactsV1`/`OwnersV1`/`UsersV1` (routing/permissions).
- **Determinism ladder** (Tier 1/2/3) is the core design constraint the artifact argues for: a stateless MCP service integrating this should keep arithmetic/rollup/catalog-lookup logic (Tier 1) in deterministic code paths, keep LLM calls confined to extraction/classification with schema validation + consensus voting (Tier 2), and always route final pricing/scope-gap judgment to a named human approver before any write to `PriceProposalsV1` (Tier 3) — the artifact frames this human gate as non-negotiable ("the block on anything reaching a dollar commitment").
- **Write path is explicitly gated**: the artifact's own closing statement says the write path (`PriceProposalsV1`, `JobOrdersV1`) requires confirmed API credentials/write scopes and an explicit choice between "assisted mode" (drafts only, human submits) vs. "gated auto-submit" — this decision has **not** been made in the document itself; it's posed as an open question to the reader.
- **Audit/versioning requirement**: every run should emit a "run manifest" (model ID, prompt hash, schema version, catalog edition, coefficient policy) — the artifact insists "no manifest, no deliverable," which implies the MCP service should persist/version these run artifacts even though the service itself is stateless (state would need to live in eGordian's own `NotesV1`/`TrackingDatesV1` or an external store, since this MCP service holds no state).
- **This is a v0.1 blueprint, not a shipped pipeline** — footer explicitly disclaims: "Blueprint for review; not yet a production pipeline." Treat all of the above as a proposed design to integrate against, not an already-built component.

---

### Session actions taken
- Opened the artifact URL in the existing authenticated session (already loaded per task setup).
- Inspected DOM, accessibility tree, iframe structure, and title-bar menu to look for source/export options — none found.
- Attempted cross-origin content access (`contentDocument`), CDP frame-tree enumeration, and direct navigation to the iframe's `src` — all blocked or redirected back to the same sandboxed wrapper.
- Fully read the artifact via mouse-wheel scroll + screenshots from top to bottom (7 capture points, confirmed end-of-document by a final no-op scroll).
- No modification, publish, submit, or send action was performed. No file existed to download, so none was downloaded.
