# Architecture

## Two-store data spine

**Catalogue (immutable, licensed).** The `catalogue.sqlite` contains exact task
rows extracted from one authorized PDF, hierarchy, external-content FTS5 index,
parse exceptions, and a sealed build manifest. It is created deterministically,
sealed with SHA-256 hashes, chmod read-only where supported, and opened by
runtime code as `mode=ro&immutable=1`. The catalogue stores only values actually
present in the source; null means absent/unparseable, never zero or invented.

**Overlay (writable, project partitioned).** The `overlay.sqlite` contains
user-bound handles, projects, policy snapshots, crosswalk edges, retrieval cache,
review queue, append-only learning events, reconciliation runs, and decisions.
It never edits catalogue rows. Project-owned queries require `project_id`; missing
or unauthorized scope fails closed before FTS, semantic retrieval, reranking, or
reasoning. Overlay rows carry an actor, event time, and provenance.

Both stores are local/private by default. The API does not serve raw catalogue
data to unauthenticated callers.

## Deterministic ingestion

The builder pins `pdftotext -layout`, PDF SHA-256, extractor version/command,
parser version, page number, page-local row ordinal, raw line SHA-256, and build
timestamp. It recognizes:

```text
01 56 26 00-0011  LF  Description ................................ 12.12 [demolition]
```

The actually observed columns are `MINOR CSI`, `UOM`, `DESCRIPTION`, `TOTAL DIRECT
UNIT COST`, and `DEMOLITION UNIT COST`. It creates task rows, plus attached
priced modifiers such as “For … Add/Deduct”; headings/notes are preserved as
evidence context. When a page's pattern is ambiguous, an exception is stored and
the parser does not infer a price or UOM.

## Retrieval cascade

1. **T0**: per-project, version-bound cached validated outcome.
2. **T1**: exact code / normalized code prefix / authorized crosswalk join.
3. **T2**: SQLite FTS5 BM25 lexical query, entirely offline.
4. **T3 (optional)**: semantic adapter returns IDs from the T1/T2 candidate set
   only; deterministic reciprocal-rank fusion \(1/(k+r)\), default \(k=60\).
5. **T4 (optional)**: a reasoning adapter receives only retrieved evidence and
   may choose one candidate or `ABSTAIN`; any other code is rejected.
6. **T5**: named human review and decision.

An optional reranker may only re-order the bounded candidate list; exact T0/T1
matches stay ahead of it. Default mode needs no model, embedding, or download.

## Crosswalk and federation

The overlay's `crosswalk_edge` supports source/target system, code or opaque
identifier, aliases, source/target edition, cardinality, unit, attributes,
authority, project scope, and provenance. Supported identifiers are
`CSI_MASTERFORMAT`, `GORDIAN_CTC`, and `RSMEANS_OPAQUE`. RSMeans integration
returns references/opaque IDs only: it does not merge or expose RSMeans data.
All crosswalk creation is a proposal until named human approval.

## Reconciliation

Code uses known target total and proposal-line costs actually available to compute
division deficits, residual, variance bands, companion gaps, decomposition, and
exception queue. It selects only positive underrepresented divisions, ordered by
the largest configured absolute/percentage deficit, preserves target total, flags
round/suspicious quantities, and never adds cost or scope itself. AI/perception
adapters can draft evidence-backed assumptions, but a named human must approve
additions and the final reconciliation.

The overlay additionally records append-only human-observed external lines,
verification events, big notes, change-order events, initial-versus-final proposal
deltas, and inert improvement candidates/decisions. These records never mutate
the immutable catalogue. Big notes and lessons are retrieved before line proposal.

## Stateless service/MCP

There is no server-side protocol session. `create_handle` creates a random opaque
handle bound to authenticated user ID, projects, expiry, and nonce hash in the
overlay. Every call validates that binding. Runtime supports injectable
`auth_hook` and `rate_limit_hook`; FastAPI is optional, binding `127.0.0.1` by
default. The MCP adapter is a thin schema-shaped wrapper over the service.

## Deployment boundary

Use SQLite for a single-host/private deployment. Migrate only after a deliberate
security and capacity design when multi-host access, materially sustained traffic,
or relational ANN joins require PostgreSQL. See the cited criteria in
`docs/research-sources.md`.
