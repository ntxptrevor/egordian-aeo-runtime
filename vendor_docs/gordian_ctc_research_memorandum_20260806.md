# Research Memorandum — Private, Licensed Gordian Construction Task Catalog (CTC) Intelligence System

**Prepared for:** NTXP LLC
**Date:** August 6, 2026
**Scope:** Authoritative best practices and public documentation for building a private, licensed CTC intelligence system: immutable line-item ingestion, stateless MCP/API query service, hybrid retrieval, CSI crosswalks, budget-to-line-item reconciliation, provenance, human-approved learning, federated RSMeans interfaces, and optional browser-assisted eGordian entry.

**Grounding rule applied:** every factual statement below is drawn from a page fetched during this research session and carries an inline link to that exact URL. Items that could not be confirmed from a fetched page are marked **n.a.**

**Content rule applied:** no proprietary CTC line items, prices, descriptions, or productivity data were sought or reproduced. Only publicly posted structural and process documentation is cited.

---

## Field 1 — MCP server architecture and security for stateless tools

### 1.1 Protocol version and lifecycle

Model Context Protocol uses `YYYY-MM-DD` date-based version strings, and the current specification revision is **2026-07-28**; the version is carried both in `_meta.io.modelcontextprotocol/protocolVersion` and in the `MCP-Protocol-Version` HTTP header, with an `UnsupportedProtocolVersionError` defined for unsupported requests and a deprecation window of at least 12 months (90 days for expedited security-driven removals) ([MCP versioning spec](https://modelcontextprotocol.io/specification/versioning)).

### 1.2 MCP is now formally stateless — this is decisive for the CTC service design

The 2026-07-28 security guidance states plainly that **"MCP is stateless and has no protocol-level sessions,"** and that servers needing state across requests must mint an **explicit handle** (e.g., a workflow ID) returned in a tool result and passed back as an ordinary tool argument ([MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)). The same page defines **state handle hijacking** and its requirement levels: servers implementing authorization **MUST** verify all inbound requests; servers **MUST NOT** treat possession of a state handle as authentication; servers **SHOULD** use secure, non-deterministic handles from a secure RNG, avoid predictable/sequential identifiers, expire handles, and **SHOULD** bind handles server-side to the authenticated user (e.g., keyed `<user_id>:<handle>` where the user ID derives from the verified token, not client input), rejecting handles presented by any other principal ([MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).

The tools page adds non-normative design guidance in the same direction: "MCP has no protocol-level session, so a server cannot rely on implicit per-connection state to relate one tool call to the next"; for authenticated servers "a handle is a name, not a capability" and the server should validate the caller's authorization against the handle on every call; handles should be opaque (structure "invite[s] parsing or guessing"), have bounded lifetimes (UUIDv4 given as an entropy example for unauthenticated servers), state their retention policy in the creation tool's description, and return a tool execution error when expired or unknown ([MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

Tool visibility is also per-request rather than per-connection: the `tools/list` result **MUST NOT** vary per-connection or as a side effect of other requests on the connection, but **MAY** vary according to the authorization presented on the request — "since credentials are per-request input, not connection state" ([MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

### 1.3 Transport hardening (Streamable HTTP)

Under 2026-07-28 Streamable HTTP: servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS rebinding and **MUST** respond `403 Forbidden` when a present `Origin` is invalid; servers running locally **SHOULD** bind only to `127.0.0.1` rather than `0.0.0.0`; servers **SHOULD** implement proper authentication for all connections; every POST **MUST** include `MCP-Protocol-Version` matching the `_meta` value, with `400 Bad Request` + `HeaderMismatch` on mismatch and `400` + `UnsupportedProtocolVersionError` for unsupported versions; the revision **removed protocol-level sessions and the GET stream**, so servers should return `405 Method Not Allowed` for GET/DELETE, ignore `Mcp-Session-Id` (never mint or echo session IDs), and ignore `Last-Event-ID` ([MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)). The 2026-07-28 transports overview frames these as binding-level rules while protocol semantics stay identical across bindings ([MCP 2026-07-28 transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)).

The prior revision's transport rules are consistent: stdio and Streamable HTTP, `Origin` validation with 403, localhost binding, authenticate all connections, single MCP endpoint ([MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)).

### 1.4 Authorization

Servers **MUST NOT** accept tokens that were not explicitly issued for them (token passthrough prohibited; audience validation per RFC 9068) ([MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)). The 2025-11-25 authorization spec, still the detailed reference, builds on OAuth 2.1 (draft-ietf-oauth-v2-1-13): the MCP server acts as an OAuth **resource server**, **MUST** implement RFC 9728 Protected Resource Metadata advertising its `authorization_servers`, clients **MUST** use PRM discovery, `WWW-Authenticate` carries `resource_metadata` and `scope`, RFC 8414/OIDC discovery applies, RFC 8707 resource indicators are used to bind tokens to the intended resource, and RFC 7591 dynamic client registration **MAY** be supported ([MCP 2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). Earlier-revision guidance that MCP servers **MUST** verify all inbound requests, **MUST NOT** use sessions for authentication, and **SHOULD** bind session IDs to user identity derived from the token remains citable for legacy compatibility ([MCP 2025-11-25 security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)).

**Confused deputy:** proxy servers combining a static third-party client ID, dynamic client registration, and third-party consent cookies can leak authorization codes; mitigation **MUST** include a per-user registry of approved `client_id` values checked before initiating the third-party flow, an MCP-level consent UI naming the client, listing scopes and the registered `redirect_uri`, CSRF protection (`state` or CSRF tokens), and anti-clickjacking via `frame-ancestors` CSP or `X-Frame-Options: DENY` ([MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).

### 1.5 Independent security authority (2026 recency anchor)

NSA, with CMU SEI, published **"Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation," May 2026, Ver. 1.0 (U/OO/6030316-26 | PP-26-1834)**, which finds MCP underspecified in key respects: identity and session association are not defined by the protocol, many implementations omit authentication, and no RBAC exchange occurs at instantiation. It recommends defining explicit trust boundaries and zones, treating dynamic tool discovery cautiously, preferring a **local MCP server instance when handling private data**, and guarding against arbitrary code execution classes CWE-77/78/94/95 ([NSA CSI on MCP security](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)).

The **OWASP Top 10 for LLM Applications 2025** (v2025, published Nov 18, 2024, CC BY-SA 4.0) enumerates LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, and LLM10 Unbounded Consumption, with mitigations including least privilege, **human approval for high-risk actions**, immutable retrieval logs, and keeping credentials out of system prompts ([OWASP Top 10 for LLMs v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)).

### 1.6 Human-in-the-loop at the protocol layer

Tools are model-controlled, and "There SHOULD always be a human in the loop with the ability to deny tool invocations"; clients SHOULD prompt for confirmation, display tool inputs before invocation, and **MUST consider tool annotations untrusted** unless the server is trusted ([MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)). The 2026-07-28 tools page restates server duties as MUST-level: validate all tool inputs, implement proper access controls, rate limit tool invocations, and sanitize tool outputs; clients SHOULD show inputs to the user "to avoid malicious or accidental data exfiltration," validate results before passing them to the LLM, prompt for confirmation on sensitive operations, implement timeouts, and **log tool usage for audit purposes** ([MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

---

## Field 2 — Hybrid retrieval and reranking for code-dense technical catalogs

### 2.1 Fusion

Reciprocal Rank Fusion assigns each document `1/(rank + k)` with a small constant `k` (Azure uses **60**) and sums across parallel rankings; because each fused query contributes at most about `1/k`, hybrid scores are bounded by the number of queries fused, whereas BM25 scores are unbounded and vector cosine similarity falls in roughly 0.333–1.0 ([Azure AI Search hybrid ranking](https://learn.microsoft.com/en-us/azure/search/hybrid-search-ranking)). This matters for a CTC service: raw BM25 and vector scores are not comparable, so fusion (not score addition) is the correct combiner.

### 2.2 Reranking

Azure's semantic ranker is a secondary (L2) rerank applied over results already ranked by BM25 or RRF, and only the **top 50** results proceed to semantic ranking; it also produces captions and answers and supports query rewriting. The page does not describe the ranker as a cross-encoder — that characterization is **n.a.** from this source ([Azure semantic ranking](https://learn.microsoft.com/en-us/azure/search/semantic-search-overview)).

### 2.3 Lexical engines suited to code-dense text

**SQLite FTS5** supports `MATCH` queries, a hidden `rank` column, the `bm25()` auxiliary function (lower values = better match), `highlight()` and `snippet()` for evidence extraction, prefix, phrase, `NEAR`, column filters, initial-token `^`, boolean AND/OR/NOT, prefix indexes, and external-content or contentless tables ([SQLite FTS5](https://www.sqlite.org/fts5.html)). External-content/contentless configurations are directly relevant to a licensed catalog where the index must not duplicate proprietary text more than necessary.

**PostgreSQL full text search** provides `to_tsvector`, stop-word handling, and `setweight` labels A/B/C/D so structured fields (code, title, unit, division) can be weighted differently during ranking ([PostgreSQL text search controls](https://www.postgresql.org/docs/current/textsearch-controls.html)).

For identifier-like strings — MasterFormat codes, CTC task numbers, modifier suffixes — **pg_trgm** supplies `similarity()`, `word_similarity()`, and `strict_word_similarity()`, a default similarity threshold of **0.3** (`pg_trgm.similarity_threshold`), and GIN/GiST operator classes that accelerate `LIKE`/`ILIKE`, regex, and equality searches ([PostgreSQL pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)). The same documentation page carries a 2026 recency marker, noting "July 16, 2026: PostgreSQL 19 Beta 2 Released!" ([PostgreSQL pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)).

OpenSearch hybrid-search documentation could not be read (the page returned a redirect stub), so OpenSearch normalization-processor specifics are **n.a.** ([OpenSearch hybrid search](https://opensearch.org/docs/latest/search-plugins/hybrid-search/)).

---

## Field 3 — SQLite / PostgreSQL / pgvector scaling and migration criteria

### 3.1 When SQLite is the right answer

SQLite's own guidance is that "SQLite does not compete with client/server databases. SQLite competes with fopen()," and it is well suited to low- to medium-traffic websites — the documentation's conservative figure is generally **fewer than 100,000 hits/day**, with a note that the demonstrated capacity is roughly ten times higher ([SQLite: appropriate uses](https://sqlite.org/whentouse.html)).

Structural limits are far above a single catalog's needs: default max string/BLOB length 1,000,000,000 bytes (implementation max 2,147,483,645), default max columns 2,000 (max 32,767), default max attached databases 10 (max 125), max page count 4,294,967,294 (the default since 3.45.0 on 2024-01-15), page sizes 512–65,536 bytes, and a maximum database size of about **281 TB** ([SQLite limits](https://www.sqlite.org/limits.html)).

**WAL mode** lets readers and writers proceed concurrently without blocking each other, but requires all processes to be on the same host — it does not work over network filesystems — fixes the page size once the WAL is created, and costs roughly 1–2% on read-mostly workloads; the historical large-transaction caveat was resolved in 3.11.0 ([SQLite WAL](https://www.sqlite.org/wal.html)).

Recency: the current release is **3.53.4 (2026-07-24)**; 3.53.0 (2026-04-09) fixed a WAL-reset corruption bug and added self-healing indexes, and 3.52.0 was withdrawn ([SQLite changelog](https://www.sqlite.org/changes.html)). The WAL-corruption fix is a concrete argument for pinning ≥ 3.53.0 in any immutable-catalog deployment.

### 3.2 When to move to PostgreSQL + pgvector

**pgvector 0.8.2** (version bump Feb 25, 2026; README updated May 30, 2026) requires PostgreSQL 13+ and performs exact nearest-neighbor search by default. HNSW gives better speed-recall tradeoffs than IVFFlat with slower builds, more memory, and no training step; defaults are `m = 16`, `ef_construction = 64`, and `hnsw.ef_search = 40`, with iterative scans configurable via `hnsw.iterative_scan` and `hnsw.max_scan_tuples` (default 20,000). Type limits allow `vector`/`halfvec` up to 16,000 dimensions and `sparsevec` up to 16,000 nonzeros, but **indexed** limits are 2,000 dims for `vector`, 4,000 for `halfvec`, 64,000 for `bit`, and 1,000 nonzeros for `sparsevec`; the payoff versus a standalone vector store is ACID transactions, point-in-time recovery, and ordinary SQL JOINs against relational catalog tables ([pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md), [pgvector repository](https://github.com/pgvector/pgvector)). The GitHub releases page was empty when fetched, so a formal release-date listing is **n.a.** ([pgvector releases](https://github.com/pgvector/pgvector/releases)).

PostgreSQL ships annual major releases with minor releases at least every three months and a **five-year support window**; currently supported majors are 18 (18.4; 18 first released Sept 25, 2025, EOL Nov 14, 2030), 17, 16, 15, and 14 (EOL Nov 12, 2026), while 13 reached EOL on Nov 13, 2025 ([PostgreSQL versioning policy](https://www.postgresql.org/support/versioning/)). Targeting PostgreSQL 17 or 18 avoids a forced upgrade inside the next twelve months.

**Migration triggers implied by the fetched sources:** the need for network-filesystem or multi-host access (excluded by [WAL](https://www.sqlite.org/wal.html)), sustained request volume above the SQLite guidance band ([appropriate uses](https://sqlite.org/whentouse.html)), the need for indexed vector search with iterative scans and relational joins in one transaction ([pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md)), and the need for weighted lexical ranking plus trigram identifier matching in the same engine ([PostgreSQL text search controls](https://www.postgresql.org/docs/current/textsearch-controls.html), [pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)).

---

## Field 4 — Provenance, temporal versioning, append-only audit, and human-in-the-loop learning

### 4.1 Provenance vocabulary

W3C **PROV-O** (W3C Recommendation, 30 April 2013) supplies the three core classes Entity, Activity, and Agent, and the properties needed to model a catalog-derived estimate line: `wasDerivedFrom`, `wasGeneratedBy`, `wasAttributedTo`, `used`, `wasRevisionOf`, `specializationOf`, `hadPrimarySource`, `wasQuotedFrom`, `actedOnBehalfOf`, `startedAtTime`/`endedAtTime`, plus `Bundle` and `SoftwareAgent` ([W3C PROV-O](https://www.w3.org/TR/prov-o/)). `hadPrimarySource` and `wasQuotedFrom` map cleanly onto "this quantity came from page N of the owner-issued scope" without copying licensed text.

### 4.2 Temporal versioning

PostgreSQL range and multirange types (`tstzrange`, `daterange`) model catalog validity periods with inclusive/exclusive bounds and support containment (`@>`) and overlap (`&&`) operators, with exclusion constraints available to prevent overlapping validity windows ([PostgreSQL range types](https://www.postgresql.org/docs/current/rangetypes.html)). This is the mechanism for "which CTC edition was in force on the job order date."

### 4.3 Append-only audit and log integrity

NIST SP 800-92, *Guide to Computer Security Log Management* (Karen Kent and Murugiah Souppaya, **September 2006**), states that logs need protection from confidentiality and integrity breaches; improperly secured logs are susceptible to intentional or unintentional alteration or destruction, which can let malicious activity go unnoticed or allow evidence manipulation. It directs that log management infrastructures preserve integrity from accidental or intentional modification or deletion, that infrastructure functions not alter the original logs, and that preservation of original logs be addressed in policy. It defines **log-file integrity checking** as calculating a message digest for each file and storing it securely so changes to archived logs are detected — a single changed bit yields a different digest — with original digests protected by FIPS-approved encryption, read-only media, or other suitable means; it identifies SHA as FIPS-approved and MD5 as not, and recommends SHA-256 where supported. For long-term storage it directs administrators to verify integrity of transferred logs via message digests ([NIST SP 800-92](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf)).

NIST SP 800-53 Revision 5 (**September 2020**, includes updates as of 12-10-2020; DOI 10.6028/NIST.SP.800-53r5) is mandatory for federal information systems under OMB Circular A-130 and FISMA, and other organizations "are encouraged to consider using these guidelines" ([NIST SP 800-53r5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)). The relevant control identifiers and enhancements are confirmed from the Rev 5.1 OSCAL-derived listing — **AU-3** Content of Audit Records; **AU-9** Protection of Audit Information with enhancements AU-9(1) Hardware Write-once Media, AU-9(2) Store on Separate Physical Systems or Components, AU-9(3) Cryptographic Protection, AU-9(4) Access by Subset of Privileged Users, AU-9(5) Dual Authorization, AU-9(6) Read-only Access, AU-9(7) Store on Component with Different Operating System; **AU-10** Non-repudiation with AU-10(1) Association of Identities, AU-10(2) Validate Binding of Information Producer Identity, AU-10(3) Chain of Custody, AU-10(4) Validate Binding of Information Reviewer Identity, AU-10(5) Digital Signatures; **AU-11** Audit Record Retention; and **SI-7** Software, Firmware, and Information Integrity with SI-7(1) Integrity Checks, SI-7(6) Cryptographic Protection, and SI-7(15) Code Authentication among its enhancements ([NIST SP 800-53 Rev 5.1 OSCAL-derived PDF](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)). The **verbatim control statement text** for AU-3, AU-9, AU-9(3), AU-10, AU-11, and SI-7 was not retrievable from the fetched PDFs — **n.a.**; only identifiers, titles, enhancement names, and page locations are confirmed ([NIST SP 800-53 Rev 5.1 OSCAL-derived PDF](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)).

### 4.4 Human-in-the-loop learning safeguards

NIST's AI RMF page confirms AI RMF 1.0 was released **Jan 26, 2023** as a voluntary framework, that the Generative AI Profile **NIST AI 600-1** followed on **July 26, 2024**, that a **concept note for an AI RMF Profile on Trustworthy AI in Critical Infrastructure was posted April 7, 2026**, and that AI RMF 1.0 "is being revised" ([NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)).

NIST AI 600-1 (July 2024; approved by the NIST Editorial Review Board 07-25-2024) states that use of GAI systems may warrant additional human review, tracking and documentation, and greater management oversight, and that GAI "may call for different levels of oversight from AI actors or different human-AI configurations in order to manage risks effectively." Its listed governance tools include auditing and assessment, **data provenance**, impact assessments, incident response, monitoring, risk-based controls, and risk mapping/measurement. It defines the "Human-AI Configuration" risk as arrangements that can cause anthropomorphizing, algorithmic aversion, **automation bias** ("excessive deference to automated systems"), over-reliance, or emotional entanglement, and notes automation bias can exacerbate confabulation, bias, and homogenization. Action **GV-1.6-003** directs that GAI system inventory entries include **data provenance information** ([NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)).

Protocol-level HITL requirements reinforce this: a human should always be able to deny tool invocations, tool annotations are untrusted, and clients should log tool usage for audit ([MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)). OWASP adds explicit human approval for high-risk actions and immutable retrieval logs ([OWASP Top 10 for LLMs v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)).

### 4.5 Estimate documentation standard to model provenance against

GAO's *Cost Estimating and Assessment Guide* (**GAO-20-195G**, *Best Practices for Developing and Managing Program Costs*; original Cost Guide published 2009; the fetched document does not state the GAO-20-195G publication date — **n.a.**) defines a reliable estimate as **comprehensive, well documented, accurate, and credible**. A **well-documented** estimate "can easily be repeated or updated," "can be traced to original sources through auditing," and thoroughly identifies the primary methods, calculations, results, rationales or assumptions, and **the sources of the data used to generate each cost element's estimate**; it must describe how the estimate was developed so a cost analyst unfamiliar with the program "could understand what was done" and "replicate it," and must show evidence that management reviewed and accepted the estimate. A **comprehensive** estimate is structured so cost elements are neither omitted nor double-counted and documents all cost-influencing ground rules and assumptions; an **accurate** estimate has validated mathematical formulas, databases, and inputs, is updated regularly, and documents, explains, and reviews variances between estimated and actual costs ([GAO-20-195G](https://www.gao.gov/assets/gao-20-195g.pdf)). This is the external benchmark the system's provenance schema should satisfy line by line.

---

## Field 5 — Safe web/browser automation for authenticated estimating systems

### 5.1 The controlling constraint is contractual, not technical

Gordian's software terms of use (effective 12/15/2023) expressly prohibit use of "any robot, spider, site search/retrieval application, or other manual or automatic device or process to retrieve, index, 'data mine,' or reproduce or circumvent the navigational structure or presentation of the Site," and further prohibit circumventing security features, probing or scanning, reverse engineering, and reformatting, mirroring, or framing. Content restrictions bar selling, transferring, assigning, licensing, sublicensing, modifying, reproducing, displaying, making derivative versions of, or distributing the Content, and the terms include RESTRICTED RIGHTS legends citing 48 CFR 52.227-19 and 252.227-7013 ([Gordian Software terms of use](https://www.gordiansoftware.com/terms-of-use)).

**Design consequence:** any browser assistance toward eGordian must be treated as *human-operated, human-supervised data entry assistance under the contractor's own valid credentials* — not automated retrieval, indexing, mining, or extraction of eGordian content. Bulk pulls of catalog content through the UI are outside what these terms permit. NTXP should obtain written authorization from Gordian before deploying anything beyond assisted keystroke entry, and should confirm the specific terms attached to its own contract vehicle, which may differ from the public site terms — **n.a.** as to NTXP's specific contract language, which was not available in this research.

### 5.2 Credential-material handling if assisted entry proceeds

Playwright's authentication guidance states that `storageState` files (conventionally under `playwright/.auth`) **must be gitignored** because they "may contain sensitive cookies and headers" that "could be used to impersonate the user," should be deleted when expired, should be separated per role, and that `testProject.outputDir` contents are cleaned automatically before each run ([Playwright authentication](https://playwright.dev/docs/auth)).

RFC 9309, the Robots Exclusion Protocol (Standards Track, September 2022), defines crawler rules, product tokens, and caching/error handling, and states explicitly that **"These rules are not a form of access authorization"** ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)). In other words, absence of a robots.txt prohibition provides no defense against the contractual prohibitions above.

### 5.3 Agent-layer risk controls

Browser automation driven by an LLM sits squarely in OWASP's LLM06 Excessive Agency and LLM01 Prompt Injection categories, whose mitigations include least privilege and human approval for high-risk actions ([OWASP Top 10 for LLMs v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)). NSA's guidance to prefer a **local MCP server instance** where private data is handled applies directly to an assistant holding estimating credentials ([NSA CSI on MCP security](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)).

---

## Field 6 — Gordian / eGordian public user guides and training references

All items below are publicly posted by Gordian or by public agencies. They document *process and screen structure*, not catalog content.

| Document | Publisher / date | What it establishes | URL |
|---|---|---|---|
| **Proposal Review in eGordian** (PDF, `/uploads/2020/10/` path; no stated version) | Gordian | Proposal Review Setup tab and Price Proposal Details tab; line items added during review display "A" in the Type column and default to quantity 0; Approve / Remove Approval control | [gordian.com](https://www.gordian.com/uploads/2020/10/6-Proposal-Review-in-eGordian.pdf) |
| **eGordian Release Notes** (undated; no version stated — **n.a.**) | Gordian (static.egordian.com) | Screen inventory: login, main screen, tab structure, Location detail, Job Order list sizes, new job order and project wizards, Estimate & Proposal details with nested item modifiers, Search & Sort Order → Search tab, Tagging, and Task Catalog view | [static.egordian.com](https://static.egordian.com/Release%20Notes/ReleaseNotes.htm) |
| **Job Order Contracting for Contractors** (eBook, `/uploads/2023/03/`) | Gordian | Five-step process: Joint Scope Meeting → Detailed Scope of Work → Price Proposal → Price Proposal Review → Job Order Issued; "The Construction Task Catalog is the source for all pricing, proposal development and review" | [gordian.com](https://www.gordian.com/uploads/2023/03/JOC-for-Contractors-eBook.pdf) |
| **Using The Construction Task Catalog® – Owner** (August 2023; © 2023 The Gordian Group, Inc.) | DASNY (NY State Dormitory Authority) | Task-selection rules: select the most practical and economical tasks; **"Assembly tasks take precedence over individual component tasks"**; unit prices are complete and in-place; or-equal approval rules; trademark list including eGordian, ezIQC, Construction Task Catalog; explicit CTC license clause (quoted in Field 8) | [dasny.org](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf) |
| **Using The Construction Task Catalog® – Upstate** (© 2024) | DASNY | Later-edition companion to the above | [dasny.org](https://www.dasny.org/sites/default/files/rfp-documents/2024-11/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Upstate.pdf) |
| **PA DGS JOC Pre-Proposal (final, 2016)** | Pennsylvania Dept. of General Services | CTC "Organized by Construction Specifications Institute (CSI)" and "Updated Annually on the RFP Anniversary Date," effective annually on the award date; line-item code form illustrated (e.g., `32 16 23 00-0002`, 4" CIP Concrete Sidewalk, SF); quantity add-on lines ("For Quantities 100 to 500, Add"); two-week proposal due window; contractors must "Justify Quantity Calculations" and "Explain Detail of Work"; 1% contractor license fee for eGordian | [pa.gov](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc/pa%20dgs%20joc%20pre-proposal%20final.pdf) |
| **PA DGS JOC Pre-Proposal — Gordian presentation** | PA DGS / Gordian | Non-pre-priced formulas — own forces `(A + B + C) × NPP Adjustment Factor`; subcontracted `D × NPP AF`; three quotes on letterhead; adjustment-factor calculation methods; eGordian software training and 24-hour support | [pa.gov](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc%20pre-proposal%20-%20gordian%20presentation.pdf) |
| **Sourcewell / State of California IDIQ General Terms** (Gordian-administered) | Sourcewell | Defines CTC as "Gordian's proprietary comprehensive listing of specific construction-related tasks created and customized for the solicitation"; defines the **Gordian IQCC System** (ezIQC) as comprising eGordian, Bid Safe, the CTC, and Technical Specifications; contractor is furnished eGordian access to generate price proposals at no software/training charge and must report contract activity within eGordian; Joint Scoping Meeting agenda; Proposal Package contents (see Field 7) | [sourcewell](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf) |
| **RSMeans Data Online FedRAMP page** | Gordian | RSMeans Data Online is authorized under FedRAMP by the Joint Authorization Board and hosted on the Gordian Federal Cloud as the first module on that cloud; authorization date, level, and package identifier are **not stated** on the page (**n.a.**) | [gordian.com](https://www.gordian.com/solutions/industry/federal/fedramp/) |
| **RSMeans API (sandbox Swagger UI)** | Gordian | A public Swagger UI endpoint titled "RSMeans API" exists, but the page rendered only "API Explorer / Explore" — no endpoints, resources, or authentication requirements were readable (**n.a.**) | [dataapi-sb.gordian.com](https://dataapi-sb.gordian.com/swagger/ui/index.html) |

**Leads not verified in this session (treat as n.a. until fetched):** a PA eMarketplace contract file reported to contain a "Sample eGordian User Manual" appendix ([PA eMarketplace file](https://www.emarketplace.state.pa.us/FileDownload.aspx?file=4400015342%5CContractFile.pdf)), an Illinois Tollway JOC training deck ([Illinois Tollway](https://agency.illinoistollway.com/documents/20184/1206382/202207+JOC+Training+Series.pdf)), and South Carolina JOC administrator instructions on sceis.sc.gov.

---

## Field 7 — JOC best practices: price proposal development, scope reconciliation, line-item justification, NPP/composite tasks

### 7.1 Federal framing

Army AFARS Subpart 5117.90 establishes that a Job Order Contract is an IDIQ contract, defines the Job Order Contract Price Book (JOCPB), and states that **"JOC unit prices include direct material, labor and equipment costs, but not indirect costs or profits which are addressed in the coefficient(s)."** It requires that the statement of work contain sufficient detail to prepare an independent government estimate per FAR 36.203 and to **minimize non-pre-priced tasks**; that the SOW be updated before order issuance with quantities, methods, quality levels, and days; that the ordering officer evaluate proposals and resolve variances between the IGE and the proposal; and that CONUS JOCPBs use commercially available pricing tools ([AFARS Subpart 5117.90](https://www.acquisition.gov/afars/subpart-5117.90-job-order-contracts)).

### 7.2 State-level best-practice guidance

Washington State's CPARB/DES **"JOC Best Practices Guidelines," DRAFT June 14, 2021** (recommendations, not requirements, under RCW 39.10) defines Unit Price Book, coefficient, City Cost Index, Non-Pre-priced, and Firm Fixed Price; states that **"Line items are broken down by Construction Specifications Institute (CSI) division"**; identifies Gordian RS Means and Gordian CTC as the most common UPBs in Washington; states that **"Unit prices from the UPB can not be negotiated"** — negotiation instead refines scope, line-item selection, and quantities — and lists UPB sections that are typically excluded ([WA DES JOC Best Practices Guidelines](https://des.wa.gov/sites/default/files/2022-06/6-17-21_JOC-BestPracticesGuidelines_Draft.pdf)).

Arizona's ADOA **JOC Manual (May 23, 2022)** defines Adjustment Factor, Prepriced Task, and Non Prepriced Task, states that a Unit Price comprises labor, equipment, and material as direct cost only, notes that new prepriced tasks can be added during the contract, and enumerates the minimum contents of a Job Order Proposal: price proposal, drawings/sketches, catalog cuts and technical data, subcontractor/supplier list with prices, construction schedule, warranties, and other required items ([ADOA JOC Manual](https://public.destinyhosted.com/yumacdocs/2024/BOSREG/20240221_1537/12676_Exhibit_II_ADOA_JOC_Manual_REV2.pdf)).

### 7.3 Proposal package contents (the reconciliation target)

The Sourcewell/California IDIQ general terms require the Proposal Package to include the price proposal; incidental drawings, sketches, and specifications; **quantity take-offs supporting all material quantities**; catalog cuts; the subcontractor list; the schedule; **back-up for Non Pre-Priced Tasks**; and warranty information ([Sourcewell IDIQ general terms](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf)). PA DGS likewise requires contractors to justify quantity calculations and explain the detail of work ([PA DGS JOC pre-proposal](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc/pa%20dgs%20joc%20pre-proposal%20final.pdf)).

### 7.4 Non-pre-priced and composite handling

Gordian's NPP formulas as presented to PA DGS are `(A + B + C) × NPP Adjustment Factor` for own-forces work and `D × NPP AF` for subcontracted work, with three quotes required on letterhead ([PA DGS Gordian presentation](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc%20pre-proposal%20-%20gordian%20presentation.pdf)). Pima Community College's JOC special conditions require three independent material quotes for own-forces work or three subcontractor quotes, a written explanation if fewer than three are obtainable, and provide that once the Owner approves an NPP unit price it **becomes a permanent NPP task no longer requiring price justification**; the Owner's determination of prepriced versus non-pre-priced status is "final, binding, and conclusive" ([Pima College JOC special conditions](https://www.pima.edu/administration/contracts-purchasing/docs/22-10046l-revised-exhibit-3.pdf)).

On composite versus component selection, DASNY's owner guide directs selecting the most practical and economical tasks and states that **"Assembly tasks take precedence over individual component tasks"** ([DASNY Using the CTC – Owner](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf)) — a rule the system can encode as a deterministic validation, since double-counting an assembly plus its components is exactly the "cost elements neither omitted nor double-counted" failure GAO warns about ([GAO-20-195G](https://www.gao.gov/assets/gao-20-195g.pdf)).

### 7.5 CSI structure and the 2026 crosswalk risk

MasterFormat is developed and maintained jointly by CSI and Construction Specifications Canada and is described as "the construction industry's shared and standardized language for project documentation," ensuring drawings, specifications, estimates, and product data "all point to the same intent." **MasterFormat 2026 introduces 2,185 new listings and 617 reorganized listings**, with the largest changes concentrated in Division 32 Exterior Improvements and Division 34 Transportation — together accounting for **more than 80% of total structural changes** — plus noticeable expansion in Division 28 Electronic Safety & Security and Division 31 Earthwork, and maintenance-level title clarifications in Divisions 01, 06, 09, 10, and 26. Its guiding principles are increased granularity, thematic consolidation, and forward-looking alignment, producing "more Level 3 breakdowns" ([CSI MasterFormat 2026](https://www.csiresources.org/standards/masterformat2026)). The page identifies divisions by two-digit numbers but does not state the full six-digit numbering structure or MasterFormat licensing terms — **n.a.** ([CSI MasterFormat 2026](https://www.csiresources.org/standards/masterformat2026)).

Because CTCs are organized by CSI division and updated annually on the contract anniversary ([PA DGS JOC pre-proposal](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc/pa%20dgs%20joc%20pre-proposal%20final.pdf)), the 2026 MasterFormat reorganization creates a real crosswalk-drift hazard for any stored CSI↔CTC mapping.

---

## Field 8 — Licensing and copyright controls for private catalogue ingestion and API output minimization

### 8.1 Copyright baseline

U.S. Copyright Office **Circular 33, "Works Not Protected by Copyright" (rev. 03/2021)**, states there is no protection for "any idea, procedure, process, system, method of operation, concept, principle, or discovery," that mere listings of ingredients and simple directions are uncopyrightable, and that protection is limited to original expression ([Circular 33](https://www.copyright.gov/circs/circ33.pdf)). The **Compendium of U.S. Copyright Office Practices (3d), Chapter 300** (page dated 01/28/2021) covers compilations and collective works under §§101 and 103, where the protectable authorship lies in the **selection, coordination, and arrangement**, subject to a minimal-creativity originality threshold ([Compendium Ch. 300](https://www.copyright.gov/comp3/chap300/ch300-copyrightable-authorship.pdf)).

The practical read for NTXP: individual factual unit prices and task facts are weak copyright subject matter, but the CTC's selection and arrangement is a compilation, and — decisively — **contract, not copyright, is the binding constraint**.

### 8.2 The contractual constraints that actually govern

DASNY's owner guide carries Gordian's CTC license clause verbatim: *"The Gordian Group, Inc. licenses the use of this CTC and other proprietary information and software for the sole purpose of providing Job Order Contracting services to [Owner]… Use of this CTC and other proprietary information and software for any other purpose, or for any other entity, is expressly prohibited without the express written consent of The Gordian Group, Inc."* ([DASNY Using the CTC – Owner](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf)). Sourcewell's terms likewise define the CTC as Gordian's proprietary listing customized for the solicitation ([Sourcewell IDIQ general terms](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf)).

Gordian's site terms add the anti-automation and anti-derivative prohibitions quoted in Field 5 ([Gordian Software terms of use](https://www.gordiansoftware.com/terms-of-use)).

### 8.3 RSMeans — the federated-interface constraint

The **Gordian General Terms of Use** governing RSMeans Online grant a "limited, non-exclusive, non-assignable, non-transferable, non-sublicensable, royalty-free, and revocable" right, in the customer's country, to access and use the SaaS and/or Data Subscription **solely for the customer's internal business purposes**, with RSMeans Data licensed "solely in the regular course of construction estimating and related work." "Data" is defined to include all construction cost data available through the Subscriptions; "Authorized User" covers employees, agents, consultants, or contractors who have agreed to the Terms and act solely for the customer's benefit; and "Named User" means a single individual on a non-temporary basis, with usage limits enforced by Named User count unless concurrent use is explicitly allowed in writing. Customers also represent that their Authorized Users are not employees or contractors of Gordian competitors or of any company delivering similar data ([Gordian General Terms of Use / RSMeans Online](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)).

Section 4.3 Restrictions prohibit, among other things: copying, modifying, translating, adapting, or creating derivative works or improvements of the Subscriptions **or any form of any Data**; combining or incorporating the Subscriptions into other programs; **merging the Data with any other software or SaaS program, or extracting such Data other than as expressly allowed**; renting, leasing, lending, selling, sublicensing, assigning, distributing, publishing, transferring, or otherwise making available the Subscriptions or any Data — expressly including via the internet, time-sharing, service bureau, software-as-a-service, or cloud service; reverse engineering or attempting to derive source code; **bypassing security devices or accessing the Subscriptions other than by an Authorized User using his or her own then-valid Access Credentials**; disrupting or impairing the Subscriptions or Gordian's provision of them to third parties; removing or altering proprietary notices; infringing third-party rights or violating law; and using the Subscriptions or Data for **competitive analysis or development, provision, or use of a competing software service or product**, or any purpose to Gordian's detriment ([Gordian General Terms of Use / RSMeans Online](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)). The public terms document does not use the words "robot," "spider," or "scraper" and states no separate API-integration clause in the fetched text — **n.a.**; the "extract such Data" and "own then-valid Access Credentials" clauses are the operative limits.

**Design consequence:** an NTXP-internal "federated interface to RSMeans" must not merge RSMeans Data into NTXP's own database, must not expose RSMeans Data through any service to third parties, and must operate under each individual's own Named User credentials. A cross-book federation layer should therefore return **references and opaque identifiers** — never redistributed cost data — and any cross-book comparison must remain inside the licensed user's session.

### 8.4 Litigation lead

A Fifth Circuit case, *Construction Cost Data v. Gordian Group*, was surfaced in search but not fetched; its holdings are **n.a.** for this memorandum ([FindLaw listing](https://caselaw.findlaw.com/court/us-5th-circuit/2074748.html)).

---

## Actionable design requirements

### A. MCP/API service

1. **Build stateless-first.** No `Mcp-Session-Id`, no GET stream, no `Last-Event-ID`; return `405` for GET/DELETE on the MCP endpoint ([MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)).
2. **Where state is unavoidable** (an open estimate, a reconciliation run), mint an opaque high-entropy handle, bind it server-side as `<user_id>:<handle>` with the user ID from the verified token, validate authorization on every call, expire it, and state its retention policy in the tool description ([MCP 2026-07-28 security](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices), [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).
3. **Validate `Origin` with a 403 on mismatch, bind local servers to 127.0.0.1, require `MCP-Protocol-Version: 2026-07-28`, and reject header/body mismatch with `400 HeaderMismatch`** ([MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)).
4. **Act as an OAuth 2.1 resource server** with RFC 9728 Protected Resource Metadata, RFC 8707 resource indicators, audience validation, and no token passthrough ([MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [MCP 2026-07-28 security](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).
5. **Scope `tools/list` by request credentials, never by connection**; validate all inputs, enforce access controls, rate limit, sanitize outputs, and log tool usage for audit ([MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).
6. **Run the CTC server as a local/private instance**, given NSA's guidance to prefer local MCP instances for private data and its finding that MCP does not itself define identity/session association or RBAC ([NSA CSI](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF)).
7. **Treat catalog text, scope documents, and owner comments as untrusted input** against LLM01/LLM05/LLM06, and require human approval for any write-side action ([OWASP Top 10 for LLMs v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)).

### B. Retrieval

8. **Three-lane retrieval, fused by RRF with k ≈ 60**: (i) exact/prefix code match, (ii) BM25 full-text, (iii) vector semantic — never additively combined, since BM25 is unbounded and cosine is bounded ([Azure hybrid ranking](https://learn.microsoft.com/en-us/azure/search/hybrid-search-ranking)).
9. **Rerank only a bounded head** of the fused list; Azure's precedent caps the L2 stage at the top 50 ([Azure semantic ranking](https://learn.microsoft.com/en-us/azure/search/semantic-search-overview)).
10. **Use trigram matching for identifier-shaped queries** (partial CTC codes, typo'd MasterFormat numbers) with GIN indexing and a tuned `pg_trgm.similarity_threshold` above the 0.3 default for high-precision code lookup ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)).
11. **Weight structured fields** with `setweight` A/B/C/D so code and title outrank long description text ([PostgreSQL text search controls](https://www.postgresql.org/docs/current/textsearch-controls.html)).
12. **On SQLite, use FTS5 with `bm25()` ranking and `snippet()`/`highlight()`** to produce evidence excerpts, and consider external-content or contentless tables to avoid duplicating licensed text in the index ([SQLite FTS5](https://www.sqlite.org/fts5.html)).

### C. Storage and migration

13. **Start on SQLite in WAL mode**, pinned to ≥ 3.53.0 for the WAL-reset corruption fix, on local storage only (never a network filesystem) ([SQLite WAL](https://www.sqlite.org/wal.html), [SQLite changelog](https://www.sqlite.org/changes.html)).
14. **Trigger migration to PostgreSQL when** multi-host or networked access is required, when sustained traffic exceeds the ~100k hits/day guidance band, or when indexed ANN search must join relational catalog data in one transaction ([SQLite appropriate uses](https://sqlite.org/whentouse.html), [SQLite WAL](https://www.sqlite.org/wal.html), [pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md)).
15. **Target PostgreSQL 17 or 18** (14 reaches EOL Nov 12, 2026) with pgvector 0.8.2, HNSW indexes, and embeddings ≤ 2,000 dimensions for `vector` (or `halfvec` up to 4,000) to stay within indexable limits ([PostgreSQL versioning](https://www.postgresql.org/support/versioning/), [pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md)).
16. **Enable iterative scans** (`hnsw.iterative_scan`, `hnsw.max_scan_tuples`) for filtered queries, since division- and edition-filtered ANN searches otherwise under-return ([pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md)).

### D. Provenance, versioning, audit

17. **Model every derived value in PROV-O terms** — the estimate line is an Entity `wasGeneratedBy` a mapping Activity, `wasAttributedTo` a SoftwareAgent acting `onBehalfOf` a human estimator, with `hadPrimarySource` pointing at the owner-issued scope and `wasRevisionOf` linking successive proposal versions ([W3C PROV-O](https://www.w3.org/TR/prov-o/)).
18. **Store catalog-edition validity as `tstzrange`/`daterange` with an exclusion constraint** so no two editions overlap for the same contract, matching the annual anniversary-date update cycle ([PostgreSQL range types](https://www.postgresql.org/docs/current/rangetypes.html), [PA DGS JOC pre-proposal](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc/pa%20dgs%20joc%20pre-proposal%20final.pdf)).
19. **Make the audit log append-only with per-record SHA-256 digests, digests protected separately (read-only media or encryption), and integrity re-verification on archival transfer**, per NIST SP 800-92's log-file integrity checking guidance and the AU-9 enhancement set (hardware write-once media, cryptographic protection, read-only access, separate physical storage) ([NIST SP 800-92](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf), [SP 800-53 Rev 5.1 control listing](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)).
20. **Design the record so a third party can replicate the estimate**: methods, calculations, results, assumptions, data sources per cost element, plus evidence of management review — GAO's "well documented" test ([GAO-20-195G](https://www.gao.gov/assets/gao-20-195g.pdf)).
21. **Gate all continuous learning behind named human approval**, log the approver, and inventory provenance for every learned mapping per NIST AI 600-1 GV-1.6-003; explicitly design against automation bias by surfacing confidence and the abstain path ([NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)).
22. **Track the NIST AI RMF critical-infrastructure profile** (concept note April 7, 2026) and the in-progress AI RMF 1.0 revision as forward compliance targets ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)).

### E. Browser automation

23. **Do not automate retrieval, indexing, or extraction from eGordian.** Gordian's terms prohibit robots, spiders, retrieval applications, and data mining outright ([Gordian Software terms of use](https://www.gordiansoftware.com/terms-of-use)).
24. **If assisted entry is pursued, restrict it to human-initiated, human-confirmed keystroke/field population under the operator's own valid credentials**, obtain written Gordian authorization first, and do not rely on robots.txt silence as permission ([Gordian Software terms of use](https://www.gordiansoftware.com/terms-of-use), [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)).
25. **Treat any stored auth state as credential material**: gitignore it, isolate per role, delete on expiry ([Playwright authentication](https://playwright.dev/docs/auth)).

### F. Licensing and output minimization

26. **Segregate catalogs by contract and owner.** The CTC license limits use to providing JOC services to the named owner; any cross-owner reuse requires written Gordian consent ([DASNY Using the CTC – Owner](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf)).
27. **Export opaque identifiers, never prices, descriptions, or productivity data.** RSMeans terms forbid merging Data with other software, extracting it, or making it available via any cloud/SaaS service ([Gordian General Terms of Use](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)).
28. **Keep any RSMeans federation inside the Named User's own session**, with per-individual credentials and no shared service accounts ([Gordian General Terms of Use](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)).
29. **Avoid any use that could be characterized as competitive analysis or building a competing product**, which is separately prohibited ([Gordian General Terms of Use](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)).
30. **Preserve proprietary notices** on anything derived from licensed content ([Gordian General Terms of Use](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf), [Gordian Software terms of use](https://www.gordiansoftware.com/terms-of-use)).

### G. Estimating logic to encode as deterministic validators

31. **Assembly-over-component precedence check** — flag any proposal containing both an assembly task and its component tasks ([DASNY Using the CTC – Owner](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf)).
32. **Coefficient/unit-price separation** — never let indirects or profit enter a unit price; they belong in the coefficient ([AFARS 5117.90](https://www.acquisition.gov/afars/subpart-5117.90-job-order-contracts)).
33. **No unit-price negotiation** — reconciliation adjusts scope, line-item selection, and quantities only ([WA DES JOC Best Practices Guidelines](https://des.wa.gov/sites/default/files/2022-06/6-17-21_JOC-BestPracticesGuidelines_Draft.pdf)).
34. **NPP gate** — require three quotes on letterhead (or a written explanation of fewer), apply the correct `(A+B+C) × NPP AF` or `D × NPP AF` formula by delivery method, and promote owner-approved NPP tasks to permanent status so they stop requiring justification ([PA DGS Gordian presentation](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc%20pre-proposal%20-%20gordian%20presentation.pdf), [Pima College JOC special conditions](https://www.pima.edu/administration/contracts-purchasing/docs/22-10046l-revised-exhibit-3.pdf)).
35. **Proposal-package completeness check** — price proposal, drawings/sketches, quantity take-offs backing every material quantity, catalog cuts, subcontractor list, schedule, NPP back-up, warranties ([Sourcewell IDIQ general terms](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf), [ADOA JOC Manual](https://public.destinyhosted.com/yumacdocs/2024/BOSREG/20240221_1537/12676_Exhibit_II_ADOA_JOC_Manual_REV2.pdf)).
36. **Version CSI crosswalk edges against a MasterFormat edition**, given 2,185 new and 617 reorganized listings in MasterFormat 2026 concentrated in Divisions 32 and 34 ([CSI MasterFormat 2026](https://www.csiresources.org/standards/masterformat2026)).

---

## 2026 recency anchors used

| Anchor | Date | Source |
|---|---|---|
| MCP specification revision 2026-07-28 (stateless, sessions removed) | 2026-07-28 | [MCP versioning](https://modelcontextprotocol.io/specification/versioning), [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) |
| NSA/CMU SEI MCP security CSI, Ver. 1.0 | May 2026 | [media.defense.gov](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF) |
| NIST AI RMF critical-infrastructure profile concept note; AI RMF 1.0 under revision | Apr 7, 2026 | [NIST](https://www.nist.gov/itl/ai-risk-management-framework) |
| SQLite 3.53.4 current; 3.53.0 WAL-reset corruption fix | 2026-07-24 / 2026-04-09 | [SQLite changelog](https://www.sqlite.org/changes.html) |
| pgvector 0.8.2 (README updated) | May 30, 2026 | [pgvector README](https://github.com/pgvector/pgvector/blob/master/README.md) |
| PostgreSQL 19 Beta 2 announcement banner; PG 14 EOL Nov 12, 2026 | Jul 16, 2026 / Nov 12, 2026 | [pg_trgm docs](https://www.postgresql.org/docs/current/pgtrgm.html), [versioning policy](https://www.postgresql.org/support/versioning/) |
| MasterFormat 2026 release (2,185 new / 617 reorganized listings) | 2026 edition | [CSI](https://www.csiresources.org/standards/masterformat2026) |

## Explicit gaps (n.a.)

- Verbatim NIST SP 800-53 control statement text for AU-3, AU-9, AU-9(3), AU-10, AU-11, SI-7 — identifiers and enhancement titles confirmed, statement text not retrievable from the fetched PDFs ([OSCAL-derived listing](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)).
- OpenSearch hybrid-search normalization details ([page returned a stub](https://opensearch.org/docs/latest/search-plugins/hybrid-search/)).
- RSMeans API endpoint inventory and authentication model ([Swagger UI rendered no content](https://dataapi-sb.gordian.com/swagger/ui/index.html)).
- FedRAMP authorization date, impact level, and package ID for RSMeans Data Online ([not stated on Gordian's page](https://www.gordian.com/solutions/industry/federal/fedramp/)).
- eGordian Release Notes version and date ([undated](https://static.egordian.com/Release%20Notes/ReleaseNotes.htm)).
- GAO-20-195G publication date ([not stated in the fetched document](https://www.gao.gov/assets/gao-20-195g.pdf)).
- MasterFormat six-digit numbering structure and licensing terms ([not stated on the 2026 page](https://www.csiresources.org/standards/masterformat2026)).
- A canonical, publicly posted **eGordian end-user manual**; the closest public artifacts are the Gordian proposal-review PDF and the agency training decks listed in Field 6. A PA eMarketplace contract file reportedly containing a "Sample eGordian User Manual" appendix was not fetched ([PA eMarketplace](https://www.emarketplace.state.pa.us/FileDownload.aspx?file=4400015342%5CContractFile.pdf)).
- *Construction Cost Data v. Gordian Group* (5th Cir.) holdings ([not fetched](https://caselaw.findlaw.com/court/us-5th-circuit/2074748.html)).
- NTXP's own contract-specific CTC/eGordian license terms, which may differ from the public documents cited here.
