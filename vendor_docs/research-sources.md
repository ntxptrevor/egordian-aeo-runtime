# Source-cited architecture basis

The local `gordian_ctc_research_memorandum_20260806.md` is the controlling
research memo for this package. Claims below link to the underlying URLs cited in
that memo.

- MCP security guidance says MCP is stateless at protocol level and persistent
  state requires an explicit handle passed as ordinary tool input
  ([MCP security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).
- Tool inputs should be schema-described and users should be able to review
  sensitive actions ([MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).
- SQLite FTS5 supports BM25, `MATCH`, highlighting, snippets, phrase/prefix, and
  Boolean search suitable for code-dense local search
  ([SQLite FTS5](https://www.sqlite.org/fts5.html)).
- SQLite remains appropriate for private/single-host applications; WAL and
  network filesystem constraints inform the local deployment default
  ([SQLite appropriate uses](https://sqlite.org/whentouse.html),
  [SQLite WAL](https://www.sqlite.org/wal.html)).
- W3C PROV-O supplies Entity, Activity, Agent, derivation, attribution, primary
  source, and quoted-from concepts used by the provenance envelope
  ([W3C PROV-O](https://www.w3.org/TR/prov-o/)).
- NIST guidance supports human approval, evidence inventory, and automation-bias
  controls for AI-assisted governance
  ([NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)).
- Proposal packages should contain takeoffs, drawings/specifications, catalog
  cuts, schedule, NPP backup, and warranties
  ([Sourcewell/California terms](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf)).
- JOC practice guidance says unit-price negotiation is not the lever; adjust
  scope, task selection, and quantities instead
  ([Washington JOC guidance](https://des.wa.gov/sites/default/files/2022-06/6-17-21_JOC-BestPracticesGuidelines_Draft.pdf)).
- The task-catalogue licensing and anti-automation boundary is documented at
  [Gordian Software Terms](https://www.gordiansoftware.com/terms-of-use) and
  [DASNY's CTC guide](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf).

No factual assertion in this package depends on a public source for a licensed
CTC line, price, productivity, or description.
