# eGordian guidance: human authorization boundary

This package must **not** automate eGordian retrieval, indexing, extraction,
data mining, bulk navigation, credential replay, or catalogue reconstruction.
Gordian's terms prohibit robots, spiders, retrieval applications, and data
mining ([Gordian Software Terms](https://www.gordiansoftware.com/terms-of-use)).
The research memorandum therefore recommends human-operated, human-supervised
assisted entry only, after written authorization.

Permitted support in this package is deliberately narrow:

- prepare baseline spreadsheet/estimate lines offline;
- direct a human to a known task code already available in the authorized local
  catalogue;
- accept an explicitly observed missing line only when the human supplies
  `operator`, `observed_at`, `screen_or_document_reference`, `contract`, and
  `approval=true`;
- record that observation as an overlay proposal, never silently update the
  catalogue.

The applicable proposal process typically includes scope, price proposal, review,
and job order issuance ([Gordian contractor guide](https://www.gordian.com/uploads/2023/03/JOC-for-Contractors-eBook.pdf)).
It does not grant a data-extraction right. A human must verify all UI entries
and persisted values.

## Post-reconciliation, user-authorized workflow

Only after the reconciliation preserves its target total **and** a named human
has approved the reconciliation, the operator may:

1. confirm they are in the intended per-job eGordian login environment without
   providing, recording, or storing credentials in this system;
2. under explicit authorization, navigate and inspect the relevant project
   settings and estimate screens;
3. have the human verify the intended line, quantity, and saved state; and
4. if a line is absent from the immutable local catalogue, record only the
   explicitly observed code/opaque ID, edition, date, and screen/page provenance
   through `observed_external_line` with verification pending.

This is not permission to automate catalogue extraction, bulk collection,
indexing, or navigation. The immutable catalogue is never changed by this
workflow.
