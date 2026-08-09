# Baseline interchange data contracts

The canonical interchange is JSON validated against `schemas/`, with a
CSV/XLSX-compatible flattened contract in
`templates/baseline_interchange_columns.csv`. Do not put licensed catalogue
descriptions or costs into a public interchange.

## Required common fields

Every project-owned record has `project_id`, `record_id`, `source_type`,
`source_ref`, `evidence_refs`, `user_notes`, and `created_by`. Evidence refs
contain page/spec/sheet references and optional coordinates/quoted text/hash.
Proposal lines also require `quantity_math`, `unit`, source-backed rate/cost
where available, decision status, **user notes**, and an evidence reference with
a page, sheet, or specification reference. Reconciliation blocks any line that
lacks one of these fields.

## Entities

| Entity | Purpose |
|---|---|
| `known_budget` | immutable target total/budget and origin |
| `quote` | vendor/sub quote and terms; never conflated with CTC task data |
| `qto` | quantity takeoff with calculation and evidence |
| `scope_atom` | atomic scope unit to translate/decompose |
| `proposal_line` | candidate cost line with evidence and decision state |
| `user_comment` | estimator/owner comments, user-authored and project-scoped |
| `evidence_ref` | page/spec/sheet/image/quote provenance |
| `reconciliation_decision` | human-approved resolution of deficit/exception |
| `observed_external_line` | human-observed eGordian/book line absent from immutable DB; pending verification only |
| `big_note` | project-scoped long-form estimator note searched before line proposal |
| `change_order_log` | append-only change-order event |
| `proposal_final_delta` | initial proposal versus accepted-final delta and acceptance event |
| `improvement_candidate` | inert process-improvement proposal requiring a named-human decision |

All additions from a model/perception adapter remain proposals. The schema uses
explicit enum status values, not open-text control flow.
