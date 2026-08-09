# Reconciliation methodology

## Purpose and disclaimer

Produce a defensible **justification estimate** from a known project total plus
quotes, drawings, QTO, scope atoms, and CTC lines without silently changing the
authorized target. This is an estimator-assumption workflow, not a substitute
for contract review, site conditions, or named estimator approval.

## Deterministic procedure

1. Create and preserve a baseline spreadsheet before external UI entry.
2. Block any proposal line lacking a user comment, a page/sheet/specification
   reference, quantity-justification math, a quantity/unit, or supported value.
3. Group priced proposal lines by CSI division and calculate:
   \(D_d=\max(0, B_d-P_d)\), where \(B_d\) is known division budget (if supplied)
   and \(P_d\) is supported proposal-line value. When only a total is supplied,
   division deficits are pending human allocation.
4. Work **positive underrepresented division deficits first**, never an already
   high division. The default profile mode orders by largest absolute deficit,
   then largest percentage deficit; a contract may instead order by percentage,
   then absolute amount. For each division:
   \[
   A_d=\max(0,B_d-P_d), \qquad Q_d=A_d/B_d
   \]
   where \(A_d\) is absolute deficit and \(Q_d\) is percentage deficit. Zero or
   negative deficits are explicitly ineligible for bid-leveling and cannot be
   used to inflate an overrepresented division.
5. Expand approved assemblies only into evidence-backed components; identify
   companion-scope gaps and unattached modifiers.
6. Calculate residual \(R=T-\sum P_i\) from the unchanged target \(T\); classify
   as balanced, under-supported, or over-supported using configured bands.
7. Flag, never “correct,” quantities with integer endings such as `00`/`000` or
   configured round increments (default candidates: 10, 25, 50, 100). Every
   quantity needs source-backed calculation math. A named-human rationale can
   supplement review of a flagged round value but cannot authorize an arbitrary
   exact-looking replacement.
8. Emit exceptions. A named human approves each added scope, assumptions, and the
   final reconciliation decision.

## Companion scope

Profile-controlled candidate assumptions include GPR/RS scanning before slab
cutting, blocking for wall-mounted work, protection/repair around existing
services, flooring demo/grinding/washing/premium flooring/default 4-inch vinyl
base, and painting low-VOC/prep-hole patching/L4 tape-bed-texture/sanding/separate
coats with a candidate \(1/3\) L.F. brush-stroke-per-painted-S.F. formula.
Electrical, plumbing, trench/site, custom-cabinetry, and equipment-mobilization
defaults are enumerated in `profiles/trevor-practices-v1.json`. They are **review
prompts, not automatic cost additions**; named humans must approve use against
the contract and project.

## Source documentation

The proposal package should tie every material quantity back to supporting QTO
and include drawings/specifications, catalog cuts, schedule, NPP backup, and
warranties ([Sourcewell/California terms](https://files.sourcewell.org/public/Shared%20Documents/Solicitations/IFB%20CA-123021-10492/Solicitation%20Documents/IFB_CA-123021_IDIQ_State_of_California_Contract_General_Terms_and_Conditions.pdf)).
PA guidance likewise requires quantity justification and detail of work
([PA DGS pre-proposal](https://www.pa.gov/content/dam/copapwp-pagov/en/dgs/documents/design-and-construction/documents/joc/pa%20dgs%20joc%20pre-proposal%20final.pdf)).
