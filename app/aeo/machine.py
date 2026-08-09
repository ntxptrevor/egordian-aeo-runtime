"""AEO - Assignment Estimate Operator: deterministic 9-stage state machine.

Derived from ``AEO_artifact_handoff.md`` (BLUEPRINT v0.1, 2026-08-07).

State and transitions are owned by code. A stage never advances itself; the
orchestrator validates the produced artifact against the stage contract, then
commits the transition inside the repository. Stages 2-4 may *propose*
candidates but can never introduce a line that is not present in the licensed
catalogue or in supplied evidence. Stage 5 reconciles to a KNOWN target using
the existing skill methodology instead of estimating from scratch. Stage 7 is
mandatory before any dollar commitment. Stage 8 is capability-blocked because
no PriceProposalsV1 write route is documented.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

TIER_DETERMINISTIC = "T1"
TIER_PERCEPTION = "T2"
TIER_JUDGMENT = "T3"


@dataclass(frozen=True)
class Stage:
    index: int
    key: str
    name: str
    tier: str
    description: str
    egordian_modules: tuple[str, ...]
    required_scopes: tuple[str, ...]
    gate: str | None = None
    blocked_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index, "key": self.key, "name": self.name, "tier": self.tier,
            "description": self.description,
            "egordian_modules": list(self.egordian_modules),
            "required_scopes": list(self.required_scopes),
            "gate": self.gate, "blocked_reason": self.blocked_reason,
        }


STAGES: tuple[Stage, ...] = (
    Stage(0, "detect_authenticate", "Detect & authenticate", TIER_DETERMINISTIC,
          "Discover the assignment, confirm credential state, start the SLA clock.",
          ("AccessToken", "JobOrders", "TrackingDatesV1"), ("aeo:run",)),
    Stage(1, "dossier", "Assemble the assignment dossier", TIER_DETERMINISTIC,
          "Pull job order, scope of work, files, pictures, notes and contacts into one "
          "provenance-stamped package.",
          ("JobOrdersV1", "FilesV1", "PicturesV1", "NotesV1", "ContactsV1"), ("aeo:run",)),
    Stage(2, "knowledge_base", "Build the knowledge base (input gates)", TIER_PERCEPTION,
          "Index every document; each extracted fact carries a page/sheet evidence span. "
          "Bad input (low OCR score, missing scale) is rejected before estimating.",
          ("FilesV1", "PicturesV1"), ("aeo:run",)),
    Stage(3, "qto_consensus", "Quantify takeoff with consensus", TIER_PERCEPTION,
          "Quantify scope; bid-critical numbers run N=5 consensus. Disagreement produces "
          "an exception with evidence, never a silent average.",
          (), ("aeo:run",)),
    Stage(4, "crosswalk", "Crosswalk scope to the CTC catalogue", TIER_DETERMINISTIC,
          "Map each scope item to a catalogue line via deterministic lookup; only genuinely "
          "new items become candidates, and no line may be invented.",
          ("ConstructionTaskCatalogV1",), ("aeo:run", "catalogue:read")),
    Stage(5, "proposal_assembly", "Assemble the price proposal", TIER_DETERMINISTIC,
          "Known-target reconciliation: the authorized target total is never changed. "
          "Quantity x catalogue unit price x coefficient, reconciled to the approved cost.",
          ("PriceProposalsV1",), ("aeo:run", "catalogue:read")),
    Stage(6, "self_check", "Self-check & confidence tier", TIER_DETERMINISTIC,
          "Range checks, cross-foots, division coverage, catalogue validity; every line gets "
          "a confidence tier and low-confidence lines surface for review.",
          (), ("aeo:run",)),
    Stage(7, "human_gate", "Human gate", TIER_JUDGMENT,
          "A named estimator reviews the flagged lines with evidence and approves. "
          "Mandatory before any dollar commitment.",
          (), ("aeo:approve",), gate="human_gate"),
    Stage(8, "submit_log", "Submit & log", TIER_DETERMINISTIC,
          "Write the proposal, post an audit note, stamp the milestone, emit the run manifest.",
          ("PriceProposalsV1", "NotesV1", "TrackingDatesV1"), ("aeo:run", "egordian:write"),
          gate="human_gate",
          blocked_reason=(
              "capability_blocked: the eGordian Help page documents only "
              "GET v1/Owners/{ownerId}/PriceProposals. No draft or submit route is published, "
              "so this stage remains assisted and produces a submission packet for a human "
              "to file manually.")),
)

STAGE_BY_INDEX = {s.index: s for s in STAGES}
STAGE_BY_KEY = {s.key: s for s in STAGES}

TERMINAL_STAGE = 8


class StateTransitionError(RuntimeError):
    pass


class GateRequired(PermissionError):
    pass


def stage_for(value: int | str) -> Stage:
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        stage = STAGE_BY_INDEX.get(int(value))
    else:
        stage = STAGE_BY_KEY.get(str(value))
    if stage is None:
        raise StateTransitionError(f"Unknown AEO stage {value!r}.")
    return stage


def assert_can_run(current_stage: int, requested: Stage, *, completed: set[int],
                   gate_approved: bool) -> None:
    """Code - not the model - decides whether a stage may execute."""
    # The dollar-commitment gate is evaluated first so that an attempt to reach
    # stage 8 always reports the human gate, never a generic ordering error.
    if requested.index >= 8 and not gate_approved:
        raise GateRequired(
            "Stage 7 human gate approval is mandatory before stage 8 "
            "(any dollar commitment).")
    if requested.index > 0 and (requested.index - 1) not in completed:
        raise StateTransitionError(
            f"Stage {requested.index} ({requested.key}) cannot run: stage "
            f"{requested.index - 1} has not completed. Stages execute in order.")
    if requested.index in completed:
        raise StateTransitionError(
            f"Stage {requested.index} ({requested.key}) already completed; "
            "re-running requires a new assignment or an explicit reset.")


def diagram() -> list[dict[str, Any]]:
    return [s.to_dict() for s in STAGES]


def next_stage(current_completed: set[int]) -> int | None:
    for stage in STAGES:
        if stage.index not in current_completed:
            return stage.index
    return None
