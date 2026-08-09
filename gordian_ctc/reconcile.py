"""Deterministic known-budget reconciliation; never fabricates scope/cost."""
from __future__ import annotations

import json
import re
import secrets
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from .overlay import ApprovalRequired, _audit, connect
from .util import canonical_json, now, sha256_bytes, stable_id

DISCLAIMER = (
    "Estimator-assumption draft only. It preserves the provided target total and does not "
    "authorize scope, task selection, quantities, unit prices, or contract compliance. "
    "A named human estimator must approve additions and final reconciliation."
)


def _d(value: Any) -> Decimal:
    return Decimal(str(value or 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _division(value: Any) -> str:
    s = re.sub(r"\D", "", str(value or ""))
    return s[:2].zfill(2) if s else "UN"


def _has_page_or_spec_reference(line: dict) -> bool:
    """Every proposal line must cite a source page, sheet, or specification ref."""
    refs = list(line.get("evidence_refs") or [])
    if isinstance(line.get("source_ref"), dict):
        refs.append(line["source_ref"])
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if isinstance(ref.get("page"), int) and ref["page"] >= 1:
            return True
        if str(ref.get("sheet") or "").strip():
            return True
        if str(ref.get("source_type") or "").lower() == "specification" and str(ref.get("reference") or "").strip():
            return True
    return False


def _has_user_comment(line: dict) -> bool:
    return bool(str(line.get("user_notes") or "").strip())


def _has_quantity_math(line: dict) -> bool:
    return bool(str(line.get("quantity_math") or "").strip())


def _has_named_quantity_rationale(line: dict) -> bool:
    rationale = line.get("quantity_rationale")
    return bool(isinstance(rationale, dict) and rationale.get("approval") is True
                and str(rationale.get("actor") or "").strip()
                and str(rationale.get("rationale") or "").strip())


def _rounded_quantity_patterns(line: dict, threshold: int, round_increments: list[int],
                               endings: list[str]) -> list[str]:
    """Flag observed round patterns; never manufacture a more precise substitute."""
    q = line.get("quantity")
    if not isinstance(q, (int, float)) or float(q) != int(float(q)):
        return []
    integer = abs(int(float(q)))
    if integer == 0:
        return []
    patterns = []
    digits = str(integer)
    if integer >= threshold:
        for ending in sorted({str(x) for x in endings}, key=lambda x: (-len(x), x)):
            if digits.endswith(ending):
                patterns.append("integer_ending_" + ending)
    for inc in sorted({int(x) for x in round_increments if int(x) > 1}):
        if integer >= inc and integer % inc == 0:
            patterns.append(f"multiple_of_{inc}")
    return patterns


def _companion_gaps(scope_atoms: list[dict], proposal_lines: list[dict], profile: dict) -> list[dict]:
    text = " ".join(str(x.get("scope_text", "")) for x in scope_atoms).lower()
    planned = " ".join(str(x.get("scope_text", x.get("description", ""))) for x in proposal_lines).lower()
    gaps = []
    for rule in profile.get("companion_scope_prompts", []):
        triggers = [str(x).lower() for x in rule.get("when", [])]
        if any(t in text for t in triggers) and not any(t in planned for t in triggers):
            gaps.append({"rule_id": rule["id"], "prompt": rule["prompt"], "blocking": bool(rule.get("blocking")),
                         "status": "review_required", "action": "Human must decide; no value was added."})
    return gaps


def _decompose(assemblies: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return only declared components; missing code/value is an exception, never filled."""
    components, issues = [], []
    for assembly in assemblies:
        aid = assembly.get("assembly_id", "unnamed")
        for idx, c in enumerate(assembly.get("components", [])):
            if not c.get("scope_text"):
                issues.append({"type": "assembly_component_missing_scope", "assembly_id": aid, "index": idx})
                continue
            if c.get("catalogue_code") is None:
                issues.append({"type": "assembly_component_no_catalogue_code", "assembly_id": aid, "index": idx,
                               "scope_text": c["scope_text"]})
            components.append({"assembly_id": aid, "component_index": idx, **c})
    return components, issues


def _priority_key(item: dict, mode: str) -> tuple:
    """Largest underrepresentation first; division code only deterministically breaks ties."""
    if mode == "percentage_deficit_then_absolute":
        return (-item["percentage_deficit"], -item["absolute_deficit"], item["division"])
    return (-item["absolute_deficit"], -item["percentage_deficit"], item["division"])


def reconcile(request: dict, profile: dict | None = None) -> dict:
    """Pure deterministic calculation. All costs must originate in request inputs."""
    profile = profile or {}
    config = profile.get("contract_configurable", {})
    rounded = config.get("rounded_quantity_review", {})
    threshold = int(rounded.get("threshold", config.get("rounded_quantity_review_threshold", 100)))
    round_increments = list(rounded.get("round_increment_candidates", [10, 25, 50, 100]))
    round_endings = list(rounded.get("flag_integer_endings", ["00", "000"]))
    prioritization = config.get("division_deficit_prioritization", {})
    priority_mode = prioritization.get("default", prioritization if isinstance(prioritization, str)
                                       else "absolute_deficit_then_percentage")
    if priority_mode not in {"absolute_deficit_then_percentage", "percentage_deficit_then_absolute"}:
        raise ValueError("Unsupported division deficit prioritization mode.")
    bands = config.get("variance_bands", {"balanced_pct": 0.005, "warn_pct": 0.03})
    budget = request.get("known_budget", {})
    if "target_total" not in budget:
        raise ValueError("known_budget.target_total is required")
    target = _d(budget["target_total"])
    scope_atoms = list(request.get("scope_atoms", []))
    lines = list(request.get("proposal_lines", []))
    exceptions: list[dict] = []
    valid_lines: list[dict] = []
    rejected_lines: list[dict] = []
    quantity_flags: list[dict] = []
    for line in lines:
        item = dict(line)
        reasons = []
        if not _has_user_comment(item):
            reasons.append("missing_user_comment")
        if not _has_page_or_spec_reference(item):
            reasons.append("missing_source_page_or_spec_reference")
        if item.get("quantity") is None or not item.get("unit"):
            reasons.append("missing_quantity_or_unit")
        if not _has_quantity_math(item):
            reasons.append("missing_quantity_justification_math")
        patterns = _rounded_quantity_patterns(item, threshold, round_increments, round_endings)
        if patterns:
            flag = {"record_id": item.get("record_id"), "quantity": item.get("quantity"),
                    "patterns": patterns, "has_quantity_math": _has_quantity_math(item),
                    "has_named_human_rationale": _has_named_quantity_rationale(item),
                    "action": "Review source-backed math; never select an arbitrary exact-looking replacement."}
            quantity_flags.append(flag)
            if not (_has_quantity_math(item) or _has_named_quantity_rationale(item)):
                reasons.append("suspicious_rounded_quantity_without_math_or_named_rationale")
        if item.get("supported_value") is None:
            reasons.append("missing_supported_value")
        if reasons:
            rejected_lines.append({"record_id": item.get("record_id"), "reasons": reasons})
            exceptions.append({"type": "line_rejected", "record_id": item.get("record_id"), "reasons": reasons})
        else:
            valid_lines.append(item)
    by_division: dict[str, Decimal] = defaultdict(Decimal)
    for line in valid_lines:
        by_division[_division(line.get("division") or line.get("catalogue_code"))] += _d(line["supported_value"])
    division_budgets = {str(_division(k)): _d(v) for k, v in budget.get("division_budgets", {}).items()}
    deficits: list[dict] = []
    if division_budgets:
        for division in sorted(division_budgets):
            supported = by_division.get(division, Decimal("0"))
            deficit = max(Decimal("0"), division_budgets[division] - supported)
            pct = (deficit / division_budgets[division]) if division_budgets[division] > 0 else Decimal("0")
            deficits.append({"division": division, "known_budget": float(division_budgets[division]),
                             "supported_value": float(supported), "absolute_deficit": float(deficit),
                             "percentage_deficit": float(pct), "eligible_for_bid_leveling": deficit > 0})
        deficits.sort(key=lambda x: _priority_key(x, priority_mode))
        for index, item in enumerate(deficits, start=1):
            item["priority"] = index if item["eligible_for_bid_leveling"] else None
            if not item["eligible_for_bid_leveling"]:
                item["reason"] = "already_at_or_above_division_budget; do_not_inflate"
    else:
        exceptions.append({"type": "division_budgets_missing",
                           "message": "Cannot allocate target-total residual to divisions without supplied division budgets."})
    supported_total = sum((_d(x["supported_value"]) for x in valid_lines), Decimal("0"))
    residual = target - supported_total
    ratio = abs(residual) / abs(target) if target else Decimal("0")
    balanced = Decimal(str(bands.get("balanced_pct", 0.005)))
    warning = Decimal(str(bands.get("warn_pct", 0.03)))
    band = "balanced" if ratio <= balanced else ("warning" if ratio <= warning else "exception")
    gaps = _companion_gaps(scope_atoms, valid_lines, profile)
    for gap in gaps:
        exceptions.append({"type": "companion_scope_gap", **gap})
    components, assembly_issues = _decompose(list(request.get("assemblies", [])))
    exceptions.extend(assembly_issues)
    result = {
        "project_id": request.get("project_id"), "target_total": float(target),
        "supported_total": float(supported_total), "residual": float(residual),
        "target_total_unchanged": True, "variance_pct": float(ratio), "variance_band": band,
        "division_deficits_prioritized": deficits, "division_deficit_priority_mode": priority_mode,
        "companion_scope_gaps": gaps,
        "assembly_decomposition": components, "valid_lines": len(valid_lines),
        "rejected_lines": rejected_lines, "exception_queue": exceptions,
        "final_status": "needs_human_approval",
        "disclaimer": DISCLAIMER,
        "quantity_flags": quantity_flags,
        "precision_rule": {
            "threshold": threshold, "round_increment_candidates": round_increments,
            "integer_endings": round_endings,
            "effect": "Every line requires source-backed quantity math; rounded patterns are flagged. A named-human rationale can supplement review but cannot create a fabricated precise quantity."
        },
    }
    return result


def persist_reconciliation(overlay_path: str, request: dict, result: dict, actor: str,
                           approval: bool = False) -> dict:
    """Persist append-only run; only a human can mark final approval."""
    if approval and not actor:
        raise ApprovalRequired("Named actor required for final approval.")
    project_id = request.get("project_id")
    if not project_id:
        raise ValueError("project_id required")
    run_id = stable_id("reconcile", [project_id, request, result, actor, now(), secrets.token_hex(4)])
    status = "approved" if approval and not result["exception_queue"] else "needs_human_approval"
    if approval and result["exception_queue"]:
        raise ApprovalRequired("Cannot final-approve reconciliation with unresolved exception queue.")
    con = connect(overlay_path)
    try:
        con.execute("INSERT INTO reconciliation_run VALUES(?,?,?,?,?,?,?,?,?)",
                    (run_id, project_id, sha256_bytes(canonical_json(request).encode()), canonical_json(result),
                     status, actor, actor if approval else None, int(approval), now()))
        _audit(con, actor, "persist_reconciliation", project_id, {"run_id": run_id, "status": status, "approval": approval})
        con.commit()
        return {"run_id": run_id, "status": status, "approval": approval}
    finally:
        con.close()
