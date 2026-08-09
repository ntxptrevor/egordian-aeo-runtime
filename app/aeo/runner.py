"""AEO stage execution.

Every stage returns a schema-valid artifact, records evidence spans, emits
audit events, and files exceptions instead of guessing. No stage may invent a
catalogue line, a quantity, or a price.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from gordian_ctc.reconcile import reconcile as engine_reconcile

from ..catalogue_gateway import CatalogueGateway, LicenseViolation, get_gateway
from ..config import MCP_PROTOCOL_VERSION, SERVICE_VERSION, get_settings
from ..egordian.client import EgordianClient, EgordianError
from ..egordian.registry import get_registry
from ..repo.base import Repository
from .machine import (STAGES, GateRequired, Stage, StateTransitionError, assert_can_run,
                      stage_for)

ARTIFACT_SCHEMA_VERSION = "aeo-artifact-1"


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def version_hashes(gateway: CatalogueGateway) -> dict[str, str]:
    registry = get_registry()
    try:
        cat = gateway.info()
        catalogue_edition = str(cat.get("edition"))
        catalogue_hash = str(cat.get("row_content_sha256"))
    except Exception:
        catalogue_edition, catalogue_hash = "unavailable", "unavailable"
    return {
        "service_version": SERVICE_VERSION,
        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "catalogue_edition": catalogue_edition,
        "catalogue_row_content_sha256": catalogue_hash,
        "operation_registry_sha256": registry.fixture_sha256,
        "stage_machine_hash": _hash([s.to_dict() for s in STAGES]),
    }


def _artifact(stage: Stage, status: str, payload: dict[str, Any],
              evidence: list[dict[str, Any]], versions: dict[str, str]) -> dict[str, Any]:
    body = {
        "schema": ARTIFACT_SCHEMA_VERSION,
        "stage": stage.index,
        "stage_key": stage.key,
        "stage_name": stage.name,
        "tier": stage.tier,
        "status": status,
        "payload": payload,
        "evidence": evidence,
        "versions": versions,
    }
    body["version_hash"] = _hash(body)
    return body


def minimize_for_storage(value: Any, _depth: int = 0) -> Any:
    """Licensing minimisation before persistence.

    Licensed catalogue prose (line descriptions) is returned to the caller in the
    live response but is never written to the control plane; the stored artifact
    keeps a hash plus the line code and provenance so the run stays auditable and
    reproducible without copying catalogue content out of the sealed database.
    """
    if _depth > 12:
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key == "description" and isinstance(item, str):
                out["description_sha256"] = _hash(item)[:32]
                out["description_stored"] = False
            else:
                out[key] = minimize_for_storage(item, _depth + 1)
        return out
    if isinstance(value, list):
        return [minimize_for_storage(v, _depth + 1) for v in value]
    return value


def validate_artifact(artifact: dict[str, Any]) -> None:
    required = ("schema", "stage", "stage_key", "tier", "status", "payload", "evidence",
                "versions", "version_hash")
    missing = [f for f in required if f not in artifact]
    if missing:
        raise StateTransitionError(f"Stage artifact is not schema-valid; missing {missing}.")
    if artifact["status"] not in ("ok", "blocked", "needs_input", "flagged"):
        raise StateTransitionError(f"Unknown artifact status {artifact['status']!r}.")


class AEORunner:
    def __init__(self, repo: Repository, gateway: CatalogueGateway | None = None,
                 client: EgordianClient | None = None):
        self.repo = repo
        self.gateway = gateway or get_gateway()
        self.client = client
        self.settings = get_settings()

    # --- helpers ----------------------------------------------------------
    def _completed(self, assignment_id: str, project_id: str) -> set[int]:
        return {
            a["stage"] for a in self.repo.list_stage_artifacts(assignment_id, project_id)
            if a["status"] in ("ok", "flagged", "blocked")
        }

    def _gate_approved(self, assignment_id: str, project_id: str) -> bool:
        approval = self.repo.latest_approval(assignment_id, project_id, "human_gate")
        return bool(approval and approval.get("decision") == "approved")

    def _egordian_state(self) -> dict[str, Any]:
        if self.client is None:
            return {"connected": False, "reason": "credential_required"}
        status = self.client.status()
        return {"connected": status["connected"],
                "reason": None if status["connected"] else "credential_required"}

    # --- public API -------------------------------------------------------
    def create_assignment(self, *, project_id: str, user_id: str, actor: str,
                          owner_id: str | None, job_order_id: str | None, title: str | None,
                          known_target_total: float | None, mode: str,
                          metadata: dict[str, Any], correlation_id: str) -> dict[str, Any]:
        record = self.repo.create_assignment({
            "project_id": project_id, "user_id": user_id, "owner_id": owner_id,
            "job_order_id": job_order_id, "title": title, "mode": mode,
            "known_target_total": known_target_total, "metadata": metadata,
        })
        self.repo.append_audit({
            "project_id": project_id, "user_id": user_id, "actor": actor,
            "action": "aeo.assignment.created", "correlation_id": correlation_id,
            "detail": {"assignment_id": record["assignment_id"], "mode": mode,
                       "job_order_id": job_order_id},
        })
        return {**record, "stage_machine": [s.to_dict() for s in STAGES],
                "versions": version_hashes(self.gateway)}

    def status(self, assignment_id: str, project_id: str) -> dict[str, Any]:
        assignment = self.repo.get_assignment(assignment_id, project_id)
        if assignment is None:
            raise KeyError(f"Unknown assignment {assignment_id}")
        artifacts = self.repo.list_stage_artifacts(assignment_id, project_id)
        completed = self._completed(assignment_id, project_id)
        pipeline = []
        for stage in STAGES:
            match = [a for a in artifacts if a["stage"] == stage.index]
            pipeline.append({
                **stage.to_dict(),
                "state": (match[-1]["status"] if match else
                          ("ready" if stage.index == min(
                              [s.index for s in STAGES if s.index not in completed] or [99])
                           else "pending")),
                "artifact_id": match[-1]["artifact_id"] if match else None,
                "version_hash": match[-1]["version_hash"] if match else None,
            })
        return {
            "assignment": assignment,
            "pipeline": pipeline,
            "completed_stages": sorted(completed),
            "human_gate_approved": self._gate_approved(assignment_id, project_id),
            "open_exceptions": len(self.repo.list_exceptions(project_id, assignment_id, "open")),
            "egordian": self._egordian_state(),
            "versions": version_hashes(self.gateway),
        }

    def manifest(self, assignment_id: str, project_id: str) -> dict[str, Any]:
        assignment = self.repo.get_assignment(assignment_id, project_id)
        if assignment is None:
            raise KeyError(f"Unknown assignment {assignment_id}")
        artifacts = self.repo.list_stage_artifacts(assignment_id, project_id)
        exceptions = self.repo.list_exceptions(project_id, assignment_id, "all", 500)
        approval = self.repo.latest_approval(assignment_id, project_id, "human_gate")
        evidence_spans = [span for a in artifacts for span in a.get("evidence", [])]
        body = {
            "manifest_schema": "aeo-run-manifest-1",
            "assignment": assignment,
            "versions": version_hashes(self.gateway),
            "stages": [{"stage": a["stage"], "stage_name": a["stage_name"], "tier": a["tier"],
                        "status": a["status"], "version_hash": a["version_hash"],
                        "created_at": a["created_at"]} for a in artifacts],
            "evidence_span_count": len(evidence_spans),
            "exceptions": {"open": len([e for e in exceptions if e["status"] == "open"]),
                           "total": len(exceptions)},
            "human_gate": approval or {"decision": "not_requested"},
            "capability_gaps": get_registry().capability_gaps(),
            "deliverable_rule": "No manifest, no deliverable.",
            "complete": bool(
                approval and approval.get("decision") == "approved"
                and not [e for e in exceptions if e["status"] == "open" and e["severity"] == "error"]
            ),
        }
        body["manifest_hash"] = _hash(body)
        return body

    def approve_gate(self, *, assignment_id: str, project_id: str, actor: str,
                     approval: dict[str, Any], decision: str, rationale: str,
                     idempotency_key: str, correlation_id: str) -> dict[str, Any]:
        assignment = self.repo.get_assignment(assignment_id, project_id)
        if assignment is None:
            raise KeyError(f"Unknown assignment {assignment_id}")
        completed = self._completed(assignment_id, project_id)
        if 6 not in completed:
            raise StateTransitionError(
                "The human gate can only be decided after stage 6 (self-check) completes.")
        record = self.repo.record_approval({
            "project_id": project_id, "assignment_id": assignment_id, "gate": "human_gate",
            "actor": actor, "decision": decision, "rationale": rationale,
            "idempotency_key": idempotency_key, "approval": approval,
        })
        stage = stage_for(7)
        artifact = _artifact(
            stage, "ok" if decision == "approved" else "flagged",
            {"decision": decision, "actor": actor, "rationale": rationale,
             "approval_id": record["approval_id"]},
            [{"kind": "approval", "ref": record["approval_id"], "actor": actor}],
            version_hashes(self.gateway))
        validate_artifact(artifact)
        self.repo.append_stage_artifact({
            "assignment_id": assignment_id, "project_id": project_id, "stage": 7,
            "stage_name": stage.name, "tier": stage.tier, "status": artifact["status"],
            "payload": artifact["payload"], "evidence": artifact["evidence"],
            "version_hash": artifact["version_hash"],
        })
        self.repo.update_assignment(assignment_id, project_id, stage=7,
                                    status="gate_" + decision)
        self.repo.append_audit({
            "project_id": project_id, "actor": actor, "action": "aeo.gate.decided",
            "correlation_id": correlation_id,
            "detail": {"assignment_id": assignment_id, "decision": decision},
        })
        return {"approval": record, "artifact": artifact}

    # --- stage execution --------------------------------------------------
    def run_stage(self, *, assignment_id: str, project_id: str, user_id: str, actor: str,
                  stage_ref: int | str, inputs: dict[str, Any],
                  correlation_id: str) -> dict[str, Any]:
        assignment = self.repo.get_assignment(assignment_id, project_id)
        if assignment is None:
            raise KeyError(f"Unknown assignment {assignment_id}")
        stage = stage_for(stage_ref)
        if stage.index == 7:
            raise GateRequired(
                "Stage 7 is a human gate; use aeo_approve_gate with a named actor and "
                "an approval envelope.")
        completed = self._completed(assignment_id, project_id)
        assert_can_run(int(assignment["stage"]), stage, completed=completed,
                       gate_approved=self._gate_approved(assignment_id, project_id))

        handler = getattr(self, f"_stage_{stage.index}")
        payload, evidence, status, exceptions = handler(assignment, inputs)

        artifact = _artifact(stage, status, payload, evidence, version_hashes(self.gateway))
        validate_artifact(artifact)
        stored = self.repo.append_stage_artifact({
            "assignment_id": assignment_id, "project_id": project_id, "stage": stage.index,
            "stage_name": stage.name, "tier": stage.tier, "status": status,
            "payload": minimize_for_storage(payload),
            "evidence": minimize_for_storage(evidence),
            "version_hash": artifact["version_hash"],
        })
        for exc in exceptions:
            self.repo.append_exception({
                "project_id": project_id, "assignment_id": assignment_id,
                "stage": stage.index, "severity": exc.get("severity", "warn"),
                "kind": exc["kind"], "detail": exc.get("detail", {}),
            })
        self.repo.update_assignment(assignment_id, project_id, stage=stage.index,
                                    status=f"stage_{stage.index}_{status}")
        self.repo.append_audit({
            "project_id": project_id, "user_id": user_id, "actor": actor,
            "action": "aeo.stage.executed", "correlation_id": correlation_id,
            "detail": {"assignment_id": assignment_id, "stage": stage.index,
                       "status": status, "version_hash": artifact["version_hash"],
                       "exceptions_filed": len(exceptions)},
        })
        return {"artifact": {**artifact, "artifact_id": stored["artifact_id"]},
                "exceptions_filed": len(exceptions),
                "next_stage": None if stage.index >= 8 else stage.index + 1}

    # --- individual stages ------------------------------------------------
    def _stage_0(self, assignment, inputs):
        eg = self._egordian_state()
        exceptions = []
        status = "ok"
        if not eg["connected"]:
            # Degraded but usable: the operator can still run in assisted mode with
            # supplied inputs. The gap is recorded as an exception, not a crash.
            status = "flagged"
            exceptions.append({"kind": "credential_required", "severity": "warn",
                               "detail": {"stage": 0,
                                          "message": "eGordian credentials are not configured; "
                                                     "assignment detection is offline."}})
        payload = {
            "detected": True,
            "egordian": eg,
            "sla_clock_started_at": assignment["created_at"],
            "job_order_id": assignment.get("job_order_id"),
            "owner_id": assignment.get("owner_id"),
            "auth_route": "GET api/AccessToken",
        }
        return payload, [{"kind": "control_plane", "ref": assignment["assignment_id"]}], status, exceptions

    def _stage_1(self, assignment, inputs):
        """Dossier assembly. Live reads only when credentials exist; otherwise a
        documented plan plus a credential_required exception - never a crash."""
        plan = [
            {"component": "job_order", "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId"},
            {"component": "detailed_scope",
             "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId_DetailedScope"},
            {"component": "files", "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Files"},
            {"component": "pictures", "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Pictures"},
            {"component": "notes", "operation_id": "get_v1_Users_by_userId_JobOrders_by_jobId_Notes"},
            {"component": "contacts", "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Contacts"},
            {"component": "tracking_dates",
             "operation_id": "get_v1_Owners_by_ownerId_JobOrders_by_jobId_TrackingDates"},
        ]
        registry = get_registry()
        for item in plan:
            op = registry.get(item["operation_id"])
            item["documented"] = op is not None
            item["route_template"] = op.route_template if op else None
            item["source_documentation_url"] = op.source_url if op else None
        supplied = inputs.get("dossier") or {}
        collected, exceptions = {}, []
        eg = self._egordian_state()
        for item in plan:
            key = item["component"]
            if key in supplied:
                collected[key] = {"source": "supplied", "records": supplied[key]}
            elif eg["connected"] and self.client is not None:
                try:
                    result = self.client.call(
                        item["operation_id"],
                        path_params=inputs.get("path_params", {}),
                        correlation_id=inputs.get("correlation_id", "cid_stage1"))
                    collected[key] = {"source": "egordian", "records": result.data}
                except EgordianError as exc:
                    exceptions.append({"kind": "egordian_read_failed", "severity": "warn",
                                       "detail": exc.to_dict()})
            else:
                exceptions.append({"kind": "credential_required", "severity": "warn",
                                   "detail": {"component": key,
                                              "operation_id": item["operation_id"]}})
        status = ("ok" if collected and not exceptions
                  else ("flagged" if collected else "needs_input"))
        payload = {"plan": plan, "collected_components": sorted(collected),
                   "dossier": collected, "provenance_stamped": True}
        evidence = [{"kind": "dossier_component", "ref": k,
                     "source": v["source"]} for k, v in collected.items()]
        return payload, evidence, status, exceptions

    def _stage_2(self, assignment, inputs):
        """Input gates: OCR score / scale / legend. Bad input is rejected."""
        documents = list(inputs.get("documents") or [])
        min_ocr = float(inputs.get("min_ocr_score", 0.85))
        accepted, rejected, evidence, exceptions = [], [], [], []
        for doc in documents:
            doc_id = str(doc.get("document_id") or doc.get("name") or "unknown")
            reasons = []
            score = doc.get("ocr_score")
            if score is None or float(score) < min_ocr:
                reasons.append("ocr_score_below_gate")
            if not doc.get("scale_verified"):
                reasons.append("scale_not_verified")
            if reasons:
                rejected.append({"document_id": doc_id, "reasons": reasons})
                exceptions.append({"kind": "input_gate_rejected", "severity": "error",
                                   "detail": {"document_id": doc_id, "reasons": reasons}})
            else:
                accepted.append({"document_id": doc_id, "ocr_score": float(score),
                                 "pages": doc.get("pages")})
                for fact in doc.get("facts", []):
                    evidence.append({"kind": "extracted_fact", "document_id": doc_id,
                                     "page": fact.get("page"), "span": fact.get("span"),
                                     "value": fact.get("value")})
        if not documents:
            exceptions.append({"kind": "no_documents_supplied", "severity": "warn",
                               "detail": {"message": "Stage 2 requires indexed documents."}})
        status = "ok" if accepted and not rejected else ("flagged" if accepted else "needs_input")
        payload = {"accepted_documents": accepted, "rejected_documents": rejected,
                   "min_ocr_score": min_ocr, "candidates_only": True,
                   "no_invented_lines": True}
        return payload, evidence, status, exceptions

    def _stage_3(self, assignment, inputs):
        """N-run consensus over supplied takeoff runs. Code decides, never averages away
        a disagreement."""
        items = list(inputs.get("quantities") or [])
        tolerance = float(inputs.get("tolerance_pct", 0.02))
        accepted, flagged, evidence, exceptions = [], [], [], []
        for item in items:
            runs = [float(r) for r in (item.get("runs") or []) if r is not None]
            name = str(item.get("scope_item") or "unnamed")
            if len(runs) < 2:
                exceptions.append({"kind": "insufficient_consensus_runs", "severity": "error",
                                   "detail": {"scope_item": name, "runs": len(runs)}})
                continue
            lo, hi = min(runs), max(runs)
            spread = (hi - lo) / hi if hi else 0.0
            median = sorted(runs)[len(runs) // 2]
            record = {"scope_item": name, "runs": runs, "n": len(runs),
                      "spread_pct": round(spread, 6), "consensus_value": median,
                      "unit": item.get("unit")}
            if spread <= tolerance:
                accepted.append({**record, "decision": "auto_accept"})
            else:
                flagged.append({**record, "decision": "exception_queue"})
                exceptions.append({"kind": "consensus_disagreement", "severity": "error",
                                   "detail": record})
            for span in item.get("evidence", []):
                evidence.append({"kind": "quantity_evidence", "scope_item": name, **span})
        status = "ok" if accepted and not flagged else ("flagged" if accepted else "needs_input")
        payload = {"accepted": accepted, "flagged": flagged, "tolerance_pct": tolerance,
                   "consensus_protocol": "N-run median with spread gate"}
        return payload, evidence, status, exceptions

    def _stage_4(self, assignment, inputs):
        """Crosswalk scope -> CTC catalogue. Only retrieved candidates may be proposed."""
        items = list(inputs.get("scope_items") or [])
        matched, unmatched, evidence, exceptions = [], [], [], []
        cost_authorized = bool(inputs.get("cost_authorized"))
        for item in items[: self.settings.catalogue_max_results]:
            term = str(item.get("description") or "").strip()
            code = item.get("catalogue_code")
            try:
                if code:
                    result = self.gateway.get(code, cost_authorized=cost_authorized)
                    hits = [result] if result.get("outcome") != "MISS" else []
                else:
                    hits = self.gateway.search(term, int(inputs.get("candidates_per_item", 5)),
                                               cost_authorized=cost_authorized)["results"]
            except LicenseViolation as exc:
                exceptions.append({"kind": "licensing_guard", "severity": "error",
                                   "detail": {"scope_item": term, "message": str(exc)}})
                continue
            if not hits:
                unmatched.append({"scope_item": term, "reason": "no_catalogue_candidate"})
                exceptions.append({"kind": "crosswalk_unmatched", "severity": "error",
                                   "detail": {"scope_item": term}})
                continue
            candidates = [{
                "line_code": h.get("line_code"),
                "code_normalized": h.get("code_normalized"),
                "unit": h.get("unit"),
                "description": h.get("description"),
                "edition": h.get("edition"),
                "evidence": h.get("evidence"),
            } for h in hits]
            matched.append({"scope_item": term, "candidates": candidates,
                            "selected": candidates[0]["line_code"],
                            "selection_rule": "top_deterministic_candidate_requires_human_confirm"})
            for cand in candidates:
                if cand.get("evidence"):
                    evidence.append({"kind": "catalogue_line", "line_code": cand["line_code"],
                                     "page": cand["evidence"].get("page"),
                                     "raw_line_hash": cand["evidence"].get("raw_line_hash"),
                                     "edition": cand.get("edition")})
        status = "ok" if matched and not unmatched else ("flagged" if matched else "needs_input")
        payload = {"matched": matched, "unmatched": unmatched,
                   "candidates_only": True,
                   "invariant": "no line may be proposed that is not retrieved from the "
                                "licensed catalogue"}
        return payload, evidence, status, exceptions

    def _stage_5(self, assignment, inputs):
        """Known-target reconciliation via the existing deterministic engine.

        This is explicitly NOT an estimate-from-scratch. The authorized target
        total is preserved unchanged (skill methodology).
        """
        request = dict(inputs.get("request") or {})
        target = assignment.get("known_target_total")
        budget = dict(request.get("known_budget") or {})
        if "target_total" not in budget and target is not None:
            budget["target_total"] = target
        request["known_budget"] = budget
        request.setdefault("project_id", assignment["project_id"])
        exceptions: list[dict[str, Any]] = []
        if "target_total" not in budget:
            return ({"error": "known_target_total_required",
                     "methodology": "known-target reconciliation, not estimate-from-scratch"},
                    [], "needs_input",
                    [{"kind": "missing_known_target", "severity": "error",
                      "detail": {"message": "A known approved target total is required."}}])
        profile = inputs.get("profile") or {}
        result = engine_reconcile(request, profile)
        for exc in (result.get("exception_queue") or []) + (result.get("exceptions") or []):
            exceptions.append({"kind": f"reconcile_{exc.get('type', 'exception')}",
                               "severity": "error", "detail": exc})
        for rejected in result.get("rejected_lines") or []:
            exceptions.append({"kind": "reconcile_line_rejected", "severity": "error",
                               "detail": rejected})
        evidence = [{"kind": "proposal_line", "record_id": line.get("record_id"),
                     "refs": line.get("evidence_refs")}
                    for line in (request.get("proposal_lines") or [])]
        status = "ok" if not exceptions else "flagged"
        payload = {"methodology": "known-target reconciliation (target total unchanged)",
                   "reconciliation": result,
                   "proposal_lines": list(request.get("proposal_lines") or []),
                   "estimate_from_scratch": False}
        return payload, evidence, status, exceptions

    def _stage_6(self, assignment, inputs):
        """Self-check and confidence tiering over the stage 5 artifact."""
        artifacts = self.repo.list_stage_artifacts(assignment["assignment_id"],
                                                   assignment["project_id"])
        stage5 = [a for a in artifacts if a["stage"] == 5]
        exceptions = []
        if not stage5:
            return ({"error": "stage_5_artifact_missing"}, [], "needs_input",
                    [{"kind": "missing_prerequisite_artifact", "severity": "error",
                      "detail": {"stage": 5}}])
        recon = stage5[-1]["payload"].get("reconciliation", {})
        lines = stage5[-1]["payload"].get("proposal_lines", []) or []
        checks = {
            "target_total_preserved": bool(recon.get("target_total_unchanged")),
            "no_rejected_lines": not recon.get("rejected_lines"),
            "cross_foot_balanced": recon.get("variance_band") in ("balanced", "warn"),
            "division_coverage_reported": "division_deficits_prioritized" in recon,
            "catalogue_codes_present": all(line.get("catalogue_code") for line in lines),
        }
        tiers = []
        for line in lines:
            has_math = bool(line.get("quantity_math"))
            has_ref = bool(line.get("evidence_refs") or line.get("source_ref"))
            tier = "high" if has_math and has_ref else ("medium" if has_ref else "low")
            tiers.append({"record_id": line.get("record_id"), "confidence": tier})
            if tier == "low":
                exceptions.append({"kind": "low_confidence_line", "severity": "warn",
                                   "detail": {"record_id": line.get("record_id")}})
        failed = [k for k, v in checks.items() if not v]
        for name in failed:
            exceptions.append({"kind": "self_check_failed", "severity": "error",
                               "detail": {"check": name}})
        status = "ok" if not failed and not exceptions else "flagged"
        payload = {"checks": checks, "failed_checks": failed, "confidence_tiers": tiers,
                   "review_share": round(len([t for t in tiers if t["confidence"] != "high"])
                                         / max(1, len(tiers)), 4),
                   "human_gate_required": True}
        return payload, [], status, exceptions

    def _stage_8(self, assignment, inputs):
        """Submit & log - permanently capability-blocked (no documented write route)."""
        gap = [g for g in get_registry().capability_gaps()
               if g["capability"] == "price_proposal_draft_or_submit"]
        packet = {
            "mode": "assisted",
            "submission_packet": {
                "assignment_id": assignment["assignment_id"],
                "job_order_id": assignment.get("job_order_id"),
                "owner_id": assignment.get("owner_id"),
                "instruction": ("A named human must file this proposal in eGordian. "
                                "This service will not perform the write."),
            },
            "capability_gap": gap[0] if gap else None,
            "documented_read_route": "GET v1/Owners/{ownerId}/PriceProposals",
            "source_documentation_url": "https://jocservice.egordian.com/Help",
        }
        exceptions = [{"kind": "write_capability_blocked", "severity": "warn",
                       "detail": {"stage": 8,
                                  "reason": "undocumented PriceProposalsV1 write route"}}]
        return packet, [], "blocked", exceptions
