"""MCP tool registry.

Tool order is deterministic: tools are always emitted sorted by name so that
``tools/list`` is byte-stable across replicas and restarts.

Every tool declares:
  * ``scopes``            - RBAC scopes required to call it
  * ``requires_handle``   - whether an opaque, user+project bound handle is needed
  * ``annotations``       - MCP hints (readOnlyHint / destructiveHint / idempotentHint)
  * ``side_effecting``    - if true, actor + approval envelope + idempotency key
                            are mandatory
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from gordian_ctc import crosswalk as ctc_crosswalk
from gordian_ctc import overlay as ctc_overlay
from gordian_ctc.catalogue import catalogue_info
from gordian_ctc.reconcile import persist_reconciliation
from gordian_ctc.reconcile import reconcile as engine_reconcile

from ..aeo.machine import STAGES, diagram
from ..aeo.runner import AEORunner, version_hashes
from ..catalogue_gateway import CatalogueGateway
from ..config import MCP_PROTOCOL_VERSION, Settings
from ..egordian.client import EgordianClient, EgordianError
from ..egordian.registry import get_registry
from ..repo.base import Repository
from ..security import Principal, fingerprint, validate_approval_envelope

HELP_URL = "https://jocservice.egordian.com/Help"


@dataclass
class ToolContext:
    principal: Principal
    repo: Repository
    gateway: CatalogueGateway
    client: EgordianClient
    settings: Settings
    correlation_id: str

    @property
    def runner(self) -> AEORunner:
        return AEORunner(self.repo, self.gateway, self.client)

    def bind(self, args: dict[str, Any]) -> str:
        """Validate the opaque handle and return the bound project_id."""
        project_id = str(args.get("project_id") or "")
        if not project_id:
            raise ValueError("project_id is required.")
        self.principal.require_project(project_id)
        self.repo.validate_handle(str(args.get("handle") or ""),
                                  self.principal.user_id, project_id)
        return project_id

    def envelope(self, args: dict[str, Any]) -> dict[str, Any]:
        env = validate_approval_envelope(args, self.principal)
        is_new, prior = self.repo.claim_idempotency_key(
            env["idempotency_key"], self.principal.user_id, fingerprint(args))
        env["idempotent_replay"] = not is_new
        env["prior_result"] = prior
        return env

    def audit(self, action: str, project_id: str | None, detail: dict[str, Any],
              actor: str | None = None) -> None:
        self.repo.append_audit({
            "project_id": project_id, "user_id": self.principal.user_id, "actor": actor,
            "action": action, "correlation_id": self.correlation_id, "detail": detail,
        })


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[ToolContext, dict[str, Any]], Any]
    scopes: tuple[str, ...] = ()
    requires_handle: bool = True
    side_effecting: bool = False
    destructive: bool = False
    idempotent: bool = True
    category: str = "core"

    def descriptor(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": not self.side_effecting,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.category in ("egordian", "aeo"),
            },
            "_meta": {
                "category": self.category,
                "requiredScopes": list(self.scopes),
                "requiresHandle": self.requires_handle,
                "sideEffecting": self.side_effecting,
                "requiresApprovalEnvelope": self.side_effecting,
                "protocolVersion": MCP_PROTOCOL_VERSION,
            },
        }


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def _schema(properties: dict[str, Any], required: list[str],
            *, handle: bool = True, write: bool = False) -> dict[str, Any]:
    props: dict[str, Any] = {}
    req = list(required)
    if handle:
        props["handle"] = {"type": "string", "minLength": 32,
                           "description": "Opaque, user- and project-bound expiring handle."}
        props["project_id"] = {"type": "string", "minLength": 1}
        req = ["handle", "project_id"] + req
    if write:
        props["actor"] = {"type": "string", "minLength": 1,
                          "description": "Named human accountable for this action."}
        props["approval"] = {
            "type": "object",
            "properties": {
                "approved": {"type": "boolean"},
                "actor": {"type": "string"},
                "rationale": {"type": "string"},
                "approved_at": {"type": "string"},
            },
            "required": ["approved", "actor", "rationale", "approved_at"],
        }
        props["idempotency_key"] = {"type": "string", "minLength": 8}
        req = req + ["actor", "approval", "idempotency_key"]
    props.update(properties)
    return {"type": "object", "properties": props, "required": req,
            "additionalProperties": False}


# ---------------------------------------------------------------------------
# Handlers - system & handles
# ---------------------------------------------------------------------------

def _h_system_status(ctx: ToolContext, args: dict[str, Any]) -> Any:
    registry = get_registry()
    return {
        "service": "egordian-aeo-mcp",
        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
        "stateless": True,
        "principal": ctx.principal.public(),
        "repository": {"backend": ctx.repo.backend, **ctx.repo.health()},
        "catalogue": ctx.gateway.status(),
        "egordian": ctx.client.status(),
        "operation_registry": registry.validate(),
        "aeo_stages": len(STAGES),
        "versions": version_hashes(ctx.gateway),
    }


def _h_handle_create(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_ids = [str(p) for p in (args.get("project_ids") or [])]
    for pid in project_ids:
        ctx.principal.require_project(pid)
    ttl = int(args.get("ttl_hours", ctx.settings.handle_ttl_hours))
    # Mirror the project into the engine overlay so learning writes stay FK-valid.
    ctc_overlay.init_overlay(ctx.settings.overlay_db_path)
    for pid in project_ids:
        try:
            ctc_overlay.create_project(ctx.settings.overlay_db_path, pid,
                                       args.get("owner_contract", "private-licensed"),
                                       ctx.principal.user_id)
        except Exception:
            pass  # already present
    result = ctx.repo.create_handle(ctx.principal.user_id, project_ids, ttl)
    ctx.audit("handle.created", project_ids[0] if project_ids else None,
              {"project_ids": project_ids, "ttl_hours": ttl})
    return result


def _h_engine_manifest(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return {
        "project_id": project_id,
        "catalogue": ctx.gateway.info(),
        "overlay": ctc_overlay.overlay_manifest(ctx.settings.overlay_db_path),
        "control_plane": ctx.repo.counts(),
        "versions": version_hashes(ctx.gateway),
        "operation_registry": get_registry().validate(),
    }


# ---------------------------------------------------------------------------
# Handlers - catalogue
# ---------------------------------------------------------------------------

def _cost_authorized(ctx: ToolContext, args: dict[str, Any]) -> bool:
    return bool(args.get("include_costs")) and ctx.principal.has("catalogue:read")


def _h_catalogue_info(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return ctx.gateway.info()


def _h_catalogue_search(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    result = ctx.gateway.search(str(args.get("query", "")), args.get("limit", 20),
                                cost_authorized=_cost_authorized(ctx, args),
                                public_safe=bool(args.get("public_safe")))
    prior = ctc_overlay.search_prior_knowledge(ctx.settings.overlay_db_path, project_id,
                                               str(args.get("query", "")), 10)
    return {"project_id": project_id, "prior_knowledge": prior, **result}


def _h_catalogue_get(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return ctx.gateway.get(str(args.get("code", "")),
                           include_modifiers=bool(args.get("include_modifiers", True)),
                           cost_authorized=_cost_authorized(ctx, args),
                           public_safe=bool(args.get("public_safe")))


def _h_catalogue_browse(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return ctx.gateway.browse(str(args.get("prefix", "")),
                              cost_authorized=_cost_authorized(ctx, args),
                              public_safe=bool(args.get("public_safe")))


def _h_crosswalk_translate(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return ctc_crosswalk.translate(ctx.settings.overlay_db_path, project_id,
                                   args["system"], args["code_or_alias"],
                                   args.get("target_system"))


def _h_reconcile(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    request = dict(args["request"])
    request.setdefault("project_id", project_id)
    if request.get("project_id") != project_id:
        raise PermissionError("request.project_id must match the authorized project.")
    result = engine_reconcile(request, args.get("profile") or {})
    run = persist_reconciliation(ctx.settings.overlay_db_path, request, result,
                                 env["actor"], True)
    ctx.audit("engine.reconcile", project_id, {"run": run.get("run_id"),
                                               "idempotent_replay": env["idempotent_replay"]},
              actor=env["actor"])
    return {**result, "run": run, "idempotent_replay": env["idempotent_replay"]}


# ---------------------------------------------------------------------------
# Handlers - learning / overlay knowledge
# ---------------------------------------------------------------------------

def _h_lessons(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return {"project_id": project_id,
            "results": ctc_overlay.lessons(ctx.settings.overlay_db_path, project_id,
                                           args.get("query", ""), int(args.get("limit", 20)))}


def _h_big_notes(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return {"project_id": project_id,
            **ctc_overlay.search_prior_knowledge(ctx.settings.overlay_db_path, project_id,
                                                 args.get("query", ""), int(args.get("limit", 20)))}


def _h_big_note_add(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.record_big_note(ctx.settings.overlay_db_path, project_id, args["title"],
                                       args["body"], args["provenance"], env["actor"], True)


def _h_external_line_observe(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.record_observed_external_line(
        ctx.settings.overlay_db_path, project_id, args["source_system"], args["edition"],
        args["code_or_opaque_id"], args["observed_date"], args["screen_page_provenance"],
        env["actor"], True)


def _h_external_line_verify(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.verify_observed_external_line(
        ctx.settings.overlay_db_path, project_id, args["observation_id"],
        args["verification_status"], args["rationale"], env["actor"], True)


def _h_external_lines_list(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return {"project_id": project_id,
            "results": ctc_overlay.observed_external_lines(ctx.settings.overlay_db_path,
                                                           project_id, int(args.get("limit", 50)))}


def _h_change_order_log(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.record_change_order(ctx.settings.overlay_db_path, project_id,
                                           args["status"], args.get("payload", {}),
                                           env["actor"], True)


def _h_proposal_delta(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.record_proposal_final_delta(
        ctx.settings.overlay_db_path, project_id, args["initial_proposal"],
        args["accepted_final"], args["delta"], args["acceptance_status"], env["actor"], True)


def _h_improvement_propose(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.propose_improvement(ctx.settings.overlay_db_path, project_id,
                                           args.get("payload", {}), env["actor"], True,
                                           args.get("proposal_delta_id"))


def _h_improvement_decide(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.decide_improvement(ctx.settings.overlay_db_path, project_id,
                                          args["candidate_id"], args["status"],
                                          args["rationale"], env["actor"], True)


def _h_review_queue(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    con = ctc_overlay.connect(ctx.settings.overlay_db_path)
    try:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM review_queue WHERE project_id=? AND status='open' ORDER BY created_at",
            (project_id,))]
    finally:
        con.close()
    return {"project_id": project_id, "results": rows}


def _h_learning_propose(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return ctc_overlay.append_learning(ctx.settings.overlay_db_path, project_id, "proposal",
                                       args["subject_type"], args["subject_id"],
                                       args.get("payload", {}), args["actor"], False)


def _h_learning_approve(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    cfg = args.get("stable_threshold", {}) or {}
    return ctc_overlay.promote_learning(
        ctx.settings.overlay_db_path, project_id, args["subject_type"], args["subject_id"],
        args.get("payload", {}), env["actor"], True,
        min_cross_project_evidence=int(cfg.get("min_cross_project_evidence", 3)),
        min_distinct_projects=int(cfg.get("min_distinct_projects", 2)))


def _h_learning_reject(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctc_overlay.append_learning(
        ctx.settings.overlay_db_path, project_id, "human_decision", args["subject_type"],
        args["subject_id"], {"decision": "rejected", **args.get("payload", {})},
        env["actor"], True, args.get("related_event_id"))


# ---------------------------------------------------------------------------
# Handlers - AEO
# ---------------------------------------------------------------------------

def _h_aeo_create(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctx.runner.create_assignment(
        project_id=project_id, user_id=ctx.principal.user_id, actor=env["actor"],
        owner_id=args.get("owner_id"), job_order_id=args.get("job_order_id"),
        title=args.get("title"), known_target_total=args.get("known_target_total"),
        mode=args.get("mode", "assisted"), metadata=args.get("metadata", {}),
        correlation_id=ctx.correlation_id)


def _h_aeo_run_stage(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    return ctx.runner.run_stage(
        assignment_id=args["assignment_id"], project_id=project_id,
        user_id=ctx.principal.user_id, actor=env["actor"], stage_ref=args["stage"],
        inputs=args.get("inputs", {}), correlation_id=ctx.correlation_id)


def _h_aeo_status(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return ctx.runner.status(args["assignment_id"], project_id)


def _h_aeo_exceptions(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return {"project_id": project_id,
            "results": ctx.repo.list_exceptions(project_id, args.get("assignment_id"),
                                                args.get("status", "open"),
                                                int(args.get("limit", 100)))}


def _h_aeo_approve_gate(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    env = ctx.envelope(args)
    decision = args.get("decision", "approved")
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'.")
    return ctx.runner.approve_gate(
        assignment_id=args["assignment_id"], project_id=project_id, actor=env["actor"],
        approval=env["approval"], decision=decision,
        rationale=args.get("rationale", env["approval"].get("rationale", "")),
        idempotency_key=env["idempotency_key"], correlation_id=ctx.correlation_id)


def _h_aeo_manifest(ctx: ToolContext, args: dict[str, Any]) -> Any:
    project_id = ctx.bind(args)
    return ctx.runner.manifest(args["assignment_id"], project_id)


# ---------------------------------------------------------------------------
# Handlers - eGordian
# ---------------------------------------------------------------------------

def _h_egordian_status(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return ctx.client.status()


def _h_egordian_operations(ctx: ToolContext, args: dict[str, Any]) -> Any:
    registry = get_registry()
    section = args.get("section")
    risk = args.get("risk")
    ops = [op.to_dict() for op in registry.all()
           if (not section or op.section == section) and (not risk or op.risk == risk)]
    return {"source_documentation_url": HELP_URL,
            "fixture_sha256": registry.fixture_sha256,
            "sections": registry.sections(),
            "counts": registry.counts(),
            "capability_gaps": registry.capability_gaps(),
            "operations": ops}


def _egordian_read(ctx: ToolContext, operation_id: str, path_params: dict[str, Any],
                   query: dict[str, Any] | None = None) -> Any:
    try:
        result = ctx.client.call(operation_id, path_params=path_params, query=query or {},
                                 correlation_id=ctx.correlation_id,
                                 has_write_scope=ctx.principal.has("egordian:write"),
                                 has_admin_scope=ctx.principal.has("admin"))
        return result.to_dict()
    except EgordianError as exc:
        return {"ok": False, **exc.to_dict(ctx.correlation_id)}


def _h_egordian_call(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    registry = get_registry()
    operation_id = str(args.get("operation_id", ""))
    operation = registry.get(operation_id)
    if operation is None:
        return {"ok": False, "error": "operation_not_allowlisted",
                "message": f"{operation_id!r} is not a documented eGordian operation.",
                "source_documentation_url": HELP_URL}
    envelope = None
    if operation.risk == "write":
        envelope = ctx.envelope(args)
        ctx.audit("egordian.write.attempt", args.get("project_id"),
                  {"operation_id": operation_id}, actor=envelope["actor"])
    try:
        result = ctx.client.call(
            operation_id, path_params=args.get("path_params", {}),
            query=args.get("query", {}), body=args.get("body"),
            correlation_id=ctx.correlation_id, envelope=envelope,
            has_write_scope=ctx.principal.has("egordian:write"),
            has_admin_scope=ctx.principal.has("admin"))
        return result.to_dict()
    except EgordianError as exc:
        return {"ok": False, **exc.to_dict(ctx.correlation_id)}


def _h_eg_assignments(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    op = ("get_v1_Owners_by_ownerId_JobOrders" if args.get("owner_id")
          else "get_v1_JobOrders")
    params = {"ownerId": args["owner_id"]} if args.get("owner_id") else {}
    return _egordian_read(ctx, op, params, {"searchTerm": args.get("search_term")})


def _h_eg_job_order(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_scope(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId_DetailedScope",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_files(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Files",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_pictures(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Pictures",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_notes(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Users_by_userId_JobOrders_by_jobId_Notes",
                          {"userId": args["user_id"], "jobId": args["job_id"]})


def _h_eg_contacts(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId_Contacts",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_tracking(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_JobOrders_by_jobId_TrackingDates",
                          {"ownerId": args["owner_id"], "jobId": args["job_id"]})


def _h_eg_catalogs(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_Catalogs", {"ownerId": args["owner_id"]})


def _h_eg_categories(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_Category_by_catalogId",
                          {"ownerId": args["owner_id"], "catalogId": args["catalog_id"]})


def _h_eg_task_data(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    return _egordian_read(ctx, "get_v1_Owners_by_ownerId_TaskData_by_catalogId_by_hierachyCode",
                          {"ownerId": args["owner_id"], "catalogId": args["catalog_id"],
                           "hierachyCode": args["hierarchy_code"]},
                          {"searchTerm": args.get("search_term")})


def _h_eg_price_proposals(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    out = _egordian_read(ctx, "get_v1_Owners_by_ownerId_PriceProposals",
                         {"ownerId": args["owner_id"]})
    out["capability_note"] = (
        "Only GET v1/Owners/{ownerId}/PriceProposals is documented. Draft and submit "
        "routes are not published, so this service cannot write a price proposal.")
    return out


def _h_eg_dossier(ctx: ToolContext, args: dict[str, Any]) -> Any:
    """Assemble the read-only intake dossier from the documented GET routes."""
    ctx.bind(args)
    owner_id, job_id = args["owner_id"], args["job_id"]
    user_id = args.get("user_id")
    plan = {
        "job_order": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId",
                      {"ownerId": owner_id, "jobId": job_id}),
        "detailed_scope": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId_DetailedScope",
                           {"ownerId": owner_id, "jobId": job_id}),
        "files": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId_Files",
                  {"ownerId": owner_id, "jobId": job_id}),
        "pictures": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId_Pictures",
                     {"ownerId": owner_id, "jobId": job_id}),
        "contacts": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId_Contacts",
                     {"ownerId": owner_id, "jobId": job_id}),
        "tracking_dates": ("get_v1_Owners_by_ownerId_JobOrders_by_jobId_TrackingDates",
                           {"ownerId": owner_id, "jobId": job_id}),
    }
    if user_id:
        plan["notes"] = ("get_v1_Users_by_userId_JobOrders_by_jobId_Notes",
                         {"userId": user_id, "jobId": job_id})
    components = {key: _egordian_read(ctx, op, params) for key, (op, params) in plan.items()}
    return {"owner_id": owner_id, "job_id": job_id, "components": components,
            "provenance": {"source_documentation_url": HELP_URL,
                           "correlation_id": ctx.correlation_id}}


def _h_eg_note_create(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    env = ctx.envelope(args)
    ctx.audit("egordian.note.create.attempt", args.get("project_id"),
              {"job_id": args.get("job_id")}, actor=env["actor"])
    try:
        result = ctx.client.call(
            "post_v1_Users_by_userId_JobOrders_by_jobId_Notes",
            path_params={"userId": args["user_id"], "jobId": args["job_id"]},
            body=args["note"], correlation_id=ctx.correlation_id, envelope=env,
            has_write_scope=ctx.principal.has("egordian:write"),
            has_admin_scope=ctx.principal.has("admin"))
        return result.to_dict()
    except EgordianError as exc:
        return {"ok": False, **exc.to_dict(ctx.correlation_id)}


def _h_eg_tracking_update(ctx: ToolContext, args: dict[str, Any]) -> Any:
    ctx.bind(args)
    env = ctx.envelope(args)
    try:
        result = ctx.client.call(
            "put_v1_Owners_by_ownerId_JobOrders_by_jobId_TrackingDates_by_trackingDateId",
            path_params={"ownerId": args["owner_id"], "jobId": args["job_id"],
                         "trackingDateId": args["tracking_date_id"]},
            body=args["value"], correlation_id=ctx.correlation_id, envelope=env,
            has_write_scope=ctx.principal.has("egordian:write"),
            has_admin_scope=ctx.principal.has("admin"))
        return result.to_dict()
    except EgordianError as exc:
        return {"ok": False, **exc.to_dict(ctx.correlation_id)}


def _h_eg_price_proposal_submit(ctx: ToolContext, args: dict[str, Any]) -> Any:
    """Explicit capability-gap surface. Always blocked - never attempts a call."""
    ctx.bind(args)
    gap = [g for g in get_registry().capability_gaps()
           if g["capability"] == "price_proposal_draft_or_submit"]
    ctx.audit("egordian.price_proposal.blocked", args.get("project_id"),
              {"reason": "undocumented_write_route"})
    return {
        "ok": False,
        "error": "capability_not_documented",
        "message": ("The eGordian Help page documents no PriceProposalsV1 draft or submit "
                    "route. This service refuses to invent one. Produce the assisted "
                    "submission packet with aeo_run_stage(stage=8) and have a named human "
                    "file it."),
        "capability_gap": gap[0] if gap else None,
        "source_documentation_url": HELP_URL,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_TOOLS: list[Tool] = [
    Tool("system_status", "Service status",
         "Health, catalogue edition/counts, eGordian connectivity, registry integrity and "
         "version hashes. Never returns secrets.",
         _schema({}, [], handle=False), _h_system_status, (), requires_handle=False,
         category="system"),
    Tool("handle_create", "Create an opaque project handle",
         "Mint an opaque, user-bound, project-bound, expiring handle. Every other tool "
         "validates this handle on every call. Auth is never stored in a protocol session.",
         _schema({"project_ids": {"type": "array", "items": {"type": "string"}},
                  "ttl_hours": {"type": "integer", "minimum": 1, "maximum": 24},
                  "owner_contract": {"type": "string"}},
                 ["project_ids"], handle=False),
         _h_handle_create, (), requires_handle=False, category="system"),
    Tool("engine_manifest", "Engine + control-plane manifest",
         "Catalogue provenance, overlay manifest, control-plane counts and version hashes.",
         _schema({}, []), _h_engine_manifest, ("catalogue:read",), category="system"),

    Tool("catalogue_info", "Catalogue edition and counts",
         "Edition, owner, provenance checksums and row counts for the licensed CTC catalogue. "
         "No catalogue content is returned.",
         _schema({}, []), _h_catalogue_info, ("catalogue:read",), category="catalogue"),
    Tool("catalogue_search", "Search CTC lines",
         "Bounded lexical search over the authorized catalogue with page-level evidence. "
         "Result counts are capped and cost fields are redacted without authorization.",
         _schema({"query": {"type": "string", "minLength": 2},
                  "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                  "include_costs": {"type": "boolean"},
                  "public_safe": {"type": "boolean"}}, ["query"]),
         _h_catalogue_search, ("catalogue:read",), category="catalogue"),
    Tool("catalogue_get", "Get one CTC line",
         "Exact line lookup with provenance, edition and optional modifiers.",
         _schema({"code": {"type": "string"},
                  "include_modifiers": {"type": "boolean"},
                  "include_costs": {"type": "boolean"},
                  "public_safe": {"type": "boolean"}}, ["code"]),
         _h_catalogue_get, ("catalogue:read",), category="catalogue"),
    Tool("catalogue_browse", "Browse CTC hierarchy",
         "Browse a CSI/MasterFormat prefix. Whole-catalogue browsing is refused.",
         _schema({"prefix": {"type": "string", "minLength": 2},
                  "include_costs": {"type": "boolean"},
                  "public_safe": {"type": "boolean"}}, ["prefix"]),
         _h_catalogue_browse, ("catalogue:read",), category="catalogue"),
    Tool("crosswalk_translate", "Translate between coding systems",
         "CTC / CSI / RSMeans opaque-ID crosswalk using approved overlay edges.",
         _schema({"system": {"type": "string"}, "code_or_alias": {"type": "string"},
                  "target_system": {"type": "string"}}, ["system", "code_or_alias"]),
         _h_crosswalk_translate, ("catalogue:read",), category="catalogue"),
    Tool("reconcile_known_target", "Known-target reconciliation",
         "Deterministic reconciliation of proposal lines to an unchanged approved target "
         "total. Estimator-assumption draft; requires actor + approval + idempotency key.",
         _schema({"request": {"type": "object"}, "profile": {"type": "object"}},
                 ["request"], write=True),
         _h_reconcile, ("catalogue:read", "aeo:run"), side_effecting=True, category="engine"),

    Tool("lessons_search", "Search project lessons",
         "Search human-promoted lessons for the project before proposing any line.",
         _schema({"query": {"type": "string"}, "limit": {"type": "integer"}}, []),
         _h_lessons, ("catalogue:read",), category="learning"),
    Tool("big_notes_search", "Search big notes / prior knowledge",
         "Search prior project knowledge captured as big notes.",
         _schema({"query": {"type": "string"}, "limit": {"type": "integer"}}, []),
         _h_big_notes, ("catalogue:read",), category="learning"),
    Tool("big_note_add", "Add a big note",
         "Append a provenance-stamped big note. Requires actor + approval + idempotency key.",
         _schema({"title": {"type": "string"}, "body": {"type": "string"},
                  "provenance": {"type": "object"}},
                 ["title", "body", "provenance"], write=True),
         _h_big_note_add, ("aeo:run",), side_effecting=True, category="learning"),
    Tool("external_line_observe", "Record an observed external line",
         "Record a human-observed external catalogue line with screen/page provenance. "
         "Never used for automated retrieval or mining.",
         _schema({"source_system": {"type": "string"}, "edition": {"type": "string"},
                  "code_or_opaque_id": {"type": "string"}, "observed_date": {"type": "string"},
                  "screen_page_provenance": {"type": "object"}},
                 ["source_system", "edition", "code_or_opaque_id", "observed_date",
                  "screen_page_provenance"], write=True),
         _h_external_line_observe, ("aeo:run",), side_effecting=True, category="learning"),
    Tool("external_line_verify", "Verify an observed external line",
         "Human verification decision for a previously observed external line.",
         _schema({"observation_id": {"type": "string"},
                  "verification_status": {"type": "string"},
                  "rationale": {"type": "string"}},
                 ["observation_id", "verification_status", "rationale"], write=True),
         _h_external_line_verify, ("aeo:approve",), side_effecting=True, category="learning"),
    Tool("external_lines_list", "List observed external lines",
         "List external-line observations recorded for the project.",
         _schema({"limit": {"type": "integer"}}, []),
         _h_external_lines_list, ("catalogue:read",), category="learning"),
    Tool("change_order_log", "Log a change order",
         "Append a change-order record to the project overlay.",
         _schema({"status": {"type": "string"}, "payload": {"type": "object"}},
                 ["status"], write=True),
         _h_change_order_log, ("aeo:run",), side_effecting=True, category="learning"),
    Tool("proposal_delta_record", "Record initial-vs-accepted delta",
         "Record the delta between the initial proposal and the accepted final for learning.",
         _schema({"initial_proposal": {"type": "object"}, "accepted_final": {"type": "object"},
                  "delta": {"type": "object"}, "acceptance_status": {"type": "string"}},
                 ["initial_proposal", "accepted_final", "delta", "acceptance_status"], write=True),
         _h_proposal_delta, ("aeo:run",), side_effecting=True, category="learning"),
    Tool("improvement_propose", "Propose a process improvement",
         "Propose an inert improvement candidate; it does nothing until a human accepts it.",
         _schema({"payload": {"type": "object"}, "proposal_delta_id": {"type": "string"}},
                 ["payload"], write=True),
         _h_improvement_propose, ("aeo:run",), side_effecting=True, category="learning"),
    Tool("improvement_decide", "Decide an improvement candidate",
         "Named-human accept/reject decision on an improvement candidate.",
         _schema({"candidate_id": {"type": "string"}, "status": {"type": "string"},
                  "rationale": {"type": "string"}},
                 ["candidate_id", "status", "rationale"], write=True),
         _h_improvement_decide, ("aeo:approve",), side_effecting=True, category="learning"),
    Tool("review_queue", "Open human review queue",
         "List open human-review items for the project.",
         _schema({}, []), _h_review_queue, ("catalogue:read",), category="learning"),
    Tool("learning_propose", "Propose a learning event",
         "Append an inert learning proposal (approval is a separate human action).",
         _schema({"subject_type": {"type": "string"}, "subject_id": {"type": "string"},
                  "payload": {"type": "object"}, "actor": {"type": "string"}},
                 ["subject_type", "subject_id", "actor"]),
         _h_learning_propose, ("aeo:run",), category="learning"),
    Tool("learning_approve", "Promote a learning event",
         "Promote a learning proposal once the cross-project threshold is met.",
         _schema({"subject_type": {"type": "string"}, "subject_id": {"type": "string"},
                  "payload": {"type": "object"}, "stable_threshold": {"type": "object"}},
                 ["subject_type", "subject_id"], write=True),
         _h_learning_approve, ("aeo:approve",), side_effecting=True, category="learning"),
    Tool("learning_reject", "Reject a learning event",
         "Record a named-human rejection of a learning proposal.",
         _schema({"subject_type": {"type": "string"}, "subject_id": {"type": "string"},
                  "payload": {"type": "object"}, "related_event_id": {"type": "string"}},
                 ["subject_type", "subject_id"], write=True),
         _h_learning_reject, ("aeo:approve",), side_effecting=True, category="learning"),

    Tool("aeo_create_assignment", "Create an AEO assignment",
         "Open a new Assignment Estimate Operator run with a pinned version manifest.",
         _schema({"owner_id": {"type": "string"}, "job_order_id": {"type": "string"},
                  "title": {"type": "string"},
                  "known_target_total": {"type": "number"},
                  "mode": {"type": "string", "enum": ["assisted", "gated_auto"]},
                  "metadata": {"type": "object"}}, [], write=True),
         _h_aeo_create, ("aeo:run",), side_effecting=True, category="aeo"),
    Tool("aeo_run_stage", "Run one AEO stage",
         "Execute a single deterministic stage (0-6, 8). Stage 7 is the human gate and uses "
         "aeo_approve_gate. Code owns the state transition; a stage never advances itself.",
         _schema({"assignment_id": {"type": "string"},
                  "stage": {"type": ["integer", "string"]},
                  "inputs": {"type": "object"}},
                 ["assignment_id", "stage"], write=True),
         _h_aeo_run_stage, ("aeo:run",), side_effecting=True, category="aeo"),
    Tool("aeo_status", "AEO pipeline status",
         "Pipeline state, per-stage artifacts, gate state, exception count and versions.",
         _schema({"assignment_id": {"type": "string"}}, ["assignment_id"]),
         _h_aeo_status, ("aeo:run",), category="aeo"),
    Tool("aeo_exception_queue", "AEO exception queue",
         "The flagged 5-10%: consensus disagreements, rejected inputs, unmatched crosswalks.",
         _schema({"assignment_id": {"type": "string"},
                  "status": {"type": "string", "enum": ["open", "resolved", "all"]},
                  "limit": {"type": "integer"}}, []),
         _h_aeo_exceptions, ("aeo:run",), category="aeo"),
    Tool("aeo_approve_gate", "Decide the human gate",
         "Named-human stage 7 decision. Mandatory before any dollar commitment.",
         _schema({"assignment_id": {"type": "string"},
                  "decision": {"type": "string", "enum": ["approved", "rejected"]},
                  "rationale": {"type": "string"}},
                 ["assignment_id", "decision"], write=True),
         _h_aeo_approve_gate, ("aeo:approve",), side_effecting=True, category="aeo"),
    Tool("aeo_manifest", "AEO run manifest",
         "The run manifest: versions, gates, evidence counts, exceptions. "
         "No manifest, no deliverable.",
         _schema({"assignment_id": {"type": "string"}}, ["assignment_id"]),
         _h_aeo_manifest, ("aeo:run",), category="aeo"),

    Tool("egordian_status", "eGordian connectivity and capabilities",
         "Connection state, auth provider (names only), enabled verbs and capability gaps.",
         _schema({}, [], handle=False), _h_egordian_status, (), requires_handle=False,
         category="egordian"),
    Tool("egordian_operations", "Documented eGordian operation registry",
         "The exact allowlist parsed from the eGordian Help page: method, templated route, "
         "parameters, risk level and source documentation URL.",
         _schema({"section": {"type": "string"}, "risk": {"type": "string"}}, [], handle=False),
         _h_egordian_operations, (), requires_handle=False, category="egordian"),
    Tool("egordian_call", "Schema-constrained eGordian call",
         "Call any allowlisted documented operation. Reads need egordian:read; PUT/POST need "
         "egordian:write plus actor + approval + idempotency key; DELETE always returns "
         "human_gate_required; admin routes are disabled by default.",
         {"type": "object",
          "properties": {
              "handle": {"type": "string", "minLength": 32},
              "project_id": {"type": "string"},
              "operation_id": {"type": "string"},
              "path_params": {"type": "object"},
              "query": {"type": "object"},
              "body": {},
              "actor": {"type": "string"},
              "approval": {"type": "object"},
              "idempotency_key": {"type": "string"},
          },
          "required": ["handle", "project_id", "operation_id"],
          "additionalProperties": False},
         _h_egordian_call, ("egordian:read",), side_effecting=True, idempotent=False,
         category="egordian"),
    Tool("egordian_assignments_discover", "Discover job orders",
         "List job orders visible to the owner or user (assignment discovery).",
         _schema({"owner_id": {"type": "string"}, "search_term": {"type": "string"}}, []),
         _h_eg_assignments, ("egordian:read",), category="egordian"),
    Tool("egordian_job_order_detail", "Job order detail",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_job_order, ("egordian:read",), category="egordian"),
    Tool("egordian_job_scope", "Detailed scope of work",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}/DetailedScope",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_scope, ("egordian:read",), category="egordian"),
    Tool("egordian_files_list", "Job order files",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}/Files (metadata only; no binary download).",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_files, ("egordian:read",), category="egordian"),
    Tool("egordian_pictures_list", "Job order pictures",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures (metadata only).",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_pictures, ("egordian:read",), category="egordian"),
    Tool("egordian_notes_list", "Job order notes",
         "GET v1/Users/{userId}/JobOrders/{jobId}/Notes",
         _schema({"user_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["user_id", "job_id"]),
         _h_eg_notes, ("egordian:read",), category="egordian"),
    Tool("egordian_contacts_list", "Job order contacts",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_contacts, ("egordian:read",), category="egordian"),
    Tool("egordian_tracking_dates", "Job order tracking dates",
         "GET v1/Owners/{ownerId}/JobOrders/{jobId}/TrackingDates (the SLA clock).",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"}},
                 ["owner_id", "job_id"]),
         _h_eg_tracking, ("egordian:read",), category="egordian"),
    Tool("egordian_catalogs_list", "Owner catalogs",
         "GET v1/Owners/{ownerId}/Catalogs",
         _schema({"owner_id": {"type": "string"}}, ["owner_id"]),
         _h_eg_catalogs, ("egordian:read",), category="egordian"),
    Tool("egordian_categories", "Catalog categories",
         "GET v1/Owners/{ownerId}/Category/{catalogId}",
         _schema({"owner_id": {"type": "string"}, "catalog_id": {"type": "string"}},
                 ["owner_id", "catalog_id"]),
         _h_eg_categories, ("egordian:read",), category="egordian"),
    Tool("egordian_task_data", "Catalog task data",
         "GET v1/Owners/{ownerId}/TaskData/{catalogId}/{hierachyCode}?searchTerm=",
         _schema({"owner_id": {"type": "string"}, "catalog_id": {"type": "string"},
                  "hierarchy_code": {"type": "string"}, "search_term": {"type": "string"}},
                 ["owner_id", "catalog_id", "hierarchy_code"]),
         _h_eg_task_data, ("egordian:read",), category="egordian"),
    Tool("egordian_price_proposals_list", "List price proposals",
         "GET v1/Owners/{ownerId}/PriceProposals - the only documented PriceProposalsV1 route.",
         _schema({"owner_id": {"type": "string"}}, ["owner_id"]),
         _h_eg_price_proposals, ("egordian:read",), category="egordian"),
    Tool("egordian_dossier_assemble", "Assemble the intake dossier",
         "One call that pulls job order, scope, files, pictures, contacts, tracking dates and "
         "(optionally) notes into a single provenance-stamped dossier.",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"},
                  "user_id": {"type": "string"}}, ["owner_id", "job_id"]),
         _h_eg_dossier, ("egordian:read",), category="egordian"),
    Tool("egordian_note_create", "Create a job note (write)",
         "POST v1/Users/{userId}/JobOrders/{jobId}/Notes. Side-effecting: requires "
         "egordian:write, actor, approval envelope and idempotency key. Disabled unless "
         "ALLOW_EGORDIAN_WRITES=true.",
         _schema({"user_id": {"type": "string"}, "job_id": {"type": "string"},
                  "note": {"type": "object"}},
                 ["user_id", "job_id", "note"], write=True),
         _h_eg_note_create, ("egordian:write",), side_effecting=True, idempotent=False,
         category="egordian"),
    Tool("egordian_tracking_date_update", "Update a tracking date (write)",
         "PUT v1/Owners/{ownerId}/JobOrders/{jobId}/TrackingDates/{trackingDateId}. "
         "Side-effecting: requires egordian:write, actor, approval and idempotency key.",
         _schema({"owner_id": {"type": "string"}, "job_id": {"type": "string"},
                  "tracking_date_id": {"type": "string"}, "value": {"type": "object"}},
                 ["owner_id", "job_id", "tracking_date_id", "value"], write=True),
         _h_eg_tracking_update, ("egordian:write",), side_effecting=True, idempotent=False,
         category="egordian"),
    Tool("egordian_price_proposal_submit", "Submit a price proposal (blocked)",
         "Capability-gap surface. The Help page documents no PriceProposalsV1 write route, so "
         "this tool always returns capability_not_documented and never calls eGordian.",
         _schema({"assignment_id": {"type": "string"}}, []),
         _h_eg_price_proposal_submit, ("egordian:read",), category="egordian"),
]

TOOLS: dict[str, Tool] = {t.name: t for t in sorted(_TOOLS, key=lambda t: t.name)}


def list_tools() -> list[dict[str, Any]]:
    """Deterministic order: always sorted by tool name."""
    return [TOOLS[name].descriptor() for name in sorted(TOOLS)]


def get_tool(name: str) -> Tool | None:
    return TOOLS.get(name)


def tool_count() -> int:
    return len(TOOLS)


def categories() -> dict[str, int]:
    out: dict[str, int] = {}
    for tool in TOOLS.values():
        out[tool.category] = out.get(tool.category, 0) + 1
    return out
