"""Stateless local/private service facade. Every operational call validates a handle."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from . import crosswalk, query
from .catalogue import catalogue_info, connect_readonly
from .overlay import (ApprovalRequired, AuthorizationError, append_learning, create_handle,
                      create_review, decide_review, get_retrieval_cache, lessons, overlay_manifest,
                      put_retrieval_cache, validate_handle, record_observed_external_line,
                      verify_observed_external_line, observed_external_lines, record_big_note,
                      search_prior_knowledge, record_change_order, record_proposal_final_delta,
                      propose_improvement, decide_improvement)
from .overlay import promote_learning
from .reconcile import persist_reconciliation, reconcile
from .util import canonical_json, now, sha256_bytes, stable_id

AuthHook = Callable[[str | None], str]
RateLimitHook = Callable[[str, str], None]


def local_auth(value: str | None) -> str:
    """Development-only hook. Replace before any network exposure."""
    return value or "local"


def no_rate_limit(_user_id: str, _operation: str) -> None:
    return None


@dataclass
class GordianService:
    catalogue_path: str
    overlay_path: str
    auth_hook: AuthHook = local_auth
    rate_limit_hook: RateLimitHook = no_rate_limit

    def _user(self, auth: str | None) -> str:
        user = self.auth_hook(auth)
        if not user:
            raise AuthorizationError("Authentication hook returned no user.")
        return user

    def _validate(self, payload: dict, operation: str, auth: str | None = None) -> tuple[str, str]:
        user = self._user(auth)
        self.rate_limit_hook(user, operation)
        handle = payload.get("handle")
        project_id = payload.get("project_id")
        validate_handle(self.overlay_path, handle, user, project_id)
        return user, project_id

    @staticmethod
    def _write_gate(payload: dict, user: str) -> bool:
        if payload.get("actor") != user:
            raise AuthorizationError("Write requires actor equal to authenticated user.")
        if "approval" not in payload or not isinstance(payload["approval"], bool):
            raise ApprovalRequired("Every write requires an explicit boolean approval field.")
        return bool(payload["approval"])

    def bootstrap_handle(self, *, auth: str | None, project_ids: list[str], ttl_hours: int = 8) -> dict:
        user = self._user(auth)
        self.rate_limit_hook(user, "bootstrap_handle")
        return create_handle(self.overlay_path, user, project_ids, ttl_hours)

    def info(self, payload: dict, *, auth: str | None = None) -> dict:
        self._validate(payload, "info", auth)
        return catalogue_info(self.catalogue_path)

    def search(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "search", auth)
        public_safe = bool(payload.get("public_safe", False))
        term, limit = str(payload.get("query", "")), int(payload.get("limit", 20))
        content_hash = catalogue_info(self.catalogue_path)["manifest"]["row_content_sha256"]
        key = sha256_bytes(canonical_json({"query": term, "limit": limit, "public_safe": public_safe}).encode())
        cached = get_retrieval_cache(self.overlay_path, project_id, key, content_hash)
        if cached:
            results = [query.get_line(self.catalogue_path, code, public_safe=public_safe)
                       for code in cached.get("code_normalized", [])]
            result = {"tier": "T0", "mode": "cache", "outcome": "HIT" if results else "MISS",
                      "results": results, "edition": cached.get("edition")}
        else:
            result = query.search(self.catalogue_path, term, limit, public_safe=public_safe)
            # Store only stable identifiers—not catalogue descriptions, costs, or excerpts.
            codes = [x.get("code_normalized") for x in result.get("results", []) if x.get("code_normalized")]
            put_retrieval_cache(self.overlay_path, project_id, key, content_hash,
                                {"code_normalized": codes, "edition": result.get("edition")}, user)
        # Prior project notes/lessons are retrieved first, before a task line can
        # be proposed from the resulting candidate set.
        prior = search_prior_knowledge(self.overlay_path, project_id, term, min(limit, 20))
        return {"project_id": project_id, "user_id": user, "prior_knowledge": prior, **result}

    def get(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "get", auth)
        result = query.get_line(self.catalogue_path, str(payload.get("code", "")),
                                bool(payload.get("include_modifiers", True)), bool(payload.get("public_safe", False)))
        return {"project_id": project_id, "user_id": user, **result}

    def browse(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "browse", auth)
        return {"project_id": project_id, "user_id": user,
                **query.browse(self.catalogue_path, str(payload.get("prefix", "")), bool(payload.get("public_safe", False)))}

    def translate(self, payload: dict, *, auth: str | None = None) -> dict:
        _, project_id = self._validate(payload, "translate", auth)
        return {"prior_knowledge": search_prior_knowledge(self.overlay_path, project_id, payload["code_or_alias"], 20),
                **crosswalk.translate(self.overlay_path, project_id, payload["system"], payload["code_or_alias"], payload.get("target_system"))}

    def reconcile(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "reconcile", auth)
        approval = self._write_gate(payload, user)
        request = dict(payload["request"])
        if request.get("project_id") != project_id:
            raise AuthorizationError("Request project_id does not match authorized project.")
        profile = payload.get("profile") or {}
        result = reconcile(request, profile)
        run = persist_reconciliation(self.overlay_path, request, result, user, approval)
        return {**result, "run": run}

    def get_lessons(self, payload: dict, *, auth: str | None = None) -> dict:
        _, project_id = self._validate(payload, "lessons", auth)
        return {"project_id": project_id, "results": lessons(self.overlay_path, project_id, payload.get("query", ""), payload.get("limit", 20))}

    def big_notes(self, payload: dict, *, auth: str | None = None) -> dict:
        _, project_id = self._validate(payload, "big_notes", auth)
        return {"project_id": project_id,
                **search_prior_knowledge(self.overlay_path, project_id, payload.get("query", ""), payload.get("limit", 20))}

    def observed_external_line(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "observed_external_line", auth)
        approval = self._write_gate(payload, user)
        return record_observed_external_line(
            self.overlay_path, project_id, payload["source_system"], payload["edition"],
            payload["code_or_opaque_id"], payload["observed_date"], payload["screen_page_provenance"],
            user, approval)

    def verify_external_line(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "verify_external_line", auth)
        approval = self._write_gate(payload, user)
        return verify_observed_external_line(self.overlay_path, project_id, payload["observation_id"],
                                             payload["verification_status"], payload["rationale"], user, approval)

    def external_lines(self, payload: dict, *, auth: str | None = None) -> dict:
        _, project_id = self._validate(payload, "external_lines", auth)
        return {"project_id": project_id, "results": observed_external_lines(self.overlay_path, project_id, payload.get("limit", 50))}

    def add_big_note(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "add_big_note", auth)
        approval = self._write_gate(payload, user)
        return record_big_note(self.overlay_path, project_id, payload["title"], payload["body"],
                               payload["provenance"], user, approval)

    def change_order_log(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "change_order_log", auth)
        approval = self._write_gate(payload, user)
        return record_change_order(self.overlay_path, project_id, payload["status"], payload.get("payload", {}),
                                   user, approval)

    def proposal_delta(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "proposal_delta", auth)
        approval = self._write_gate(payload, user)
        return record_proposal_final_delta(self.overlay_path, project_id, payload["initial_proposal"],
                                           payload["accepted_final"], payload["delta"],
                                           payload["acceptance_status"], user, approval)

    def propose_improvement(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "propose_improvement", auth)
        approval = self._write_gate(payload, user)
        return propose_improvement(self.overlay_path, project_id, payload.get("payload", {}), user, approval,
                                   payload.get("proposal_delta_id"))

    def decide_improvement(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "decide_improvement", auth)
        approval = self._write_gate(payload, user)
        return decide_improvement(self.overlay_path, project_id, payload["candidate_id"], payload["status"],
                                  payload["rationale"], user, approval)

    def review_queue(self, payload: dict, *, auth: str | None = None) -> dict:
        _, project_id = self._validate(payload, "review_queue", auth)
        from .overlay import connect
        con = connect(self.overlay_path)
        try:
            rows = [dict(r) for r in con.execute("SELECT * FROM review_queue WHERE project_id=? AND status='open' ORDER BY created_at",
                                                 (project_id,))]
            return {"project_id": project_id, "results": rows}
        finally:
            con.close()

    def propose_learning(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "propose_learning", auth)
        if self._write_gate(payload, user):
            raise ApprovalRequired("A learning proposal must use approval=false; promotion is a separate human action.")
        return append_learning(self.overlay_path, project_id, "proposal", payload["subject_type"], payload["subject_id"],
                               payload.get("payload", {}), user, False)

    def approve_learning(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "approve_learning", auth)
        if not self._write_gate(payload, user):
            raise ApprovalRequired("Named actor and approval=true are required.")
        config = payload.get("stable_threshold", {})
        return promote_learning(self.overlay_path, project_id, payload["subject_type"], payload["subject_id"],
                                payload.get("payload", {}), user, True,
                                min_cross_project_evidence=int(config.get("min_cross_project_evidence", 3)),
                                min_distinct_projects=int(config.get("min_distinct_projects", 2)))

    def reject_learning(self, payload: dict, *, auth: str | None = None) -> dict:
        user, project_id = self._validate(payload, "reject_learning", auth)
        if not self._write_gate(payload, user):
            raise ApprovalRequired("Named actor and approval=true are required.")
        return append_learning(self.overlay_path, project_id, "human_decision", payload["subject_type"], payload["subject_id"],
                               {"decision": "rejected", **payload.get("payload", {})}, user, True, payload.get("related_event_id"))

    def manifest(self, payload: dict, *, auth: str | None = None) -> dict:
        self._validate(payload, "manifest", auth)
        return {"catalogue": catalogue_info(self.catalogue_path), "overlay": overlay_manifest(self.overlay_path),
                "generated_at": now(), "private": True}


def create_app(service: GordianService):
    """Optional FastAPI application; importing this module stays stdlib-only."""
    try:
        from fastapi import FastAPI, Header, HTTPException
    except ImportError as e:
        raise RuntimeError("FastAPI is optional. Install with `pip install .[api]`.") from e
    app = FastAPI(title="Private eGordian Proposal Generator service", docs_url=None, redoc_url=None)

    def endpoint(method: str):
        fn = getattr(service, method)
        async def handler(payload: dict, x_user_id: str | None = Header(default=None)):
            try:
                return fn(payload, auth=x_user_id)
            except (AuthorizationError, ApprovalRequired) as e:
                raise HTTPException(status_code=403, detail=str(e))
            except (ValueError, KeyError) as e:
                raise HTTPException(status_code=400, detail=str(e))
        handler.__name__ = f"{method}_handler"
        app.post(f"/v1/{method}")(handler)
    for method in ("info", "search", "get", "browse", "translate", "reconcile", "get_lessons", "big_notes",
                   "observed_external_line", "verify_external_line", "external_lines", "add_big_note",
                   "change_order_log", "proposal_delta", "propose_improvement", "decide_improvement",
                   "review_queue", "propose_learning", "approve_learning", "reject_learning", "manifest"):
        endpoint(method)

    @app.post("/v1/bootstrap_handle")
    async def bootstrap(payload: dict, x_user_id: str | None = Header(default=None)):
        try:
            return service.bootstrap_handle(auth=x_user_id, project_ids=payload["project_ids"], ttl_hours=payload.get("ttl_hours", 8))
        except (AuthorizationError, ValueError) as e:
            raise HTTPException(status_code=403, detail=str(e))

    return app
