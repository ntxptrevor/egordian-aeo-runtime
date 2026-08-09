"""Writable project-scoped overlay with append-only audit and opaque handles."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .util import canonical_json, ensure_parent, now, sha256_bytes, stable_id

OVERLAY_SCHEMA_VERSION = 2

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE project(
  project_id TEXT PRIMARY KEY, owner_contract TEXT NOT NULL, created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE handle(
  handle_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, handle_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE handle_project(
  handle_id TEXT NOT NULL REFERENCES handle(handle_id), project_id TEXT NOT NULL REFERENCES project(project_id),
  PRIMARY KEY(handle_id,project_id)
);
CREATE TABLE profile_snapshot(
  snapshot_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  profile_ids_json TEXT NOT NULL, resolved_json TEXT NOT NULL, conflicts_json TEXT NOT NULL,
  approved_by TEXT, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE crosswalk_edge(
  edge_id TEXT PRIMARY KEY, project_id TEXT REFERENCES project(project_id), status TEXT NOT NULL
    CHECK(status IN ('candidate','approved','rejected','superseded')),
  source_system TEXT NOT NULL CHECK(source_system IN ('CSI_MASTERFORMAT','GORDIAN_CTC','RSMEANS_OPAQUE')),
  source_code TEXT, source_edition TEXT, source_alias TEXT,
  target_system TEXT NOT NULL CHECK(target_system IN ('CSI_MASTERFORMAT','GORDIAN_CTC','RSMEANS_OPAQUE')),
  target_code_or_opaque_id TEXT NOT NULL, target_edition TEXT, cardinality TEXT NOT NULL
    CHECK(cardinality IN ('one_to_one','one_to_many','many_to_one','many_to_many')),
  unit TEXT, attributes_json TEXT NOT NULL, provenance_json TEXT NOT NULL,
  proposed_by TEXT NOT NULL, approved_by TEXT, approval INTEGER NOT NULL DEFAULT 0,
  supersedes_edge_id TEXT, created_at TEXT NOT NULL
);
CREATE INDEX edge_project_idx ON crosswalk_edge(project_id,status);
CREATE TABLE retrieval_cache(
  cache_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  query_key TEXT NOT NULL, outcome_json TEXT NOT NULL, catalogue_content_hash TEXT NOT NULL,
  validated_by TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id,query_key,catalogue_content_hash)
);
CREATE TABLE review_queue(
  review_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  review_type TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','approved','rejected','deferred')),
  payload_json TEXT NOT NULL, proposed_by TEXT NOT NULL, decision_by TEXT, decision_rationale TEXT,
  approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, decided_at TEXT
);
CREATE INDEX review_project_idx ON review_queue(project_id,status);
CREATE TABLE learning_event(
  event_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  event_type TEXT NOT NULL CHECK(event_type IN ('observation','proposal','human_decision','before_after_delta',
   'workflow_acceptance','promotion','rollback','supersession','change_order','lesson','shortcut','scope_gap_solution','process_improvement')),
  subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, payload_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, related_event_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX learning_subject_idx ON learning_event(project_id,subject_type,subject_id,created_at);
CREATE TABLE reconciliation_run(
  run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  request_hash TEXT NOT NULL, result_json TEXT NOT NULL, status TEXT NOT NULL,
  proposed_by TEXT NOT NULL, approved_by TEXT, approval INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE observed_external_line(
  observation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  source_system TEXT NOT NULL, edition TEXT NOT NULL, code_or_opaque_id TEXT NOT NULL,
  observed_date TEXT NOT NULL, screen_page_provenance_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX observed_external_line_project_idx ON observed_external_line(project_id,source_system,code_or_opaque_id);
CREATE TABLE external_line_verification(
  verification_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL REFERENCES observed_external_line(observation_id),
  project_id TEXT NOT NULL REFERENCES project(project_id),
  verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','rejected','needs_review')),
  rationale TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX external_line_verification_idx ON external_line_verification(observation_id,created_at);
CREATE TABLE big_note(
  note_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  title TEXT NOT NULL, body TEXT NOT NULL, provenance_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX big_note_search_idx ON big_note(project_id,created_at);
CREATE TABLE change_order_log(
  change_order_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  status TEXT NOT NULL CHECK(status IN ('candidate','submitted','accepted','rejected','superseded')),
  payload_json TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE proposal_final_delta(
  delta_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  initial_proposal_json TEXT NOT NULL, accepted_final_json TEXT NOT NULL, delta_json TEXT NOT NULL,
  acceptance_status TEXT NOT NULL CHECK(acceptance_status IN ('candidate','accepted','rejected')),
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE improvement_candidate(
  candidate_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  proposal_delta_id TEXT REFERENCES proposal_final_delta(delta_id), payload_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE improvement_decision(
  decision_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL REFERENCES improvement_candidate(candidate_id),
  project_id TEXT NOT NULL REFERENCES project(project_id),
  status TEXT NOT NULL CHECK(status IN ('accepted','rejected','deferred')),
  rationale TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE audit_log(
  event_id TEXT PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  project_id TEXT, detail_json TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
CREATE TRIGGER learning_no_update BEFORE UPDATE ON learning_event BEGIN SELECT RAISE(ABORT,'learning_event is append-only'); END;
CREATE TRIGGER learning_no_delete BEFORE DELETE ON learning_event BEGIN SELECT RAISE(ABORT,'learning_event is append-only'); END;
CREATE TRIGGER observed_external_line_no_update BEFORE UPDATE ON observed_external_line BEGIN SELECT RAISE(ABORT,'observed_external_line is append-only'); END;
CREATE TRIGGER observed_external_line_no_delete BEFORE DELETE ON observed_external_line BEGIN SELECT RAISE(ABORT,'observed_external_line is append-only'); END;
CREATE TRIGGER external_line_verification_no_update BEFORE UPDATE ON external_line_verification BEGIN SELECT RAISE(ABORT,'external_line_verification is append-only'); END;
CREATE TRIGGER external_line_verification_no_delete BEFORE DELETE ON external_line_verification BEGIN SELECT RAISE(ABORT,'external_line_verification is append-only'); END;
CREATE TRIGGER big_note_no_update BEFORE UPDATE ON big_note BEGIN SELECT RAISE(ABORT,'big_note is append-only'); END;
CREATE TRIGGER big_note_no_delete BEFORE DELETE ON big_note BEGIN SELECT RAISE(ABORT,'big_note is append-only'); END;
CREATE TRIGGER change_order_no_update BEFORE UPDATE ON change_order_log BEGIN SELECT RAISE(ABORT,'change_order_log is append-only'); END;
CREATE TRIGGER change_order_no_delete BEFORE DELETE ON change_order_log BEGIN SELECT RAISE(ABORT,'change_order_log is append-only'); END;
CREATE TRIGGER proposal_delta_no_update BEFORE UPDATE ON proposal_final_delta BEGIN SELECT RAISE(ABORT,'proposal_final_delta is append-only'); END;
CREATE TRIGGER proposal_delta_no_delete BEFORE DELETE ON proposal_final_delta BEGIN SELECT RAISE(ABORT,'proposal_final_delta is append-only'); END;
CREATE TRIGGER improvement_candidate_no_update BEFORE UPDATE ON improvement_candidate BEGIN SELECT RAISE(ABORT,'improvement_candidate is append-only'); END;
CREATE TRIGGER improvement_candidate_no_delete BEFORE DELETE ON improvement_candidate BEGIN SELECT RAISE(ABORT,'improvement_candidate is append-only'); END;
CREATE TRIGGER improvement_decision_no_update BEFORE UPDATE ON improvement_decision BEGIN SELECT RAISE(ABORT,'improvement_decision is append-only'); END;
CREATE TRIGGER improvement_decision_no_delete BEFORE DELETE ON improvement_decision BEGIN SELECT RAISE(ABORT,'improvement_decision is append-only'); END;
"""

MIGRATION_V2 = """
CREATE TABLE IF NOT EXISTS observed_external_line(
  observation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  source_system TEXT NOT NULL, edition TEXT NOT NULL, code_or_opaque_id TEXT NOT NULL,
  observed_date TEXT NOT NULL, screen_page_provenance_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observed_external_line_project_idx ON observed_external_line(project_id,source_system,code_or_opaque_id);
CREATE TABLE IF NOT EXISTS external_line_verification(
  verification_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL REFERENCES observed_external_line(observation_id),
  project_id TEXT NOT NULL REFERENCES project(project_id),
  verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','rejected','needs_review')),
  rationale TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS external_line_verification_idx ON external_line_verification(observation_id,created_at);
CREATE TABLE IF NOT EXISTS big_note(
  note_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  title TEXT NOT NULL, body TEXT NOT NULL, provenance_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS big_note_search_idx ON big_note(project_id,created_at);
CREATE TABLE IF NOT EXISTS change_order_log(
  change_order_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  status TEXT NOT NULL CHECK(status IN ('candidate','submitted','accepted','rejected','superseded')),
  payload_json TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proposal_final_delta(
  delta_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  initial_proposal_json TEXT NOT NULL, accepted_final_json TEXT NOT NULL, delta_json TEXT NOT NULL,
  acceptance_status TEXT NOT NULL CHECK(acceptance_status IN ('candidate','accepted','rejected')),
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS improvement_candidate(
  candidate_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(project_id),
  proposal_delta_id TEXT REFERENCES proposal_final_delta(delta_id), payload_json TEXT NOT NULL,
  actor TEXT NOT NULL, approval INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS improvement_decision(
  decision_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL REFERENCES improvement_candidate(candidate_id),
  project_id TEXT NOT NULL REFERENCES project(project_id),
  status TEXT NOT NULL CHECK(status IN ('accepted','rejected','deferred')),
  rationale TEXT NOT NULL, actor TEXT NOT NULL, approval INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS observed_external_line_no_update BEFORE UPDATE ON observed_external_line BEGIN SELECT RAISE(ABORT,'observed_external_line is append-only'); END;
CREATE TRIGGER IF NOT EXISTS observed_external_line_no_delete BEFORE DELETE ON observed_external_line BEGIN SELECT RAISE(ABORT,'observed_external_line is append-only'); END;
CREATE TRIGGER IF NOT EXISTS external_line_verification_no_update BEFORE UPDATE ON external_line_verification BEGIN SELECT RAISE(ABORT,'external_line_verification is append-only'); END;
CREATE TRIGGER IF NOT EXISTS external_line_verification_no_delete BEFORE DELETE ON external_line_verification BEGIN SELECT RAISE(ABORT,'external_line_verification is append-only'); END;
CREATE TRIGGER IF NOT EXISTS big_note_no_update BEFORE UPDATE ON big_note BEGIN SELECT RAISE(ABORT,'big_note is append-only'); END;
CREATE TRIGGER IF NOT EXISTS big_note_no_delete BEFORE DELETE ON big_note BEGIN SELECT RAISE(ABORT,'big_note is append-only'); END;
CREATE TRIGGER IF NOT EXISTS change_order_no_update BEFORE UPDATE ON change_order_log BEGIN SELECT RAISE(ABORT,'change_order_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS change_order_no_delete BEFORE DELETE ON change_order_log BEGIN SELECT RAISE(ABORT,'change_order_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS proposal_delta_no_update BEFORE UPDATE ON proposal_final_delta BEGIN SELECT RAISE(ABORT,'proposal_final_delta is append-only'); END;
CREATE TRIGGER IF NOT EXISTS proposal_delta_no_delete BEFORE DELETE ON proposal_final_delta BEGIN SELECT RAISE(ABORT,'proposal_final_delta is append-only'); END;
CREATE TRIGGER IF NOT EXISTS improvement_candidate_no_update BEFORE UPDATE ON improvement_candidate BEGIN SELECT RAISE(ABORT,'improvement_candidate is append-only'); END;
CREATE TRIGGER IF NOT EXISTS improvement_candidate_no_delete BEFORE DELETE ON improvement_candidate BEGIN SELECT RAISE(ABORT,'improvement_candidate is append-only'); END;
CREATE TRIGGER IF NOT EXISTS improvement_decision_no_update BEFORE UPDATE ON improvement_decision BEGIN SELECT RAISE(ABORT,'improvement_decision is append-only'); END;
CREATE TRIGGER IF NOT EXISTS improvement_decision_no_delete BEFORE DELETE ON improvement_decision BEGIN SELECT RAISE(ABORT,'improvement_decision is append-only'); END;
"""


class AuthorizationError(PermissionError):
    pass


class ApprovalRequired(PermissionError):
    pass


def connect(path: str) -> sqlite3.Connection:
    ensure_parent(path)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_overlay(path: str) -> dict:
    con = connect(path)
    try:
        has_meta = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        if not has_meta:
            con.executescript(SCHEMA)
        else:
            version_row = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            current = int(version_row["value"]) if version_row and version_row["value"].isdigit() else 1
            if current < 2:
                con.executescript(MIGRATION_V2)
        con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
                    (str(OVERLAY_SCHEMA_VERSION),))
        con.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('created_at',?)", (now(),))
        con.commit()
        return {"overlay_path": str(Path(path).resolve()), "schema_version": OVERLAY_SCHEMA_VERSION}
    finally:
        con.close()


def _audit(con: sqlite3.Connection, actor: str, action: str, project_id: str | None, detail: Any) -> str:
    ident = stable_id("audit", [now(), actor, action, project_id, detail, secrets.token_hex(4)])
    con.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?)",
                (ident, now(), actor, action, project_id, canonical_json(detail)))
    return ident


def create_project(path: str, project_id: str, owner_contract: str, actor: str) -> dict:
    if not actor:
        raise ValueError("actor is required")
    con = connect(path)
    try:
        con.execute("INSERT INTO project VALUES(?,?,?,?,1)", (project_id, owner_contract, actor, now()))
        _audit(con, actor, "create_project", project_id, {"owner_contract": owner_contract})
        con.commit()
        return {"project_id": project_id, "owner_contract": owner_contract}
    finally:
        con.close()


def create_handle(path: str, user_id: str, project_ids: Iterable[str], ttl_hours: int = 8) -> dict:
    from datetime import datetime, timedelta, timezone
    if not user_id:
        raise ValueError("user_id is required")
    token = secrets.token_urlsafe(32)
    handle_id = stable_id("handle", [user_id, token])
    projects = list(project_ids)
    expires = (datetime.now(timezone.utc) + timedelta(hours=max(1, min(ttl_hours, 24)))).isoformat(timespec="seconds")
    con = connect(path)
    try:
        for p in projects:
            if not con.execute("SELECT 1 FROM project WHERE project_id=? AND active=1", (p,)).fetchone():
                raise AuthorizationError(f"Project does not exist/active: {p}")
        con.execute("INSERT INTO handle VALUES(?,?,?,?,?,NULL)",
                    (handle_id, user_id, sha256_bytes(token.encode()), expires, now()))
        con.executemany("INSERT INTO handle_project VALUES(?,?)", [(handle_id, p) for p in projects])
        _audit(con, user_id, "create_handle", None, {"handle_id": handle_id, "projects": projects, "expires_at": expires})
        con.commit()
    finally:
        con.close()
    return {"handle": token, "expires_at": expires, "projects": projects}


def validate_handle(path: str, handle: str, user_id: str, project_id: str) -> dict:
    if not handle or not user_id or not project_id:
        raise AuthorizationError("handle, user_id, and project_id are required (fail closed).")
    con = connect(path)
    try:
        row = con.execute(
            """SELECT h.* FROM handle h JOIN handle_project hp ON hp.handle_id=h.handle_id
               WHERE h.handle_hash=? AND h.user_id=? AND hp.project_id=? AND h.revoked_at IS NULL
               AND h.expires_at > ?""", (sha256_bytes(handle.encode()), user_id, project_id, now())
        ).fetchone()
        if not row:
            raise AuthorizationError("Opaque handle is invalid, expired, or unauthorized for this project.")
        return {"handle_id": row["handle_id"], "user_id": row["user_id"], "project_id": project_id}
    finally:
        con.close()


def append_learning(path: str, project_id: str, event_type: str, subject_type: str, subject_id: str,
                    payload: dict, actor: str, approval: bool = False, related_event_id: str | None = None) -> dict:
    if not actor:
        raise ValueError("actor is required")
    if event_type in {"promotion", "rollback", "supersession", "human_decision"} and not approval:
        raise ApprovalRequired(f"{event_type} requires explicit approval=true.")
    event_id = stable_id("learn", [project_id, event_type, subject_type, subject_id, payload, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        if not con.execute("SELECT 1 FROM project WHERE project_id=?", (project_id,)).fetchone():
            raise AuthorizationError(f"Unknown project: {project_id}")
        con.execute("INSERT INTO learning_event VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (event_id, project_id, event_type, subject_type, subject_id, canonical_json(payload), actor,
                     1 if approval else 0, related_event_id, now()))
        _audit(con, actor, f"learning_{event_type}", project_id, {"event_id": event_id, "subject": subject_id, "approval": approval})
        con.commit()
        return {"event_id": event_id, "event_type": event_type, "approval": approval}
    finally:
        con.close()


def promote_learning(path: str, project_id: str, subject_type: str, subject_id: str, payload: dict,
                     actor: str, approval: bool, *, min_cross_project_evidence: int = 3,
                     min_distinct_projects: int = 2) -> dict:
    """Human-gated promotion. It may be recorded below threshold but never marked stable.

    Only counts metadata for cross-project evidence; project narrative/content is
    neither copied nor propagated to a reusable profile automatically.
    """
    if not approval or not actor:
        raise ApprovalRequired("Named human and approval=true are required for promotion.")
    con = connect(path)
    try:
        rows = con.execute(
            """SELECT project_id, event_id FROM learning_event
               WHERE subject_type=? AND subject_id=? AND event_type IN
               ('observation','human_decision','workflow_acceptance')
               ORDER BY created_at""", (subject_type, subject_id)
        ).fetchall()
        evidence_count = len(rows)
        distinct_projects = len({r["project_id"] for r in rows})
    finally:
        con.close()
    stable = evidence_count >= min_cross_project_evidence and distinct_projects >= min_distinct_projects
    target_scope = payload.get("target_scope", "project")
    if target_scope != "project" and not payload.get("reusable_profile_id"):
        raise ValueError("Reusable promotion needs an explicit reusable_profile_id; project data never moves upward implicitly.")
    outcome = append_learning(
        path, project_id, "promotion", subject_type, subject_id,
        {**payload, "target_scope": target_scope, "stability": "stable" if stable else "candidate",
         "evidence_count": evidence_count, "distinct_projects": distinct_projects,
         "threshold": {"min_cross_project_evidence": min_cross_project_evidence,
                       "min_distinct_projects": min_distinct_projects}},
        actor, True,
    )
    return {**outcome, "stable": stable, "evidence_count": evidence_count, "distinct_projects": distinct_projects}


def create_review(path: str, project_id: str, review_type: str, payload: dict, actor: str) -> dict:
    review_id = stable_id("review", [project_id, review_type, payload, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        con.execute("INSERT INTO review_queue VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (review_id, project_id, review_type, "open", canonical_json(payload), actor, None, None, 0, now(), None))
        _audit(con, actor, "create_review", project_id, {"review_id": review_id, "type": review_type})
        con.commit()
        return {"review_id": review_id, "status": "open"}
    finally:
        con.close()


def decide_review(path: str, project_id: str, review_id: str, status: str, actor: str, approval: bool, rationale: str) -> dict:
    if status not in {"approved", "rejected", "deferred"}:
        raise ValueError("status must be approved, rejected, or deferred")
    if status == "approved" and not approval:
        raise ApprovalRequired("Approving a review requires approval=true.")
    con = connect(path)
    try:
        row = con.execute("SELECT * FROM review_queue WHERE review_id=? AND project_id=?", (review_id, project_id)).fetchone()
        if not row or row["status"] != "open":
            raise ValueError("Open project-scoped review not found.")
        con.execute("""UPDATE review_queue SET status=?,decision_by=?,decision_rationale=?,approval=?,decided_at=?
                       WHERE review_id=? AND project_id=?""", (status, actor, rationale, int(approval), now(), review_id, project_id))
        _audit(con, actor, "decide_review", project_id, {"review_id": review_id, "status": status, "approval": approval})
        con.commit()
        return {"review_id": review_id, "status": status, "approved_by": actor if approval else None}
    finally:
        con.close()


def lessons(path: str, project_id: str, query: str = "", limit: int = 20) -> list[dict]:
    """Search big notes/lessons first; project filter is mandatory."""
    con = connect(path)
    try:
        like = f"%{query.lower()}%"
        rows = con.execute(
            """SELECT * FROM learning_event WHERE project_id=? AND event_type IN
                 ('lesson','shortcut','scope_gap_solution','process_improvement','human_decision','workflow_acceptance')
                 AND lower(payload_json) LIKE ? ORDER BY created_at DESC LIMIT ?""",
            (project_id, like, max(1, min(limit, 100))),
        ).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload_json"])} for r in rows]
    finally:
        con.close()


def record_observed_external_line(path: str, project_id: str, source_system: str, edition: str,
                                  code_or_opaque_id: str, observed_date: str,
                                  screen_page_provenance: dict, actor: str, approval: bool) -> dict:
    """Record, but never ingest, a human-observed external line absent from catalogue."""
    if approval is not False:
        raise ApprovalRequired("External-line observation is a proposal and requires explicit approval=false.")
    if not all(str(x).strip() for x in (source_system, edition, code_or_opaque_id, observed_date, actor)):
        raise ValueError("source_system, edition, code_or_opaque_id, observed_date, and actor are required.")
    if not isinstance(screen_page_provenance, dict) or not screen_page_provenance:
        raise ValueError("screen/page provenance is required for observed external line.")
    observation_id = stable_id("external", [project_id, source_system, edition, code_or_opaque_id,
                                             observed_date, screen_page_provenance, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        con.execute("INSERT INTO observed_external_line VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (observation_id, project_id, source_system, edition, code_or_opaque_id, observed_date,
                     canonical_json(screen_page_provenance), actor, 0, now()))
        _audit(con, actor, "record_observed_external_line", project_id,
               {"observation_id": observation_id, "source_system": source_system,
                "verification_status": "pending_human_verification",
                "catalogue_mutation": False})
        con.commit()
        return {"observation_id": observation_id, "verification_status": "pending_human_verification",
                "immutable_catalogue_modified": False}
    finally:
        con.close()


def verify_observed_external_line(path: str, project_id: str, observation_id: str, verification_status: str,
                                  rationale: str, actor: str, approval: bool) -> dict:
    if not approval:
        raise ApprovalRequired("External-line verification requires named-human approval=true.")
    if verification_status not in {"verified", "rejected", "needs_review"}:
        raise ValueError("verification_status must be verified, rejected, or needs_review.")
    if not str(rationale).strip():
        raise ValueError("verification rationale is required.")
    verification_id = stable_id("external_verify", [observation_id, verification_status, rationale, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        if not con.execute("SELECT 1 FROM observed_external_line WHERE observation_id=? AND project_id=?",
                           (observation_id, project_id)).fetchone():
            raise AuthorizationError("Observed external line not found in this project.")
        con.execute("INSERT INTO external_line_verification VALUES(?,?,?,?,?,?,?,?)",
                    (verification_id, observation_id, project_id, verification_status, rationale, actor, 1, now()))
        _audit(con, actor, "verify_observed_external_line", project_id,
               {"observation_id": observation_id, "verification_status": verification_status,
                "catalogue_mutation": False})
        con.commit()
        return {"verification_id": verification_id, "observation_id": observation_id,
                "verification_status": verification_status, "immutable_catalogue_modified": False}
    finally:
        con.close()


def observed_external_lines(path: str, project_id: str, limit: int = 50) -> list[dict]:
    con = connect(path)
    try:
        rows = con.execute(
            """SELECT o.*, COALESCE((SELECT v.verification_status FROM external_line_verification v
                   WHERE v.observation_id=o.observation_id ORDER BY v.created_at DESC LIMIT 1),
                   'pending_human_verification') AS verification_status
               FROM observed_external_line o WHERE o.project_id=? ORDER BY o.created_at DESC LIMIT ?""",
            (project_id, max(1, min(limit, 100))),
        ).fetchall()
        return [{**dict(r), "screen_page_provenance": json.loads(r["screen_page_provenance_json"])} for r in rows]
    finally:
        con.close()


def record_big_note(path: str, project_id: str, title: str, body: str, provenance: dict,
                    actor: str, approval: bool) -> dict:
    if approval is not False:
        raise ApprovalRequired("Big-note capture requires explicit approval=false; it is not a promotion.")
    if not str(title).strip() or not str(body).strip() or not isinstance(provenance, dict) or not provenance:
        raise ValueError("title, body, and provenance are required.")
    note_id = stable_id("note", [project_id, title, body, provenance, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        con.execute("INSERT INTO big_note VALUES(?,?,?,?,?,?,?,?)",
                    (note_id, project_id, title, body, canonical_json(provenance), actor, 0, now()))
        _audit(con, actor, "record_big_note", project_id, {"note_id": note_id})
        con.commit()
        return {"note_id": note_id, "status": "recorded"}
    finally:
        con.close()


def search_prior_knowledge(path: str, project_id: str, query: str = "", limit: int = 20) -> dict:
    """Big notes and lessons are retrieved before proposing/mapping a catalogue line."""
    con = connect(path)
    try:
        like = f"%{query.lower()}%"
        notes = [dict(r) for r in con.execute(
            """SELECT note_id,title,body,provenance_json,actor,created_at FROM big_note
               WHERE project_id=? AND (lower(title) LIKE ? OR lower(body) LIKE ?)
               ORDER BY created_at DESC LIMIT ?""", (project_id, like, like, max(1, min(limit, 100)))
        )]
        for note in notes:
            note["provenance"] = json.loads(note.pop("provenance_json"))
    finally:
        con.close()
    return {"big_notes": notes, "lessons": lessons(path, project_id, query, limit)}


def record_change_order(path: str, project_id: str, status: str, payload: dict,
                        actor: str, approval: bool) -> dict:
    if status not in {"candidate", "submitted", "accepted", "rejected", "superseded"}:
        raise ValueError("Unsupported change-order status.")
    if status == "accepted" and not approval:
        raise ApprovalRequired("Accepted change order requires named-human approval=true.")
    change_order_id = stable_id("co", [project_id, status, payload, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        con.execute("INSERT INTO change_order_log VALUES(?,?,?,?,?,?,?)",
                    (change_order_id, project_id, status, canonical_json(payload), actor, int(approval), now()))
        _audit(con, actor, "record_change_order", project_id, {"change_order_id": change_order_id, "status": status, "approval": approval})
        con.commit()
        return {"change_order_id": change_order_id, "status": status}
    finally:
        con.close()


def record_proposal_final_delta(path: str, project_id: str, initial_proposal: dict, accepted_final: dict,
                                delta: dict, acceptance_status: str, actor: str, approval: bool) -> dict:
    if acceptance_status not in {"candidate", "accepted", "rejected"}:
        raise ValueError("Unsupported acceptance status.")
    if acceptance_status == "accepted" and not approval:
        raise ApprovalRequired("Accepted final proposal requires named-human approval=true.")
    delta_id = stable_id("delta", [project_id, initial_proposal, accepted_final, delta, acceptance_status, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        con.execute("INSERT INTO proposal_final_delta VALUES(?,?,?,?,?,?,?,?,?)",
                    (delta_id, project_id, canonical_json(initial_proposal), canonical_json(accepted_final),
                     canonical_json(delta), acceptance_status, actor, int(approval), now()))
        _audit(con, actor, "record_proposal_final_delta", project_id,
               {"delta_id": delta_id, "acceptance_status": acceptance_status, "approval": approval})
        con.commit()
        return {"delta_id": delta_id, "acceptance_status": acceptance_status}
    finally:
        con.close()


def propose_improvement(path: str, project_id: str, payload: dict, actor: str, approval: bool,
                        proposal_delta_id: str | None = None) -> dict:
    if approval is not False:
        raise ApprovalRequired("Improvement candidates are inert and require explicit approval=false.")
    candidate_id = stable_id("improve", [project_id, proposal_delta_id, payload, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        if proposal_delta_id and not con.execute(
            "SELECT 1 FROM proposal_final_delta WHERE delta_id=? AND project_id=?", (proposal_delta_id, project_id)
        ).fetchone():
            raise AuthorizationError("Proposal delta is not in this project.")
        con.execute("INSERT INTO improvement_candidate VALUES(?,?,?,?,?,?,?)",
                    (candidate_id, project_id, proposal_delta_id, canonical_json(payload), actor, 0, now()))
        _audit(con, actor, "propose_improvement", project_id, {"candidate_id": candidate_id, "status": "inert_candidate"})
        con.commit()
        return {"candidate_id": candidate_id, "status": "inert_candidate"}
    finally:
        con.close()


def decide_improvement(path: str, project_id: str, candidate_id: str, status: str,
                       rationale: str, actor: str, approval: bool) -> dict:
    if status not in {"accepted", "rejected", "deferred"}:
        raise ValueError("Improvement decision must be accepted, rejected, or deferred.")
    if not approval:
        raise ApprovalRequired("Improvement decision requires named-human approval=true.")
    decision_id = stable_id("improve_decision", [candidate_id, status, rationale, actor, now(), secrets.token_hex(4)])
    con = connect(path)
    try:
        if not con.execute("SELECT 1 FROM improvement_candidate WHERE candidate_id=? AND project_id=?",
                           (candidate_id, project_id)).fetchone():
            raise AuthorizationError("Improvement candidate is not in this project.")
        con.execute("INSERT INTO improvement_decision VALUES(?,?,?,?,?,?,?,?)",
                    (decision_id, candidate_id, project_id, status, rationale, actor, 1, now()))
        _audit(con, actor, "decide_improvement", project_id, {"candidate_id": candidate_id, "status": status})
        con.commit()
        return {"decision_id": decision_id, "candidate_id": candidate_id, "status": status}
    finally:
        con.close()


def get_retrieval_cache(path: str, project_id: str, query_key: str, catalogue_content_hash: str) -> dict | None:
    """T0 cache contains only identifiers/outcome metadata, never book text or prices."""
    con = connect(path)
    try:
        row = con.execute("""SELECT outcome_json FROM retrieval_cache
                           WHERE project_id=? AND query_key=? AND catalogue_content_hash=?""",
                          (project_id, query_key, catalogue_content_hash)).fetchone()
        return json.loads(row["outcome_json"]) if row else None
    finally:
        con.close()


def put_retrieval_cache(path: str, project_id: str, query_key: str, catalogue_content_hash: str,
                        outcome: dict, actor: str) -> None:
    con = connect(path)
    try:
        cache_id = stable_id("cache", [project_id, query_key, catalogue_content_hash])
        con.execute("""INSERT OR IGNORE INTO retrieval_cache
                     VALUES(?,?,?,?,?,?,?)""", (cache_id, project_id, query_key, canonical_json(outcome),
                                                  catalogue_content_hash, actor, now()))
        con.commit()
    finally:
        con.close()


def overlay_manifest(path: str) -> dict:
    con = connect(path)
    try:
        counts = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in
                  ("project", "crosswalk_edge", "review_queue", "learning_event", "reconciliation_run",
                   "observed_external_line", "external_line_verification", "big_note", "change_order_log",
                   "proposal_final_delta", "improvement_candidate", "improvement_decision", "audit_log")}
        tail = [dict(x) for x in con.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT 20")]
        return {"schema_version": OVERLAY_SCHEMA_VERSION, "counts": counts, "audit_tail": tail}
    finally:
        con.close()
