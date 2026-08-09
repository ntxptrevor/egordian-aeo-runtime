"""Project-scoped CTC/CSI/RSMeans-opaque crosswalk proposals."""
from __future__ import annotations

import json
import secrets
from typing import Any

from .overlay import ApprovalRequired, AuthorizationError, _audit, connect
from .util import canonical_json, now, stable_id


def propose_edge(overlay_path: str, project_id: str, source_system: str, source_code: str | None,
                 target_system: str, target_code_or_opaque_id: str, actor: str, *,
                 source_edition: str | None = None, target_edition: str | None = None,
                 source_alias: str | None = None, cardinality: str = "one_to_one",
                 unit: str | None = None, attributes: dict | None = None, provenance: dict | None = None,
                 catalogue_path: str | None = None, approval: bool | None = None) -> dict:
    if approval is None:
        raise ApprovalRequired("Crosswalk write requires explicit approval=false for proposal or true for decision.")
    if approval:
        raise ApprovalRequired("Use approve_edge for a named-human approval; proposals require approval=false.")
    if target_system == "GORDIAN_CTC":
        # An actual CTC target must originate from the authorized catalogue—not
        # a model/string. Opaque federation targets use RSMEANS_OPAQUE instead.
        if not catalogue_path:
            raise ValueError("GORDIAN_CTC target validation requires catalogue_path; refusing an unverified code.")
        from .query import get_line
        if get_line(catalogue_path, target_code_or_opaque_id, include_modifiers=False).get("outcome") != "HIT":
            raise ValueError("Refusing target Gordian code absent from the authorized catalogue.")
    edge_id = stable_id("edge", [project_id, source_system, source_code, target_system,
                                  target_code_or_opaque_id, now(), secrets.token_hex(4)])
    con = connect(overlay_path)
    try:
        if not con.execute("SELECT 1 FROM project WHERE project_id=?", (project_id,)).fetchone():
            raise AuthorizationError("Unknown project.")
        con.execute("""INSERT INTO crosswalk_edge(
                    edge_id,project_id,status,source_system,source_code,source_edition,source_alias,
                    target_system,target_code_or_opaque_id,target_edition,cardinality,unit,
                    attributes_json,provenance_json,proposed_by,approved_by,approval,supersedes_edge_id,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (edge_id, project_id, "candidate", source_system, source_code, source_edition, source_alias,
                     target_system, target_code_or_opaque_id, target_edition, cardinality, unit,
                     canonical_json(attributes or {}), canonical_json(provenance or {}), actor, None, 0, None, now()))
        _audit(con, actor, "propose_crosswalk", project_id, {"edge_id": edge_id})
        con.commit()
        return {"edge_id": edge_id, "status": "candidate"}
    finally:
        con.close()


def approve_edge(overlay_path: str, project_id: str, edge_id: str, actor: str, approval: bool, rationale: str) -> dict:
    if not approval:
        raise ApprovalRequired("Crosswalk approval requires approval=true.")
    con = connect(overlay_path)
    try:
        row = con.execute("SELECT * FROM crosswalk_edge WHERE edge_id=? AND project_id=?", (edge_id, project_id)).fetchone()
        if not row or row["status"] != "candidate":
            raise ValueError("Candidate edge not found.")
        con.execute("UPDATE crosswalk_edge SET status='approved',approved_by=?,approval=1 WHERE edge_id=?",
                    (actor, edge_id))
        _audit(con, actor, "approve_crosswalk", project_id, {"edge_id": edge_id, "rationale": rationale})
        con.commit()
        return {"edge_id": edge_id, "status": "approved", "actor": actor}
    finally:
        con.close()


def translate(overlay_path: str, project_id: str, system: str, code_or_alias: str,
              target_system: str | None = None) -> dict:
    """T1 crosswalk only returns this project's approved/candidate data; no global leakage."""
    con = connect(overlay_path)
    try:
        sql = """SELECT * FROM crosswalk_edge WHERE project_id=? AND status IN ('approved','candidate')
                 AND source_system=? AND (source_code=? OR source_alias=?)"""
        args: list[Any] = [project_id, system, code_or_alias, code_or_alias]
        if target_system:
            sql += " AND target_system=?"
            args.append(target_system)
        rows = [dict(r) for r in con.execute(sql + " ORDER BY approval DESC, created_at DESC", args)]
        for r in rows:
            r["attributes"] = json.loads(r.pop("attributes_json"))
            r["provenance"] = json.loads(r.pop("provenance_json"))
        return {"tier": "T1", "outcome": "HIT" if rows else "MISS", "results": rows}
    finally:
        con.close()
