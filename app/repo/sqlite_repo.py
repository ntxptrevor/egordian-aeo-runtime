"""SQLite control-plane repository (WAL, transactional, migrated).

Used for the private preview deployment. Contains overlay/control-plane rows
only; no licensed catalogue content is ever copied here.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .base import HandleInvalid, Repository
from .migrations import SQLITE

_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _uid(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


class SQLiteRepository(Repository):
    backend = "sqlite"

    def __init__(self, path: str):
        self.path = str(Path(path).expanduser())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.migrate()

    # --- plumbing ---------------------------------------------------------
    def _con(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=10000")
            self._local.con = con
        return con

    def migrate(self) -> dict[str, Any]:
        con = self._con()
        applied: list[int] = []
        with _LOCK:
            con.execute(
                "CREATE TABLE IF NOT EXISTS cp_migration ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            done = {r[0] for r in con.execute("SELECT version FROM cp_migration")}
            for version, sql in SQLITE:
                if version in done:
                    continue
                con.executescript("BEGIN;" + sql + "; COMMIT;")
                con.execute("INSERT INTO cp_migration VALUES(?,?)", (version, _now()))
                con.commit()
                applied.append(version)
        return {"backend": self.backend, "applied": applied,
                "current_version": max([v for v, _ in SQLITE])}

    def health(self) -> dict[str, Any]:
        try:
            self._con().execute("SELECT 1").fetchone()
            return {"ok": True, "backend": self.backend, "path": self.path}
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            return {"ok": False, "backend": self.backend, "error": type(exc).__name__}

    # --- handles ----------------------------------------------------------
    def create_handle(self, user_id: str, project_ids: Iterable[str], ttl_hours: int) -> dict[str, Any]:
        pids = sorted({str(p) for p in project_ids if str(p).strip()})
        if not pids:
            raise ValueError("At least one project_id is required for a handle.")
        handle = secrets.token_urlsafe(32)
        created = datetime.now(timezone.utc)
        expires = created + timedelta(hours=max(1, min(int(ttl_hours), 24)))
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_handle(handle,user_id,project_ids,created_at,expires_at,revoked)"
                " VALUES(?,?,?,?,?,0)",
                (handle, user_id, json.dumps(pids), created.isoformat(timespec="seconds"),
                 expires.isoformat(timespec="seconds")),
            )
            con.commit()
        return {"handle": handle, "user_id": user_id, "project_ids": pids,
                "expires_at": expires.isoformat(timespec="seconds")}

    def validate_handle(self, handle: str, user_id: str, project_id: str) -> dict[str, Any]:
        if not handle or not isinstance(handle, str) or len(handle) < 32:
            raise HandleInvalid("A valid opaque handle is required on every call.")
        row = self._con().execute(
            "SELECT * FROM cp_handle WHERE handle=?", (handle,)
        ).fetchone()
        if row is None or row["revoked"]:
            raise HandleInvalid("Handle is unknown or revoked.")
        if row["user_id"] != user_id:
            raise HandleInvalid("Handle is not bound to the authenticated user.")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            raise HandleInvalid("Handle has expired; request a new one.")
        pids = json.loads(row["project_ids"])
        if project_id not in pids:
            raise HandleInvalid("Handle is not bound to the requested project.")
        return {"handle": handle, "user_id": user_id, "project_id": project_id,
                "expires_at": row["expires_at"]}

    def revoke_handle(self, handle: str, user_id: str) -> dict[str, Any]:
        con = self._con()
        with _LOCK:
            cur = con.execute("UPDATE cp_handle SET revoked=1 WHERE handle=? AND user_id=?",
                              (handle, user_id))
            con.commit()
        return {"revoked": cur.rowcount > 0}

    # --- assignments ------------------------------------------------------
    def create_assignment(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "assignment_id": record.get("assignment_id") or _uid("asg"),
            "project_id": record["project_id"],
            "user_id": record["user_id"],
            "owner_id": record.get("owner_id"),
            "job_order_id": record.get("job_order_id"),
            "title": record.get("title"),
            "mode": record.get("mode", "assisted"),
            "stage": int(record.get("stage", 0)),
            "status": record.get("status", "created"),
            "known_target_total": record.get("known_target_total"),
            "created_at": _now(),
            "updated_at": _now(),
            "metadata_json": json.dumps(record.get("metadata", {}), sort_keys=True),
        }
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_assignment(assignment_id,project_id,user_id,owner_id,job_order_id,"
                "title,mode,stage,status,known_target_total,created_at,updated_at,metadata_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(rec[k] for k in ("assignment_id", "project_id", "user_id", "owner_id",
                                       "job_order_id", "title", "mode", "stage", "status",
                                       "known_target_total", "created_at", "updated_at",
                                       "metadata_json")),
            )
            con.commit()
        return self._assignment_out(rec)

    @staticmethod
    def _assignment_out(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
        return d

    def get_assignment(self, assignment_id: str, project_id: str) -> dict[str, Any] | None:
        row = self._con().execute(
            "SELECT * FROM cp_assignment WHERE assignment_id=? AND project_id=?",
            (assignment_id, project_id),
        ).fetchone()
        return self._assignment_out(row) if row else None

    def update_assignment(self, assignment_id: str, project_id: str, **fields: Any) -> dict[str, Any]:
        allowed = {"owner_id", "job_order_id", "title", "mode", "stage", "status",
                   "known_target_total", "metadata"}
        sets, vals = [], []
        for key, value in fields.items():
            if key not in allowed:
                continue
            if key == "metadata":
                sets.append("metadata_json=?")
                vals.append(json.dumps(value, sort_keys=True))
            else:
                sets.append(f"{key}=?")
                vals.append(value)
        sets.append("updated_at=?")
        vals.append(_now())
        vals += [assignment_id, project_id]
        con = self._con()
        with _LOCK:
            con.execute(
                f"UPDATE cp_assignment SET {','.join(sets)} WHERE assignment_id=? AND project_id=?",
                tuple(vals),
            )
            con.commit()
        out = self.get_assignment(assignment_id, project_id)
        if out is None:
            raise KeyError(assignment_id)
        return out

    def list_assignments(self, project_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._con().execute(
            "SELECT * FROM cp_assignment WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
            (project_id, int(limit)),
        ).fetchall()
        return [self._assignment_out(r) for r in rows]

    # --- stage artifacts --------------------------------------------------
    def append_stage_artifact(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "artifact_id": record.get("artifact_id") or _uid("art"),
            "assignment_id": record["assignment_id"],
            "project_id": record["project_id"],
            "stage": int(record["stage"]),
            "stage_name": record["stage_name"],
            "tier": record.get("tier", "T1"),
            "status": record.get("status", "ok"),
            "payload_json": json.dumps(record.get("payload", {}), sort_keys=True),
            "evidence_json": json.dumps(record.get("evidence", []), sort_keys=True),
            "version_hash": record["version_hash"],
            "created_at": _now(),
        }
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_stage_artifact(artifact_id,assignment_id,project_id,stage,stage_name,"
                "tier,status,payload_json,evidence_json,version_hash,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                tuple(rec.values()),
            )
            con.commit()
        return self._artifact_out(rec)

    @staticmethod
    def _artifact_out(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["payload"] = json.loads(d.pop("payload_json", "{}") or "{}")
        d["evidence"] = json.loads(d.pop("evidence_json", "[]") or "[]")
        return d

    def list_stage_artifacts(self, assignment_id: str, project_id: str) -> list[dict[str, Any]]:
        rows = self._con().execute(
            "SELECT * FROM cp_stage_artifact WHERE assignment_id=? AND project_id=?"
            " ORDER BY stage, created_at",
            (assignment_id, project_id),
        ).fetchall()
        return [self._artifact_out(r) for r in rows]

    # --- exceptions -------------------------------------------------------
    def append_exception(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "exception_id": record.get("exception_id") or _uid("exc"),
            "project_id": record["project_id"],
            "assignment_id": record.get("assignment_id"),
            "stage": record.get("stage"),
            "severity": record.get("severity", "warn"),
            "kind": record["kind"],
            "detail_json": json.dumps(record.get("detail", {}), sort_keys=True),
            "status": "open",
            "resolved_by": None,
            "resolution": None,
            "created_at": _now(),
            "resolved_at": None,
        }
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_exception(exception_id,project_id,assignment_id,stage,severity,kind,"
                "detail_json,status,resolved_by,resolution,created_at,resolved_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(rec.values()),
            )
            con.commit()
        return self._exception_out(rec)

    @staticmethod
    def _exception_out(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["detail"] = json.loads(d.pop("detail_json", "{}") or "{}")
        return d

    def list_exceptions(self, project_id: str, assignment_id: str | None = None,
                        status: str = "open", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cp_exception WHERE project_id=?"
        params: list[Any] = [project_id]
        if assignment_id:
            sql += " AND assignment_id=?"
            params.append(assignment_id)
        if status and status != "all":
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(int(limit))
        return [self._exception_out(r) for r in self._con().execute(sql, tuple(params)).fetchall()]

    def resolve_exception(self, exception_id: str, project_id: str, actor: str,
                          resolution: str) -> dict[str, Any]:
        con = self._con()
        with _LOCK:
            con.execute(
                "UPDATE cp_exception SET status='resolved',resolved_by=?,resolution=?,resolved_at=?"
                " WHERE exception_id=? AND project_id=?",
                (actor, resolution, _now(), exception_id, project_id),
            )
            con.commit()
        row = con.execute("SELECT * FROM cp_exception WHERE exception_id=?", (exception_id,)).fetchone()
        return self._exception_out(row) if row else {"exception_id": exception_id, "status": "unknown"}

    # --- approvals --------------------------------------------------------
    def record_approval(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "approval_id": record.get("approval_id") or _uid("apr"),
            "project_id": record["project_id"],
            "assignment_id": record["assignment_id"],
            "gate": record["gate"],
            "actor": record["actor"],
            "decision": record["decision"],
            "rationale": record.get("rationale"),
            "idempotency_key": record.get("idempotency_key"),
            "approval_json": json.dumps(record.get("approval", {}), sort_keys=True),
            "created_at": _now(),
        }
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_approval(approval_id,project_id,assignment_id,gate,actor,decision,"
                "rationale,idempotency_key,approval_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                tuple(rec.values()),
            )
            con.commit()
        out = dict(rec)
        out["approval"] = json.loads(out.pop("approval_json"))
        return out

    def latest_approval(self, assignment_id: str, project_id: str, gate: str) -> dict[str, Any] | None:
        row = self._con().execute(
            "SELECT * FROM cp_approval WHERE assignment_id=? AND project_id=? AND gate=?"
            " ORDER BY created_at DESC LIMIT 1",
            (assignment_id, project_id, gate),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["approval"] = json.loads(d.pop("approval_json", "{}") or "{}")
        return d

    # --- idempotency ------------------------------------------------------
    def claim_idempotency_key(self, key: str, user_id: str, fingerprint: str,
                              result: dict[str, Any] | None = None) -> tuple[bool, dict[str, Any] | None]:
        con = self._con()
        with _LOCK:
            row = con.execute(
                "SELECT * FROM cp_idempotency WHERE idempotency_key=?", (key,)
            ).fetchone()
            if row is not None:
                if row["user_id"] != user_id or row["fingerprint"] != fingerprint:
                    raise PermissionError(
                        "Idempotency key was already used with a different actor or payload."
                    )
                prior = json.loads(row["result_json"]) if row["result_json"] else None
                return False, prior
            con.execute(
                "INSERT INTO cp_idempotency(idempotency_key,user_id,fingerprint,result_json,created_at)"
                " VALUES(?,?,?,?,?)",
                (key, user_id, fingerprint,
                 json.dumps(result, sort_keys=True) if result is not None else None, _now()),
            )
            con.commit()
        return True, None

    # --- audit ------------------------------------------------------------
    def append_audit(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "audit_id": record.get("audit_id") or _uid("aud"),
            "project_id": record.get("project_id"),
            "user_id": record.get("user_id"),
            "actor": record.get("actor"),
            "action": record["action"],
            "correlation_id": record.get("correlation_id"),
            "detail_json": json.dumps(record.get("detail", {}), sort_keys=True),
            "created_at": _now(),
        }
        con = self._con()
        with _LOCK:
            con.execute(
                "INSERT INTO cp_audit(audit_id,project_id,user_id,actor,action,correlation_id,"
                "detail_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                tuple(rec.values()),
            )
            con.commit()
        out = dict(rec)
        out["detail"] = json.loads(out.pop("detail_json"))
        return out

    def list_audit(self, project_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if project_id:
            rows = self._con().execute(
                "SELECT * FROM cp_audit WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
                (project_id, int(limit)),
            ).fetchall()
        else:
            rows = self._con().execute(
                "SELECT * FROM cp_audit ORDER BY created_at DESC LIMIT ?", (int(limit),)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.pop("detail_json", "{}") or "{}")
            out.append(d)
        return out

    def counts(self) -> dict[str, int]:
        con = self._con()
        tables = ("cp_handle", "cp_assignment", "cp_stage_artifact", "cp_exception",
                  "cp_approval", "cp_audit")
        return {t.replace("cp_", ""): con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in tables}
