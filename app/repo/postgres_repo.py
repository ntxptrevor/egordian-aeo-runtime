"""PostgreSQL control-plane repository (durable production / Supabase / Hostinger).

Selected automatically when ``DATABASE_URL`` is set. Requires the optional
``psycopg[binary]`` dependency. The schema is identical in meaning to the
SQLite overlay (see ``migrations.POSTGRES``) so the service can be moved
between backends without any code change and without local filesystem
reliance.

This adapter is exercised by contract tests against the abstract interface;
a live PostgreSQL instance is required for end-to-end verification and none is
available in the build environment, so it is shipped as a migration-complete
adapter rather than a live-tested path.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .base import HandleInvalid, Repository, RepositoryError
from .migrations import POSTGRES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _iso(value: Any) -> Any:
    return value.isoformat(timespec="seconds") if isinstance(value, datetime) else value


class PostgresRepository(Repository):
    backend = "postgres"

    def __init__(self, dsn: str):
        try:
            import psycopg  # noqa: F401
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RepositoryError(
                "DATABASE_URL is set but psycopg[binary]/psycopg_pool is not installed."
            ) from exc
        self.dsn = dsn
        self._pool = ConnectionPool(dsn, min_size=1, max_size=10, open=True)
        self.migrate()

    def _rows(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        from psycopg.rows import dict_row
        with self._pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                if cur.description is None:
                    return []
                return [dict(r) for r in cur.fetchall()]

    def _exec(self, sql: str, params: tuple = ()) -> int:
        with self._pool.connection() as con:
            with con.cursor() as cur:
                cur.execute(sql, params)
                return cur.rowcount

    # --- lifecycle --------------------------------------------------------
    def migrate(self) -> dict[str, Any]:
        self._exec("CREATE TABLE IF NOT EXISTS cp_migration ("
                   "version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)")
        done = {r["version"] for r in self._rows("SELECT version FROM cp_migration")}
        applied = []
        for version, sql in POSTGRES:
            if version in done:
                continue
            with self._pool.connection() as con:
                with con.cursor() as cur:
                    cur.execute(sql)
                    cur.execute("INSERT INTO cp_migration VALUES(%s,%s)", (version, _now()))
            applied.append(version)
        return {"backend": self.backend, "applied": applied,
                "current_version": max(v for v, _ in POSTGRES)}

    def health(self) -> dict[str, Any]:
        try:
            self._rows("SELECT 1 AS ok")
            return {"ok": True, "backend": self.backend}
        except Exception as exc:  # pragma: no cover - defensive
            return {"ok": False, "backend": self.backend, "error": type(exc).__name__}

    # --- handles ----------------------------------------------------------
    def create_handle(self, user_id: str, project_ids: Iterable[str], ttl_hours: int) -> dict[str, Any]:
        pids = sorted({str(p) for p in project_ids if str(p).strip()})
        if not pids:
            raise ValueError("At least one project_id is required for a handle.")
        handle = secrets.token_urlsafe(32)
        created = _now()
        expires = created + timedelta(hours=max(1, min(int(ttl_hours), 24)))
        self._exec(
            "INSERT INTO cp_handle(handle,user_id,project_ids,created_at,expires_at,revoked)"
            " VALUES(%s,%s,%s,%s,%s,FALSE)",
            (handle, user_id, json.dumps(pids), created, expires),
        )
        return {"handle": handle, "user_id": user_id, "project_ids": pids,
                "expires_at": expires.isoformat(timespec="seconds")}

    def validate_handle(self, handle: str, user_id: str, project_id: str) -> dict[str, Any]:
        if not handle or len(handle) < 32:
            raise HandleInvalid("A valid opaque handle is required on every call.")
        rows = self._rows("SELECT * FROM cp_handle WHERE handle=%s", (handle,))
        if not rows or rows[0]["revoked"]:
            raise HandleInvalid("Handle is unknown or revoked.")
        row = rows[0]
        if row["user_id"] != user_id:
            raise HandleInvalid("Handle is not bound to the authenticated user.")
        if row["expires_at"] <= _now():
            raise HandleInvalid("Handle has expired; request a new one.")
        pids = row["project_ids"] if isinstance(row["project_ids"], list) else json.loads(row["project_ids"])
        if project_id not in pids:
            raise HandleInvalid("Handle is not bound to the requested project.")
        return {"handle": handle, "user_id": user_id, "project_id": project_id,
                "expires_at": _iso(row["expires_at"])}

    def revoke_handle(self, handle: str, user_id: str) -> dict[str, Any]:
        n = self._exec("UPDATE cp_handle SET revoked=TRUE WHERE handle=%s AND user_id=%s",
                       (handle, user_id))
        return {"revoked": n > 0}

    # --- assignments ------------------------------------------------------
    def create_assignment(self, record: dict[str, Any]) -> dict[str, Any]:
        aid = record.get("assignment_id") or _uid("asg")
        now = _now()
        self._exec(
            "INSERT INTO cp_assignment(assignment_id,project_id,user_id,owner_id,job_order_id,title,"
            "mode,stage,status,known_target_total,created_at,updated_at,metadata_json)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (aid, record["project_id"], record["user_id"], record.get("owner_id"),
             record.get("job_order_id"), record.get("title"), record.get("mode", "assisted"),
             int(record.get("stage", 0)), record.get("status", "created"),
             record.get("known_target_total"), now, now,
             json.dumps(record.get("metadata", {}), sort_keys=True)),
        )
        out = self.get_assignment(aid, record["project_id"])
        assert out is not None
        return out

    @staticmethod
    def _out(row: dict[str, Any], json_field: str, key: str) -> dict[str, Any]:
        d = dict(row)
        raw = d.pop(json_field, None)
        d[key] = raw if isinstance(raw, (dict, list)) else json.loads(raw or "{}")
        for k, v in list(d.items()):
            d[k] = _iso(v)
        return d

    def get_assignment(self, assignment_id: str, project_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT * FROM cp_assignment WHERE assignment_id=%s AND project_id=%s",
                          (assignment_id, project_id))
        return self._out(rows[0], "metadata_json", "metadata") if rows else None

    def update_assignment(self, assignment_id: str, project_id: str, **fields: Any) -> dict[str, Any]:
        allowed = {"owner_id", "job_order_id", "title", "mode", "stage", "status",
                   "known_target_total", "metadata"}
        sets, vals = [], []
        for key, value in fields.items():
            if key not in allowed:
                continue
            if key == "metadata":
                sets.append("metadata_json=%s")
                vals.append(json.dumps(value, sort_keys=True))
            else:
                sets.append(f"{key}=%s")
                vals.append(value)
        sets.append("updated_at=%s")
        vals.append(_now())
        vals += [assignment_id, project_id]
        self._exec(f"UPDATE cp_assignment SET {','.join(sets)} WHERE assignment_id=%s AND project_id=%s",
                   tuple(vals))
        out = self.get_assignment(assignment_id, project_id)
        if out is None:
            raise KeyError(assignment_id)
        return out

    def list_assignments(self, project_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._rows("SELECT * FROM cp_assignment WHERE project_id=%s"
                          " ORDER BY created_at DESC LIMIT %s", (project_id, int(limit)))
        return [self._out(r, "metadata_json", "metadata") for r in rows]

    # --- stage artifacts --------------------------------------------------
    def append_stage_artifact(self, record: dict[str, Any]) -> dict[str, Any]:
        art_id = record.get("artifact_id") or _uid("art")
        self._exec(
            "INSERT INTO cp_stage_artifact(artifact_id,assignment_id,project_id,stage,stage_name,tier,"
            "status,payload_json,evidence_json,version_hash,created_at)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (art_id, record["assignment_id"], record["project_id"], int(record["stage"]),
             record["stage_name"], record.get("tier", "T1"), record.get("status", "ok"),
             json.dumps(record.get("payload", {}), sort_keys=True),
             json.dumps(record.get("evidence", []), sort_keys=True),
             record["version_hash"], _now()),
        )
        rows = self._rows("SELECT * FROM cp_stage_artifact WHERE artifact_id=%s", (art_id,))
        return self._artifact_out(rows[0])

    @staticmethod
    def _artifact_out(row: dict[str, Any]) -> dict[str, Any]:
        d = dict(row)
        for src, key in (("payload_json", "payload"), ("evidence_json", "evidence")):
            raw = d.pop(src, None)
            d[key] = raw if isinstance(raw, (dict, list)) else json.loads(raw or "{}")
        for k, v in list(d.items()):
            d[k] = _iso(v)
        return d

    def list_stage_artifacts(self, assignment_id: str, project_id: str) -> list[dict[str, Any]]:
        rows = self._rows("SELECT * FROM cp_stage_artifact WHERE assignment_id=%s AND project_id=%s"
                          " ORDER BY stage, created_at", (assignment_id, project_id))
        return [self._artifact_out(r) for r in rows]

    # --- exceptions -------------------------------------------------------
    def append_exception(self, record: dict[str, Any]) -> dict[str, Any]:
        exc_id = record.get("exception_id") or _uid("exc")
        self._exec(
            "INSERT INTO cp_exception(exception_id,project_id,assignment_id,stage,severity,kind,"
            "detail_json,status,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,'open',%s)",
            (exc_id, record["project_id"], record.get("assignment_id"), record.get("stage"),
             record.get("severity", "warn"), record["kind"],
             json.dumps(record.get("detail", {}), sort_keys=True), _now()),
        )
        rows = self._rows("SELECT * FROM cp_exception WHERE exception_id=%s", (exc_id,))
        return self._out(rows[0], "detail_json", "detail")

    def list_exceptions(self, project_id: str, assignment_id: str | None = None,
                        status: str = "open", limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cp_exception WHERE project_id=%s"
        params: list[Any] = [project_id]
        if assignment_id:
            sql += " AND assignment_id=%s"
            params.append(assignment_id)
        if status and status != "all":
            sql += " AND status=%s"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT %s"
        params.append(int(limit))
        return [self._out(r, "detail_json", "detail") for r in self._rows(sql, tuple(params))]

    def resolve_exception(self, exception_id: str, project_id: str, actor: str,
                          resolution: str) -> dict[str, Any]:
        self._exec(
            "UPDATE cp_exception SET status='resolved',resolved_by=%s,resolution=%s,resolved_at=%s"
            " WHERE exception_id=%s AND project_id=%s",
            (actor, resolution, _now(), exception_id, project_id),
        )
        rows = self._rows("SELECT * FROM cp_exception WHERE exception_id=%s", (exception_id,))
        return self._out(rows[0], "detail_json", "detail") if rows else {
            "exception_id": exception_id, "status": "unknown"}

    # --- approvals --------------------------------------------------------
    def record_approval(self, record: dict[str, Any]) -> dict[str, Any]:
        apr_id = record.get("approval_id") or _uid("apr")
        self._exec(
            "INSERT INTO cp_approval(approval_id,project_id,assignment_id,gate,actor,decision,"
            "rationale,idempotency_key,approval_json,created_at)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (apr_id, record["project_id"], record["assignment_id"], record["gate"], record["actor"],
             record["decision"], record.get("rationale"), record.get("idempotency_key"),
             json.dumps(record.get("approval", {}), sort_keys=True), _now()),
        )
        rows = self._rows("SELECT * FROM cp_approval WHERE approval_id=%s", (apr_id,))
        return self._out(rows[0], "approval_json", "approval")

    def latest_approval(self, assignment_id: str, project_id: str, gate: str) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM cp_approval WHERE assignment_id=%s AND project_id=%s AND gate=%s"
            " ORDER BY created_at DESC LIMIT 1", (assignment_id, project_id, gate))
        return self._out(rows[0], "approval_json", "approval") if rows else None

    # --- idempotency ------------------------------------------------------
    def claim_idempotency_key(self, key: str, user_id: str, fingerprint: str,
                              result: dict[str, Any] | None = None) -> tuple[bool, dict[str, Any] | None]:
        rows = self._rows("SELECT * FROM cp_idempotency WHERE idempotency_key=%s", (key,))
        if rows:
            row = rows[0]
            if row["user_id"] != user_id or row["fingerprint"] != fingerprint:
                raise PermissionError(
                    "Idempotency key was already used with a different actor or payload.")
            raw = row["result_json"]
            prior = raw if isinstance(raw, dict) else (json.loads(raw) if raw else None)
            return False, prior
        self._exec(
            "INSERT INTO cp_idempotency(idempotency_key,user_id,fingerprint,result_json,created_at)"
            " VALUES(%s,%s,%s,%s,%s)",
            (key, user_id, fingerprint,
             json.dumps(result, sort_keys=True) if result is not None else None, _now()),
        )
        return True, None

    # --- audit ------------------------------------------------------------
    def append_audit(self, record: dict[str, Any]) -> dict[str, Any]:
        aud_id = record.get("audit_id") or _uid("aud")
        self._exec(
            "INSERT INTO cp_audit(audit_id,project_id,user_id,actor,action,correlation_id,"
            "detail_json,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (aud_id, record.get("project_id"), record.get("user_id"), record.get("actor"),
             record["action"], record.get("correlation_id"),
             json.dumps(record.get("detail", {}), sort_keys=True), _now()),
        )
        rows = self._rows("SELECT * FROM cp_audit WHERE audit_id=%s", (aud_id,))
        return self._out(rows[0], "detail_json", "detail")

    def list_audit(self, project_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if project_id:
            rows = self._rows("SELECT * FROM cp_audit WHERE project_id=%s"
                              " ORDER BY created_at DESC LIMIT %s", (project_id, int(limit)))
        else:
            rows = self._rows("SELECT * FROM cp_audit ORDER BY created_at DESC LIMIT %s", (int(limit),))
        return [self._out(r, "detail_json", "detail") for r in rows]

    def counts(self) -> dict[str, int]:
        out = {}
        for t in ("cp_handle", "cp_assignment", "cp_stage_artifact", "cp_exception",
                  "cp_approval", "cp_audit"):
            out[t.replace("cp_", "")] = self._rows(f"SELECT COUNT(*) AS n FROM {t}")[0]["n"]
        return out
