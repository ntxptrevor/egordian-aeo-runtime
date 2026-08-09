"""Versioned control-plane migrations.

The same logical schema is emitted for SQLite (private preview overlay
``data.db``) and PostgreSQL (durable production). The immutable licensed
catalogue database is NEVER touched by these migrations - it lives in a
physically separate, read-only, ``immutable=1`` file.
"""
from __future__ import annotations

SQLITE: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS cp_handle (
            handle TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            project_ids TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_handle_user ON cp_handle(user_id);

        CREATE TABLE IF NOT EXISTS cp_assignment (
            assignment_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            owner_id TEXT,
            job_order_id TEXT,
            title TEXT,
            mode TEXT NOT NULL DEFAULT 'assisted',
            stage INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'created',
            known_target_total REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_assignment_project ON cp_assignment(project_id);

        CREATE TABLE IF NOT EXISTS cp_stage_artifact (
            artifact_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            stage INTEGER NOT NULL,
            stage_name TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            version_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_artifact_assignment ON cp_stage_artifact(assignment_id);

        CREATE TABLE IF NOT EXISTS cp_exception (
            exception_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            assignment_id TEXT,
            stage INTEGER,
            severity TEXT NOT NULL DEFAULT 'warn',
            kind TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            resolved_by TEXT,
            resolution TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_exception_project ON cp_exception(project_id, status);

        CREATE TABLE IF NOT EXISTS cp_approval (
            approval_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            assignment_id TEXT NOT NULL,
            gate TEXT NOT NULL,
            actor TEXT NOT NULL,
            decision TEXT NOT NULL,
            rationale TEXT,
            idempotency_key TEXT,
            approval_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_approval_assignment ON cp_approval(assignment_id, gate);

        CREATE TABLE IF NOT EXISTS cp_idempotency (
            idempotency_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            result_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cp_audit (
            audit_id TEXT PRIMARY KEY,
            project_id TEXT,
            user_id TEXT,
            actor TEXT,
            action TEXT NOT NULL,
            correlation_id TEXT,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON cp_audit(created_at);
        """,
    ),
]

POSTGRES: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS cp_handle (
            handle TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            project_ids JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE INDEX IF NOT EXISTS idx_handle_user ON cp_handle(user_id);

        CREATE TABLE IF NOT EXISTS cp_assignment (
            assignment_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            owner_id TEXT,
            job_order_id TEXT,
            title TEXT,
            mode TEXT NOT NULL DEFAULT 'assisted',
            stage INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'created',
            known_target_total NUMERIC,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
        );
        CREATE INDEX IF NOT EXISTS idx_assignment_project ON cp_assignment(project_id);

        CREATE TABLE IF NOT EXISTS cp_stage_artifact (
            artifact_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            stage INTEGER NOT NULL,
            stage_name TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json JSONB NOT NULL,
            evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            version_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_artifact_assignment ON cp_stage_artifact(assignment_id);

        CREATE TABLE IF NOT EXISTS cp_exception (
            exception_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            assignment_id TEXT,
            stage INTEGER,
            severity TEXT NOT NULL DEFAULT 'warn',
            kind TEXT NOT NULL,
            detail_json JSONB NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            resolved_by TEXT,
            resolution TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            resolved_at TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_exception_project ON cp_exception(project_id, status);

        CREATE TABLE IF NOT EXISTS cp_approval (
            approval_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            assignment_id TEXT NOT NULL,
            gate TEXT NOT NULL,
            actor TEXT NOT NULL,
            decision TEXT NOT NULL,
            rationale TEXT,
            idempotency_key TEXT,
            approval_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_approval_assignment ON cp_approval(assignment_id, gate);

        CREATE TABLE IF NOT EXISTS cp_idempotency (
            idempotency_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            result_json JSONB,
            created_at TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cp_audit (
            audit_id TEXT PRIMARY KEY,
            project_id TEXT,
            user_id TEXT,
            actor TEXT,
            action TEXT NOT NULL,
            correlation_id TEXT,
            detail_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON cp_audit(created_at);
        """,
    ),
]
