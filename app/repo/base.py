"""Repository abstraction for the control plane / overlay store.

The service process itself is horizontally stateless: no MCP session, no
sticky routing, no in-process request state that survives a response. Every
piece of cross-call state lives behind this interface so the same code runs on
a local SQLite overlay (private preview) or on PostgreSQL (durable
production / Supabase / Hostinger) with no filesystem reliance.
"""
from __future__ import annotations

import abc
from typing import Any, Iterable


class RepositoryError(RuntimeError):
    pass


class HandleInvalid(PermissionError):
    """Opaque handle missing, expired, or not bound to this user/project."""


class Repository(abc.ABC):
    backend: str = "abstract"

    # --- lifecycle --------------------------------------------------------
    @abc.abstractmethod
    def migrate(self) -> dict[str, Any]:
        """Apply all pending migrations idempotently. Returns applied versions."""

    @abc.abstractmethod
    def health(self) -> dict[str, Any]:
        ...

    # --- handles (explicit, opaque, user+project bound, expiring) ---------
    @abc.abstractmethod
    def create_handle(self, user_id: str, project_ids: Iterable[str], ttl_hours: int) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def validate_handle(self, handle: str, user_id: str, project_id: str) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def revoke_handle(self, handle: str, user_id: str) -> dict[str, Any]:
        ...

    # --- AEO assignments --------------------------------------------------
    @abc.abstractmethod
    def create_assignment(self, record: dict[str, Any]) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def get_assignment(self, assignment_id: str, project_id: str) -> dict[str, Any] | None:
        ...

    @abc.abstractmethod
    def update_assignment(self, assignment_id: str, project_id: str, **fields: Any) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def list_assignments(self, project_id: str, limit: int = 50) -> list[dict[str, Any]]:
        ...

    # --- stage artifacts --------------------------------------------------
    @abc.abstractmethod
    def append_stage_artifact(self, record: dict[str, Any]) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def list_stage_artifacts(self, assignment_id: str, project_id: str) -> list[dict[str, Any]]:
        ...

    # --- exceptions -------------------------------------------------------
    @abc.abstractmethod
    def append_exception(self, record: dict[str, Any]) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def list_exceptions(self, project_id: str, assignment_id: str | None = None,
                        status: str = "open", limit: int = 100) -> list[dict[str, Any]]:
        ...

    @abc.abstractmethod
    def resolve_exception(self, exception_id: str, project_id: str, actor: str,
                          resolution: str) -> dict[str, Any]:
        ...

    # --- approvals / gates ------------------------------------------------
    @abc.abstractmethod
    def record_approval(self, record: dict[str, Any]) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def latest_approval(self, assignment_id: str, project_id: str, gate: str) -> dict[str, Any] | None:
        ...

    # --- idempotency ------------------------------------------------------
    @abc.abstractmethod
    def claim_idempotency_key(self, key: str, user_id: str, fingerprint: str,
                              result: dict[str, Any] | None = None) -> tuple[bool, dict[str, Any] | None]:
        """Returns (is_new, prior_result)."""

    # --- audit ------------------------------------------------------------
    @abc.abstractmethod
    def append_audit(self, record: dict[str, Any]) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def list_audit(self, project_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        ...

    # --- counters ---------------------------------------------------------
    @abc.abstractmethod
    def counts(self) -> dict[str, int]:
        ...
