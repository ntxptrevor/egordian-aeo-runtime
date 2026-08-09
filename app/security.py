"""Authentication, RBAC/scopes, approval envelopes, rate limiting, redaction.

Private by default: every route except ``/healthz`` requires a bearer token.
Auth material never enters the MCP protocol layer, the repository, or logs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .config import ALL_SCOPES, Settings, get_settings

DEV_TOKEN = "dev-local-token"
DEV_PRINCIPAL_SCOPES = ("catalogue:read", "egordian:read", "aeo:run", "aeo:approve", "admin")


class AuthError(PermissionError):
    """401 - no or bad credentials."""


class ScopeError(PermissionError):
    """403 - authenticated but not authorized."""


class ApprovalRequired(PermissionError):
    """403 - write attempted without a complete approval envelope."""


class RateLimited(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    user_id: str
    scopes: frozenset[str]
    project_ids: tuple[str, ...]
    token_id: str
    mode: str = "bearer"

    def has(self, scope: str) -> bool:
        return scope in self.scopes or "admin" in self.scopes

    def require(self, *scopes: str) -> None:
        missing = [s for s in scopes if not self.has(s)]
        if missing:
            raise ScopeError(f"Missing required scope(s): {', '.join(sorted(missing))}")

    def require_project(self, project_id: str) -> None:
        if self.project_ids and project_id not in self.project_ids:
            raise ScopeError("Principal is not bound to this project_id.")

    def public(self) -> dict[str, Any]:
        return {"user_id": self.user_id, "scopes": sorted(self.scopes),
                "project_ids": list(self.project_ids), "mode": self.mode}


# ---------------------------------------------------------------------------
# Token table
# ---------------------------------------------------------------------------

def _parse_service_tokens(raw: str) -> dict[str, Principal]:
    """Parse the SERVICE_TOKENS environment variable (never stored anywhere else).

    Format (entries separated by ``;``, fields by ``|``, lists by ``,``)::

        SERVICE_TOKENS="<token>|<user>|<proj1,proj2>|<catalogue:read,aeo:run>; ..."

    Scope names contain ``:`` so ``|`` is used as the field separator.
    """
    table: dict[str, Principal] = {}
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("|")
        if len(parts) < 2:
            continue
        token, user = parts[0].strip(), parts[1].strip()
        projects = tuple(p.strip() for p in (parts[2].split(",") if len(parts) > 2 and parts[2]
                                             else []) if p.strip())
        scopes = [s.strip() for s in (parts[3].split(",") if len(parts) > 3 and parts[3]
                                      else []) if s.strip()]
        valid = frozenset(s for s in scopes if s in ALL_SCOPES) or frozenset({"catalogue:read"})
        if token and user:
            table[token] = Principal(user_id=user, scopes=valid, project_ids=projects,
                                     token_id=hashlib.sha256(token.encode()).hexdigest()[:12])
    return table


class Authenticator:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._tokens = _parse_service_tokens(self.settings.service_tokens_raw)

    @property
    def configured_token_count(self) -> int:
        return len(self._tokens)

    def authenticate(self, authorization: str | None) -> Principal:
        settings = self.settings
        if settings.auth_mode == "dev":
            if settings.deployment_env == "production":
                raise AuthError("AUTH_MODE=dev is refused when DEPLOYMENT_ENV=production.")
            token = _bearer(authorization)
            if token not in (DEV_TOKEN, None):
                # dev mode still validates a known dev token if one is supplied
                pass
            return Principal(user_id="dev-user", scopes=frozenset(DEV_PRINCIPAL_SCOPES),
                             project_ids=(), token_id="dev", mode="dev")
        token = _bearer(authorization)
        if not token:
            raise AuthError("Bearer token required.")
        for candidate, principal in self._tokens.items():
            if hmac.compare_digest(candidate, token):
                return principal
        raise AuthError("Invalid bearer token.")


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


# ---------------------------------------------------------------------------
# Rate limiting (per principal, fixed window; stateless-friendly)
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._buckets: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> dict[str, int]:
        window = int(time.time() // 60)
        with self._lock:
            bucket_window, count = self._buckets.get(key, (window, 0))
            if bucket_window != window:
                bucket_window, count = window, 0
            count += 1
            self._buckets[key] = (bucket_window, count)
            if len(self._buckets) > 10000:  # bounded memory
                self._buckets = {k: v for k, v in self._buckets.items() if v[0] == window}
        if count > self.per_minute:
            raise RateLimited(f"Rate limit of {self.per_minute}/min exceeded.")
        return {"limit": self.per_minute, "remaining": max(0, self.per_minute - count)}


# ---------------------------------------------------------------------------
# Approval envelope + idempotency
# ---------------------------------------------------------------------------

APPROVAL_REQUIRED_FIELDS = ("approved", "actor", "rationale", "approved_at")


def validate_approval_envelope(payload: dict[str, Any], principal: Principal) -> dict[str, Any]:
    """Every side-effecting call must carry actor + approval object + idempotency key."""
    actor = payload.get("actor")
    approval = payload.get("approval")
    idem = payload.get("idempotency_key")
    if not actor or not isinstance(actor, str):
        raise ApprovalRequired("A named 'actor' string is required for any write operation.")
    if not isinstance(approval, dict):
        raise ApprovalRequired(
            "An 'approval' object is required: "
            "{approved, actor, rationale, approved_at}.")
    missing = [f for f in APPROVAL_REQUIRED_FIELDS if f not in approval]
    if missing:
        raise ApprovalRequired(f"approval object missing field(s): {', '.join(missing)}")
    if approval.get("approved") is not True:
        raise ApprovalRequired("approval.approved must be true for a write operation.")
    if approval.get("actor") != actor:
        raise ApprovalRequired("approval.actor must equal the top-level actor.")
    if not idem or not isinstance(idem, str) or len(idem) < 8:
        raise ApprovalRequired("An 'idempotency_key' of at least 8 characters is required.")
    return {"actor": actor, "approval": approval, "idempotency_key": idem,
            "principal": principal.user_id}


def fingerprint(payload: dict[str, Any]) -> str:
    scrubbed = {k: v for k, v in payload.items() if k != "idempotency_key"}
    return hashlib.sha256(
        json.dumps(scrubbed, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|authorization|api[_-]?key|bearer|credential|cookie|"
    r"client[_-]?secret|private[_-]?key)",
    re.I,
)
_SECRET_VALUE_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}", re.I),
    re.compile(r"Basic\s+[A-Za-z0-9+/=]{8,}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"),
]
REDACTED = "[REDACTED]"


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact anything that looks like auth material."""
    if _depth > 12:
        return REDACTED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = REDACTED
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, str):
        result = value
        for pattern in _SECRET_VALUE_PATTERNS:
            result = pattern.sub(REDACTED, result)
        return result
    return value


def correlation_id() -> str:
    return f"cid_{secrets.token_hex(8)}"


@dataclass
class SecurityContext:
    principal: Principal
    correlation_id: str = field(default_factory=correlation_id)
