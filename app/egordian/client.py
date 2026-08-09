"""Hardened eGordian JOC Service Web API client.

Safety properties:
  * Strict allowlist   - only operations present in the fetched Help registry.
  * SSRF prevention    - the base URL host is pinned; no redirects are followed;
                         path/query parameters are percent-encoded and cannot
                         introduce a new scheme, host, or traversal segment.
  * Bounded retries    - idempotent GETs only, with jittered backoff.
  * Response limits    - content-length and streamed byte cap, content-type check.
  * Structured errors  - never raw upstream bodies; correlation ID on every call.
  * Redacted logging   - auth headers and secret-shaped values are scrubbed.
  * Write discipline   - PUT/POST require actor + approval + idempotency key and
                         an explicit capability flag; DELETE and admin routes are
                         disabled and return ``human_gate_required``.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import random
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

from ..config import Settings, get_settings
from ..security import redact
from .auth import AuthProvider, CredentialRequired, build_provider
from .registry import (RISK_ADMIN, RISK_DESTRUCTIVE, RISK_READ, RISK_WRITE, Operation,
                       OperationRegistry, get_registry)

log = logging.getLogger("egordian.client")

ALLOWED_CONTENT_TYPES = ("application/json", "text/json", "application/problem+json")
_RETRY_STATUS = {429, 500, 502, 503, 504}


class EgordianError(RuntimeError):
    """Structured client error carrying a machine-readable code."""

    def __init__(self, code: str, message: str, *, status: int | None = None,
                 detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.detail = detail or {}

    def to_dict(self, correlation_id: str | None = None) -> dict[str, Any]:
        out = {"error": self.code, "message": self.message}
        if self.status is not None:
            out["upstream_status"] = self.status
        if self.detail:
            out["detail"] = redact(self.detail)
        if correlation_id:
            out["correlation_id"] = correlation_id
        return out


class CapabilityBlocked(EgordianError):
    pass


@dataclass
class CallResult:
    operation_id: str
    method: str
    url_template: str
    status: int
    data: Any
    correlation_id: str
    truncated: bool = False
    mode: str = "live"

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "method": self.method,
            "route_template": self.url_template,
            "status": self.status,
            "data": self.data,
            "correlation_id": self.correlation_id,
            "truncated": self.truncated,
            "mode": self.mode,
            "source_documentation_url": "https://jocservice.egordian.com/Help",
        }


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

_FORBIDDEN_SEGMENTS = ("..", "\\", "//")


def encode_path_value(value: Any) -> str:
    """Percent-encode a single path segment value; reject traversal/injection."""
    raw = str(value)
    if raw == "" or raw.strip() != raw:
        raise EgordianError("invalid_parameter", "Path parameter must be a non-empty trimmed value.")
    if any(bad in raw for bad in _FORBIDDEN_SEGMENTS) or "/" in raw:
        raise EgordianError("invalid_parameter",
                            f"Path parameter contains a forbidden character sequence: {raw!r}")
    if "://" in raw or raw.startswith("%2F") or raw.startswith("%2f"):
        raise EgordianError("invalid_parameter", "Path parameter may not contain a URL.")
    return quote(raw, safe="")


def render_route(operation: Operation, path_params: dict[str, Any]) -> str:
    route = operation.route_template
    for name in operation.path_params:
        if name not in path_params:
            raise EgordianError("missing_parameter", f"Missing required path parameter: {name}")
        route = route.replace("{" + name + "}", encode_path_value(path_params[name]))
    if "{" in route or "}" in route:  # pragma: no cover - defensive
        raise EgordianError("missing_parameter", "Unresolved path template placeholders remain.")
    return route


def assert_safe_base_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise EgordianError("ssrf_blocked", "eGordian base URL must use https.")
    if not parts.hostname:
        raise EgordianError("ssrf_blocked", "eGordian base URL has no host.")
    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise EgordianError("ssrf_blocked", "eGordian base URL resolves to a private address.")
    except ValueError:
        pass
    return base_url.rstrip("/")


def resolves_to_public_address(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
    return True


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class EgordianClient:
    def __init__(self, settings: Settings | None = None,
                 registry: OperationRegistry | None = None,
                 transport: httpx.BaseTransport | None = None,
                 provider: AuthProvider | None = None):
        self.settings = settings or get_settings()
        self.registry = registry or get_registry()
        self.base_url = assert_safe_base_url(self.settings.egordian_base_url)
        self.provider = provider or build_provider(self.settings)
        self._transport = transport

    # --- capability reporting --------------------------------------------
    def status(self) -> dict[str, Any]:
        auth = self.provider.status()
        return {
            "base_url": self.base_url,
            "auth": auth,
            "connected": bool(auth.get("connected")),
            "state": "connected" if auth.get("connected") else "disconnected",
            "writes_enabled": self.settings.allow_egordian_writes,
            "write_mode": self.settings.egordian_write_mode,
            "delete_enabled": self.settings.allow_egordian_delete,
            "admin_enabled": self.settings.allow_admin_operations,
            "operation_counts": self.registry.counts(),
            "capability_gaps": self.registry.capability_gaps(),
        }

    # --- gating -----------------------------------------------------------
    def check_capability(self, operation: Operation, *, envelope: dict[str, Any] | None = None,
                         has_write_scope: bool = False, has_admin_scope: bool = False) -> None:
        if operation.risk == RISK_DESTRUCTIVE:
            raise CapabilityBlocked(
                "human_gate_required",
                "DELETE operations are disabled by default and are never executed by this "
                "service. A named human must perform this action directly in eGordian.",
                detail={"operation_id": operation.operation_id, "risk": operation.risk,
                        "source_documentation_url": operation.source_url},
            )
        if operation.risk == RISK_ADMIN:
            if not (self.settings.allow_admin_operations and has_admin_scope):
                raise CapabilityBlocked(
                    "admin_operation_disabled",
                    "This route mutates remote cache/admin state and is disabled by default. "
                    "It requires ALLOW_ADMIN_OPERATIONS=true and the 'admin' scope.",
                    detail={"operation_id": operation.operation_id},
                )
        if operation.risk == RISK_WRITE:
            if not has_write_scope:
                raise CapabilityBlocked(
                    "scope_required",
                    "Write operations require the egordian:write scope.",
                    detail={"operation_id": operation.operation_id},
                )
            if not self.settings.allow_egordian_writes:
                raise CapabilityBlocked(
                    "writes_disabled",
                    "Write operations are disabled for this deployment "
                    "(ALLOW_EGORDIAN_WRITES=false). Default mode is assisted/draft.",
                    detail={"operation_id": operation.operation_id,
                            "write_mode": self.settings.egordian_write_mode},
                )
            if not envelope:
                raise CapabilityBlocked(
                    "approval_required",
                    "A named actor, an approval object, and an idempotency key are required "
                    "for every write operation.",
                    detail={"operation_id": operation.operation_id},
                )

    # --- transport --------------------------------------------------------
    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.settings.egordian_timeout_s),
            follow_redirects=False,
            transport=self._transport,
            headers={"Accept": "application/json",
                     "User-Agent": "egordian-aeo-mcp/1.0 (+private)"},
        )

    def _auth_headers(self, client: httpx.Client) -> dict[str, str]:
        def fetch_json(route: str, headers: dict[str, str]) -> Any:
            response = client.get("/" + route.lstrip("/"), headers=headers)
            if response.status_code >= 400:
                raise EgordianError("auth_failed",
                                    "Access token exchange failed.",
                                    status=response.status_code)
            try:
                return response.json()
            except ValueError:
                return response.text
        return self.provider.headers(fetch_json)

    def call(self, operation_id: str, *, path_params: dict[str, Any] | None = None,
             query: dict[str, Any] | None = None, body: Any = None,
             correlation_id: str = "cid_unknown", envelope: dict[str, Any] | None = None,
             has_write_scope: bool = False, has_admin_scope: bool = False) -> CallResult:
        operation = self.registry.get(operation_id)
        if operation is None:
            raise EgordianError(
                "operation_not_allowlisted",
                f"Unknown operation_id {operation_id!r}. Only operations documented on the "
                "eGordian Help page are callable.",
                detail={"source_documentation_url": "https://jocservice.egordian.com/Help"},
            )
        self.check_capability(operation, envelope=envelope, has_write_scope=has_write_scope,
                              has_admin_scope=has_admin_scope)

        route = render_route(operation, path_params or {})
        allowed_query = set(operation.query_params) | {"pageSize", "pageNumber", "searchTerm"}
        params = {k: v for k, v in (query or {}).items() if k in allowed_query and v is not None}
        if operation.binary_response:
            raise CapabilityBlocked(
                "binary_download_blocked",
                "Binary download routes are not exposed through this service; "
                "metadata-only access is provided.",
                detail={"operation_id": operation.operation_id},
            )

        if not self.settings.egordian_credentials_present and self._transport is None:
            raise EgordianError(
                "credential_required",
                "eGordian credentials are not configured for this deployment. Configure "
                "EGORDIAN_AUTH_PROVIDER and its environment variables to enable live calls.",
                detail={"operation_id": operation.operation_id,
                        "auth_provider": self.settings.egordian_auth_provider},
            )

        url_path = "/" + route
        if params:
            url_path += "?" + urlencode(params, doseq=False, quote_via=quote)

        attempts = 1 + (self.settings.egordian_max_retries if operation.method == "GET" else 0)
        last_error: EgordianError | None = None
        with self._client() as client:
            headers = self._auth_headers(client)
            for attempt in range(attempts):
                try:
                    response = client.request(
                        operation.method, url_path, headers=headers,
                        json=body if operation.method in ("PUT", "POST") else None,
                    )
                except httpx.TimeoutException as exc:
                    last_error = EgordianError("upstream_timeout", "eGordian request timed out.",
                                               detail={"attempt": attempt + 1})
                except httpx.HTTPError as exc:
                    last_error = EgordianError("upstream_unreachable",
                                               "eGordian request failed at the transport layer.",
                                               detail={"kind": type(exc).__name__})
                else:
                    if response.status_code in _RETRY_STATUS and operation.method == "GET" \
                            and attempt + 1 < attempts:
                        time.sleep(min(2.0, 0.2 * (2 ** attempt)) + random.random() * 0.1)
                        continue
                    return self._finalize(operation, response, correlation_id)
                if attempt + 1 < attempts:
                    time.sleep(min(2.0, 0.2 * (2 ** attempt)))
        assert last_error is not None
        log.warning("egordian call failed cid=%s op=%s err=%s", correlation_id,
                    operation.operation_id, last_error.code)
        raise last_error

    def _finalize(self, operation: Operation, response: httpx.Response,
                  correlation_id: str) -> CallResult:
        if response.status_code in (301, 302, 303, 307, 308):
            raise EgordianError("redirect_blocked",
                                "Upstream attempted a redirect; redirects are not followed.",
                                status=response.status_code)
        if response.status_code in (401, 403):
            raise EgordianError("credential_rejected",
                                "eGordian rejected the configured credentials.",
                                status=response.status_code)
        if response.status_code >= 400:
            raise EgordianError("upstream_error",
                                f"eGordian returned HTTP {response.status_code}.",
                                status=response.status_code)
        raw = response.content
        truncated = False
        limit = self.settings.egordian_max_response_bytes
        if len(raw) > limit:
            raw = raw[:limit]
            truncated = True
        content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type and not any(content_type.startswith(t) for t in ALLOWED_CONTENT_TYPES):
            raise EgordianError("unsupported_content_type",
                                f"Unsupported upstream content-type {content_type!r}; "
                                "only JSON responses are accepted.",
                                status=response.status_code)
        try:
            data = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            if truncated:
                raise EgordianError("response_too_large",
                                    "Upstream response exceeded the configured size limit.",
                                    status=response.status_code)
            raise EgordianError("invalid_json", "Upstream response was not valid JSON.",
                                status=response.status_code)
        return CallResult(
            operation_id=operation.operation_id, method=operation.method,
            url_template=operation.route_template, status=response.status_code,
            data=data, correlation_id=correlation_id, truncated=truncated,
        )
