"""MCP protocol revision 2026-07-28 ("MCP 2.0") wire semantics.

Differences from the 2025 revisions that this module implements deliberately:

* Single ``POST /mcp`` endpoint. There is **no** ``initialize`` /
  ``notifications/initialized`` handshake, **no** ``Mcp-Session-Id``, **no**
  ``GET`` event stream, and **no** sticky sessions. Every request is complete
  on its own and any replica can serve it.
* Three request headers are authoritative and are cross-validated against the
  JSON-RPC body:
    - ``MCP-Protocol-Version`` must be exactly ``2026-07-28``
    - ``Mcp-Method``          must equal the body ``method``
    - ``Mcp-Name``            must equal the body's primary target name
      (``params.name`` for ``tools/call``, ``params.uri`` for
      ``resources/read``); it must be absent for name-less methods.
  A mismatch is a protocol error, never a silent coercion.
* Methods: ``server/discover``, ``tools/list``, ``tools/call``,
  ``resources/list``, ``resources/read``.
* Every response carries ``serverInfo`` and, where the revision requires a
  cacheability hint, ``ttlMs`` and ``cacheScope``.
* Requests carry client metadata in ``params._meta`` (``clientInfo``).
* Legacy stateless 2025 clients are only accepted when explicitly enabled and
  are handled on an isolated code path that still refuses to create sessions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import (LEGACY_MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION, SERVICE_NAME,
                      SERVICE_VERSION)

HEADER_PROTOCOL_VERSION = "mcp-protocol-version"
HEADER_METHOD = "mcp-method"
HEADER_NAME = "mcp-name"
HEADER_FORBIDDEN_SESSION = "mcp-session-id"

SUPPORTED_METHODS = (
    "server/discover",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
)

# Methods whose body carries a primary target name that Mcp-Name must mirror.
NAMED_METHODS = {"tools/call": "name", "resources/read": "uri"}

# Cacheability hints required by the revision for discovery-style responses.
CACHE_HINTS: dict[str, dict[str, Any]] = {
    "server/discover": {"ttlMs": 300000, "cacheScope": "server"},
    "tools/list": {"ttlMs": 300000, "cacheScope": "server"},
    "resources/list": {"ttlMs": 60000, "cacheScope": "session-less"},
    "resources/read": {"ttlMs": 30000, "cacheScope": "user"},
    "tools/call": {"ttlMs": 0, "cacheScope": "none"},
}

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# Implementation-defined range
PROTOCOL_HEADER_MISMATCH = -32001
UNAUTHORIZED = -32002
FORBIDDEN = -32003
RATE_LIMITED = -32004
CAPABILITY_BLOCKED = -32005


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, data: dict[str, Any] | None = None,
                 http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data or {}
        self.http_status = http_status


@dataclass
class MCPRequest:
    jsonrpc: str
    id: Any
    method: str
    params: dict[str, Any]
    protocol_version: str
    client_meta: dict[str, Any]
    legacy: bool = False

    @property
    def target_name(self) -> str | None:
        key = NAMED_METHODS.get(self.method)
        return None if key is None else self.params.get(key)


def server_info() -> dict[str, Any]:
    return {
        "name": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "stateless": True,
        "sessions": False,
        "transport": "http-post-json-rpc",
    }


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProtocolError(INVALID_PARAMS, f"{field} must be an object.")
    return value


def parse_request(headers: dict[str, str], body: Any, *,
                  allow_legacy: bool = False) -> MCPRequest:
    """Validate headers against the body and produce a normalized request."""
    lower = {k.lower(): v for k, v in headers.items()}

    if HEADER_FORBIDDEN_SESSION in lower:
        raise ProtocolError(
            PROTOCOL_HEADER_MISMATCH,
            "Mcp-Session-Id is not supported: this server is stateless and never issues "
            "or accepts protocol sessions.",
            {"header": "Mcp-Session-Id"},
        )

    version = (lower.get(HEADER_PROTOCOL_VERSION) or "").strip()
    if not version:
        raise ProtocolError(
            PROTOCOL_HEADER_MISMATCH,
            f"MCP-Protocol-Version header is required and must be {MCP_PROTOCOL_VERSION}.",
            {"expected": MCP_PROTOCOL_VERSION},
        )
    legacy = False
    if version != MCP_PROTOCOL_VERSION:
        if allow_legacy and version == LEGACY_MCP_PROTOCOL_VERSION:
            legacy = True
        else:
            raise ProtocolError(
                PROTOCOL_HEADER_MISMATCH,
                f"Unsupported MCP-Protocol-Version {version!r}; this server implements "
                f"{MCP_PROTOCOL_VERSION}.",
                {"expected": MCP_PROTOCOL_VERSION, "received": version},
            )

    if not isinstance(body, dict):
        raise ProtocolError(INVALID_REQUEST, "JSON-RPC body must be a single JSON object. "
                                             "Batching is not supported.")
    if body.get("jsonrpc") != "2.0":
        raise ProtocolError(INVALID_REQUEST, "jsonrpc must be exactly '2.0'.")
    method = body.get("method")
    if not isinstance(method, str) or not method:
        raise ProtocolError(INVALID_REQUEST, "method is required.")
    if method in ("initialize", "notifications/initialized"):
        raise ProtocolError(
            METHOD_NOT_FOUND,
            "The 2026-07-28 revision removes the initialize/initialized handshake; "
            "call server/discover instead.",
            {"method": method},
        )
    if method not in SUPPORTED_METHODS:
        raise ProtocolError(METHOD_NOT_FOUND, f"Unknown method {method!r}.",
                            {"supported": list(SUPPORTED_METHODS)})

    header_method = (lower.get(HEADER_METHOD) or "").strip()
    if not header_method:
        raise ProtocolError(PROTOCOL_HEADER_MISMATCH, "Mcp-Method header is required.")
    if header_method != method:
        raise ProtocolError(
            PROTOCOL_HEADER_MISMATCH,
            "Mcp-Method header does not match the JSON-RPC body method.",
            {"header": header_method, "body": method},
        )

    params = _require_object(body.get("params"), "params")
    header_name = lower.get(HEADER_NAME)
    name_key = NAMED_METHODS.get(method)
    if name_key:
        body_name = params.get(name_key)
        if not isinstance(body_name, str) or not body_name:
            raise ProtocolError(INVALID_PARAMS, f"params.{name_key} is required for {method}.")
        if header_name is None or header_name.strip() == "":
            raise ProtocolError(PROTOCOL_HEADER_MISMATCH,
                                f"Mcp-Name header is required for {method}.")
        if header_name.strip() != body_name:
            raise ProtocolError(
                PROTOCOL_HEADER_MISMATCH,
                "Mcp-Name header does not match the JSON-RPC body target.",
                {"header": header_name.strip(), "body": body_name},
            )
    elif header_name is not None and header_name.strip() != "":
        raise ProtocolError(
            PROTOCOL_HEADER_MISMATCH,
            f"Mcp-Name header must be omitted for {method}.",
            {"header": header_name.strip()},
        )

    meta = _require_object(params.get("_meta"), "params._meta")
    if not legacy:
        client_info = _require_object(meta.get("clientInfo"), "params._meta.clientInfo")
        if not client_info.get("name"):
            raise ProtocolError(
                INVALID_PARAMS,
                "params._meta.clientInfo.name is required: every 2026-07-28 request carries "
                "client metadata in _meta.",
            )

    if "id" not in body:
        raise ProtocolError(INVALID_REQUEST,
                            "Notifications are not supported; every request needs an id.")

    return MCPRequest(jsonrpc="2.0", id=body.get("id"), method=method, params=params,
                      protocol_version=version, client_meta=meta, legacy=legacy)


def success(request_id: Any, method: str, result: dict[str, Any],
            extra_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    hints = CACHE_HINTS.get(method, {"ttlMs": 0, "cacheScope": "none"})
    payload = dict(result)
    payload.setdefault("serverInfo", server_info())
    meta = {**hints, **(extra_meta or {})}
    payload["_meta"] = {**payload.get("_meta", {}), **meta}
    # ttlMs / cacheScope are also surfaced at the top level of the result where
    # the revision requires them for discovery-style responses.
    if method in ("server/discover", "tools/list", "resources/list"):
        payload["ttlMs"] = hints["ttlMs"]
        payload["cacheScope"] = hints["cacheScope"]
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def failure(request_id: Any, code: int, message: str,
            data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    payload = dict(data or {})
    payload.setdefault("serverInfo", server_info())
    error["data"] = payload
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
