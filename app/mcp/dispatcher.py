"""Stateless MCP method dispatch.

Nothing here retains request state: the dispatcher builds a per-request
context, executes, and returns. Any replica can serve any request.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..aeo.machine import GateRequired, StateTransitionError
from ..catalogue_gateway import CatalogueGateway, LicenseViolation, get_gateway
from ..config import MCP_PROTOCOL_VERSION, Settings, get_settings
from ..egordian.client import EgordianClient
from ..egordian.registry import get_registry
from ..repo.base import HandleInvalid, Repository
from ..security import ApprovalRequired, Principal, ScopeError, redact
from . import resources as res
from . import tools as tool_mod
from .protocol import (CAPABILITY_BLOCKED, FORBIDDEN, INTERNAL_ERROR, INVALID_PARAMS,
                       METHOD_NOT_FOUND, MCPRequest, ProtocolError, server_info)

log = logging.getLogger("mcp.dispatch")


def capabilities() -> dict[str, Any]:
    return {
        "tools": {"listChanged": False, "count": tool_mod.tool_count(),
                  "categories": tool_mod.categories()},
        "resources": {"listChanged": False, "subscribe": False,
                      "count": len(res.list_resources())},
        "sessions": False,
        "streaming": False,
        "batching": False,
        "logging": False,
    }


def discover(gateway: CatalogueGateway, client: EgordianClient) -> dict[str, Any]:
    registry = get_registry()
    return {
        "serverInfo": server_info(),
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": capabilities(),
        "instructions": (
            "Stateless MCP 2026-07-28 server for the eGordian AEO operator. Call "
            "handle_create first to mint an opaque project handle, then pass handle + "
            "project_id on every subsequent tool call. Writes require a named actor, an "
            "approval object and an idempotency key. DELETE and undocumented write routes "
            "are permanently blocked."
        ),
        "methods": ["server/discover", "tools/list", "tools/call", "resources/list",
                    "resources/read"],
        "deployment": {
            "catalogue": gateway.status(),
            "egordian": {k: v for k, v in client.status().items()
                         if k not in ("capability_gaps",)},
            "operationRegistry": {"fixture_sha256": registry.fixture_sha256,
                                  "counts": registry.counts()},
        },
    }


class Dispatcher:
    def __init__(self, repo: Repository, gateway: CatalogueGateway | None = None,
                 client: EgordianClient | None = None, settings: Settings | None = None):
        self.repo = repo
        self.settings = settings or get_settings()
        self.gateway = gateway or get_gateway()
        self.client = client or EgordianClient(self.settings)

    def handle(self, request: MCPRequest, principal: Principal,
               correlation_id: str) -> dict[str, Any]:
        method = request.method
        if method == "server/discover":
            return discover(self.gateway, self.client)
        if method == "tools/list":
            return {"tools": tool_mod.list_tools()}
        if method == "resources/list":
            return {"resources": res.list_resources()}
        if method == "resources/read":
            uri = str(request.params.get("uri"))
            try:
                return res.read_resource(uri, self.gateway)
            except KeyError:
                raise ProtocolError(INVALID_PARAMS, f"Unknown resource uri {uri!r}.")
        if method == "tools/call":
            return self._call_tool(request, principal, correlation_id)
        raise ProtocolError(METHOD_NOT_FOUND, f"Unsupported method {method!r}.")

    # --- tools/call -------------------------------------------------------
    def _call_tool(self, request: MCPRequest, principal: Principal,
                   correlation_id: str) -> dict[str, Any]:
        name = str(request.params.get("name"))
        tool = tool_mod.get_tool(name)
        if tool is None:
            raise ProtocolError(INVALID_PARAMS, f"Unknown tool {name!r}.",
                                {"available": sorted(tool_mod.TOOLS)})
        arguments = request.params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ProtocolError(INVALID_PARAMS, "arguments must be an object.")
        try:
            principal.require(*tool.scopes)
        except ScopeError as exc:
            raise ProtocolError(FORBIDDEN, str(exc),
                                {"required_scopes": list(tool.scopes),
                                 "granted_scopes": sorted(principal.scopes)})
        if tool.requires_handle and not arguments.get("handle"):
            raise ProtocolError(INVALID_PARAMS,
                                "An opaque handle is required; call handle_create first.")

        ctx = tool_mod.ToolContext(principal=principal, repo=self.repo, gateway=self.gateway,
                                   client=self.client, settings=self.settings,
                                   correlation_id=correlation_id)
        try:
            payload = tool.handler(ctx, arguments)
            is_error = bool(isinstance(payload, dict) and payload.get("ok") is False)
        except (HandleInvalid,) as exc:
            raise ProtocolError(FORBIDDEN, str(exc), {"reason": "handle_invalid"})
        except (ScopeError,) as exc:
            raise ProtocolError(FORBIDDEN, str(exc), {"reason": "scope_denied"})
        except ApprovalRequired as exc:
            raise ProtocolError(FORBIDDEN, str(exc), {"reason": "approval_required"})
        except LicenseViolation as exc:
            raise ProtocolError(CAPABILITY_BLOCKED, str(exc),
                                {"reason": "licensing_boundary"})
        except GateRequired as exc:
            raise ProtocolError(CAPABILITY_BLOCKED, str(exc), {"reason": "human_gate_required"})
        except StateTransitionError as exc:
            raise ProtocolError(INVALID_PARAMS, str(exc), {"reason": "invalid_state_transition"})
        except PermissionError as exc:
            raise ProtocolError(FORBIDDEN, str(exc), {"reason": "forbidden"})
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError(INVALID_PARAMS, f"{type(exc).__name__}: {exc}",
                                {"tool": name})
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("tool failure cid=%s tool=%s", correlation_id, name)
            raise ProtocolError(INTERNAL_ERROR, f"Tool execution failed: {type(exc).__name__}",
                                {"tool": name, "correlation_id": correlation_id})

        safe = redact(payload)
        return {
            "content": [{"type": "text",
                         "text": json.dumps(safe, indent=2, sort_keys=True, default=str)}],
            "structuredContent": safe,
            "isError": is_error,
            "_meta": {"tool": name, "correlationId": correlation_id,
                      "sideEffecting": tool.side_effecting,
                      "destructive": tool.destructive},
        }
