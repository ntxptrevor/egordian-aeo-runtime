"""MCP adapter. Stateless tool calls are delegated to :class:`GordianService`."""
from __future__ import annotations

import json
import os
from typing import Any

from .service import GordianService

TOOL_NAMES = (
    "info", "search", "get", "browse", "translate", "reconcile", "lessons",
    "big_notes", "observed_external_line", "verify_external_line", "external_lines",
    "add_big_note", "change_order_log", "proposal_delta", "propose_improvement",
    "decide_improvement", "review_queue", "propose_learning", "approve_learning",
    "reject_learning", "manifest",
)


def tool_schemas() -> dict[str, dict]:
    common = {"type": "object", "required": ["handle", "project_id"],
              "properties": {"handle": {"type": "string", "minLength": 32},
                             "project_id": {"type": "string", "minLength": 1}}, "additionalProperties": True}
    schemas = {name: dict(common) for name in TOOL_NAMES}
    schemas["search"]["required"] = ["handle", "project_id", "query"]
    schemas["get"]["required"] = ["handle", "project_id", "code"]
    schemas["browse"]["required"] = ["handle", "project_id"]
    schemas["translate"]["required"] = ["handle", "project_id", "system", "code_or_alias"]
    schemas["reconcile"]["required"] = ["handle", "project_id", "request", "actor", "approval"]
    schemas["observed_external_line"]["required"] = [
        "handle", "project_id", "source_system", "edition", "code_or_opaque_id",
        "observed_date", "screen_page_provenance", "actor", "approval"]
    schemas["verify_external_line"]["required"] = [
        "handle", "project_id", "observation_id", "verification_status", "rationale", "actor", "approval"]
    schemas["add_big_note"]["required"] = ["handle", "project_id", "title", "body", "provenance", "actor", "approval"]
    schemas["change_order_log"]["required"] = ["handle", "project_id", "status", "payload", "actor", "approval"]
    schemas["proposal_delta"]["required"] = [
        "handle", "project_id", "initial_proposal", "accepted_final", "delta",
        "acceptance_status", "actor", "approval"]
    schemas["propose_improvement"]["required"] = ["handle", "project_id", "payload", "actor", "approval"]
    schemas["decide_improvement"]["required"] = [
        "handle", "project_id", "candidate_id", "status", "rationale", "actor", "approval"]
    for name in ("propose_learning", "approve_learning", "reject_learning"):
        schemas[name]["required"] = ["handle", "project_id", "actor", "subject_type", "subject_id", "approval"]
    return schemas


class MCPAdapter:
    """Importable adapter that works even when the optional MCP SDK is absent."""
    def __init__(self, service: GordianService):
        self.service = service

    def call(self, name: str, arguments: dict[str, Any], *, auth: str | None = None) -> dict:
        if name not in TOOL_NAMES:
            raise ValueError(f"Unknown MCP tool: {name}")
        method = "get_lessons" if name == "lessons" else name
        return getattr(self.service, method)(arguments, auth=auth)


def main() -> None:
    """Run stdio MCP if the optional SDK is installed; otherwise explain the dependency."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:
        raise SystemExit("Optional MCP SDK unavailable. Install with `pip install .[mcp]`.") from e
    catalogue = os.environ.get("GORDIAN_CTC_CATALOGUE")
    overlay = os.environ.get("GORDIAN_CTC_OVERLAY")
    if not catalogue or not overlay:
        raise SystemExit("Set GORDIAN_CTC_CATALOGUE and GORDIAN_CTC_OVERLAY.")
    adapter = MCPAdapter(GordianService(catalogue, overlay))
    mcp = FastMCP("private-gordian-ctc")
    # Each named tool remains stateless: hosts pass the opaque handle/project in
    # arguments_json on every invocation; there is no server-side conversation.
    def register(name: str) -> None:
        def invoke(arguments_json: str, user_id: str = "local") -> str:
            return json.dumps(adapter.call(name, json.loads(arguments_json), auth=user_id))
        invoke.__name__ = name
        mcp.tool(name=name)(invoke)
    for name in TOOL_NAMES:
        register(name)
    mcp.run()


if __name__ == "__main__":
    main()
