"""Versioned profile resolution with explicit conflict reports."""
from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from .overlay import ApprovalRequired, _audit, connect
from .util import canonical_json, now, stable_id


def load_profile(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("profile_id", "version", "scope", "precedence"):
        if key not in data:
            raise ValueError(f"Profile missing {key}: {path}")
    return data


def _flatten(prefix: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {prefix: value}
    out: dict[str, Any] = {}
    for k, v in value.items():
        out.update(_flatten(f"{prefix}.{k}" if prefix else k, v))
    return out


def resolve(profile_paths: list[str]) -> dict:
    profiles = sorted((load_profile(p) for p in profile_paths), key=lambda x: (x["precedence"], x["profile_id"]))
    values: dict[str, Any] = {}
    sources: dict[str, dict] = {}
    conflicts: list[dict] = []
    for p in profiles:
        rules = p.get("rules", p.get("invariants", {}))
        for key, value in _flatten("", rules).items():
            if key in values and values[key] != value:
                conflicts.append({"key": key, "lower": {"value": values[key], "profile": sources[key]},
                                  "higher": {"value": value, "profile": p["profile_id"]}})
            values[key] = value
            sources[key] = p["profile_id"]
    return {"profile_ids": [p["profile_id"] for p in profiles], "values": values,
            "sources": sources, "conflicts": conflicts}


def store_resolution(overlay_path: str, project_id: str, resolved: dict, actor: str, approval: bool) -> dict:
    if resolved["conflicts"] and not approval:
        raise ApprovalRequired("Profile conflict report requires named-human approval=true before use.")
    snapshot_id = stable_id("profile", [project_id, resolved, actor, now(), secrets.token_hex(4)])
    con = connect(overlay_path)
    try:
        con.execute("INSERT INTO profile_snapshot VALUES(?,?,?,?,?,?,?,?)",
                    (snapshot_id, project_id, canonical_json(resolved["profile_ids"]), canonical_json(resolved["values"]),
                     canonical_json(resolved["conflicts"]), actor if approval else None, int(approval), now()))
        _audit(con, actor, "store_profile_resolution", project_id, {"snapshot_id": snapshot_id, "conflicts": len(resolved["conflicts"]), "approval": approval})
        con.commit()
        return {"snapshot_id": snapshot_id, "conflicts": resolved["conflicts"], "approved": approval}
    finally:
        con.close()
