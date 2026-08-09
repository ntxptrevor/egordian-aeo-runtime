"""Command line interface. Default operation is local/private and stdlib-only."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

from .catalogue import build_catalogue, catalogue_info, verify_catalogue
from .evaluate import run_eval
from .leakscan import scan_archive, scan_export, scan_obj
from .overlay import (create_handle, create_project, init_overlay, overlay_manifest,
                      record_observed_external_line, verify_observed_external_line,
                      observed_external_lines, record_big_note, search_prior_knowledge,
                      record_change_order, record_proposal_final_delta,
                      propose_improvement, decide_improvement)
from .profiles import resolve, store_resolution
from .query import browse, get_line, search
from .reconcile import persist_reconciliation, reconcile
from .service import GordianService, create_app


def _out(value: dict, exit_code: int = 0) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))
    if exit_code:
        raise SystemExit(exit_code)


def _json_input(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Input JSON must be an object.")
    return value


def _package(root: Path, out: Path) -> dict:
    excluded = {".pdf", ".sqlite", ".db", ".zip"}
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() not in excluded
             and "var" not in p.parts and "dist" not in p.parts and "__pycache__" not in p.parts]
    if len(files) > 100:
        raise ValueError(f"Package would contain {len(files)} files (>100).")
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for file in sorted(files):
            z.write(file, file.relative_to(root.parent))
    if out.stat().st_size > 70 * 1024 * 1024:
        out.unlink()
        raise ValueError("Package would exceed 70MB.")
    issues = scan_archive(str(out))
    if issues:
        out.unlink(missing_ok=True)
        raise ValueError("Public-safe archive leak scan failed: " + "; ".join(issues))
    return {"path": str(out), "bytes": out.stat().st_size, "files": len(files), "leak_scan": "passed"}


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="gordian-ctc")
    sub = p.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("init"); x.add_argument("--overlay", required=True)
    x = sub.add_parser("project-create"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--owner-contract", required=True); x.add_argument("--actor", required=True)
    x = sub.add_parser("handle-create"); x.add_argument("--overlay", required=True); x.add_argument("--user", required=True); x.add_argument("--project", action="append", required=True); x.add_argument("--ttl-hours", type=int, default=8)
    x = sub.add_parser("build"); x.add_argument("--pdf", required=True); x.add_argument("--catalogue", required=True); x.add_argument("--edition", required=True); x.add_argument("--owner"); x.add_argument("--report", required=True)
    x = sub.add_parser("verify"); x.add_argument("--catalogue", required=True)
    x = sub.add_parser("info"); x.add_argument("--catalogue", required=True)
    x = sub.add_parser("search"); x.add_argument("query"); x.add_argument("--catalogue", required=True); x.add_argument("--limit", type=int, default=20); x.add_argument("--public-safe", action="store_true")
    x = sub.add_parser("get"); x.add_argument("code"); x.add_argument("--catalogue", required=True); x.add_argument("--public-safe", action="store_true")
    x = sub.add_parser("browse"); x.add_argument("prefix", nargs="?", default=""); x.add_argument("--catalogue", required=True); x.add_argument("--public-safe", action="store_true")
    x = sub.add_parser("reconcile"); x.add_argument("--input", required=True); x.add_argument("--overlay", required=True); x.add_argument("--profile"); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("profiles-resolve"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--profile", action="append", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("manifest"); x.add_argument("--catalogue", required=True); x.add_argument("--overlay", required=True)
    x = sub.add_parser("eval"); x.add_argument("--catalogue", required=True); x.add_argument("--eval", required=True)
    x = sub.add_parser("external-line-observe"); x.add_argument("--overlay", required=True); x.add_argument("--input", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("external-line-verify"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--observation-id", required=True); x.add_argument("--status", required=True); x.add_argument("--rationale", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("external-lines"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--limit", type=int, default=50)
    x = sub.add_parser("big-note-add"); x.add_argument("--overlay", required=True); x.add_argument("--input", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("big-notes"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--query", default=""); x.add_argument("--limit", type=int, default=20)
    x = sub.add_parser("change-order-log"); x.add_argument("--overlay", required=True); x.add_argument("--input", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("proposal-delta"); x.add_argument("--overlay", required=True); x.add_argument("--input", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("improvement-propose"); x.add_argument("--overlay", required=True); x.add_argument("--input", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("improvement-decide"); x.add_argument("--overlay", required=True); x.add_argument("--project", required=True); x.add_argument("--candidate-id", required=True); x.add_argument("--status", required=True); x.add_argument("--rationale", required=True); x.add_argument("--actor", required=True); x.add_argument("--approval", action="store_true")
    x = sub.add_parser("leak-scan"); x.add_argument("path")
    x = sub.add_parser("export-public"); x.add_argument("--catalogue", required=True); x.add_argument("--code", action="append", required=True); x.add_argument("--out", required=True)
    x = sub.add_parser("package"); x.add_argument("--out", required=True)
    x = sub.add_parser("api"); x.add_argument("--catalogue", required=True); x.add_argument("--overlay", required=True); x.add_argument("--host", default="127.0.0.1"); x.add_argument("--port", type=int, default=8787)
    a = p.parse_args(argv)
    if a.cmd == "init": _out(init_overlay(a.overlay))
    elif a.cmd == "project-create": _out(create_project(a.overlay, a.project, a.owner_contract, a.actor))
    elif a.cmd == "handle-create": _out(create_handle(a.overlay, a.user, a.project, a.ttl_hours))
    elif a.cmd == "build": _out(build_catalogue(a.pdf, a.catalogue, a.edition, a.owner, a.report))
    elif a.cmd == "verify": _out(verify_catalogue(a.catalogue), 0 if verify_catalogue(a.catalogue)["ok"] else 2)
    elif a.cmd == "info": _out(catalogue_info(a.catalogue))
    elif a.cmd == "search": _out(search(a.catalogue, a.query, a.limit, public_safe=a.public_safe))
    elif a.cmd == "get": _out(get_line(a.catalogue, a.code, public_safe=a.public_safe))
    elif a.cmd == "browse": _out(browse(a.catalogue, a.prefix, public_safe=a.public_safe))
    elif a.cmd == "reconcile":
        request = json.loads(Path(a.input).read_text())
        profile = json.loads(Path(a.profile).read_text()) if a.profile else {}
        result = reconcile(request, profile); result["run"] = persist_reconciliation(a.overlay, request, result, a.actor, a.approval)
        _out(result)
    elif a.cmd == "profiles-resolve":
        result = resolve(a.profile); result["stored"] = store_resolution(a.overlay, a.project, result, a.actor, a.approval); _out(result)
    elif a.cmd == "manifest": _out({"catalogue": catalogue_info(a.catalogue), "overlay": overlay_manifest(a.overlay)})
    elif a.cmd == "eval": _out(run_eval(a.catalogue, a.eval))
    elif a.cmd == "external-line-observe":
        v = _json_input(a.input)
        _out(record_observed_external_line(a.overlay, v["project_id"], v["source_system"], v["edition"],
                                            v["code_or_opaque_id"], v["observed_date"],
                                            v["screen_page_provenance"], a.actor, a.approval))
    elif a.cmd == "external-line-verify":
        _out(verify_observed_external_line(a.overlay, a.project, a.observation_id, a.status,
                                            a.rationale, a.actor, a.approval))
    elif a.cmd == "external-lines":
        _out({"project_id": a.project, "results": observed_external_lines(a.overlay, a.project, a.limit)})
    elif a.cmd == "big-note-add":
        v = _json_input(a.input)
        _out(record_big_note(a.overlay, v["project_id"], v["title"], v["body"], v["provenance"], a.actor, a.approval))
    elif a.cmd == "big-notes":
        _out({"project_id": a.project, **search_prior_knowledge(a.overlay, a.project, a.query, a.limit)})
    elif a.cmd == "change-order-log":
        v = _json_input(a.input)
        _out(record_change_order(a.overlay, v["project_id"], v["status"], v.get("payload", {}), a.actor, a.approval))
    elif a.cmd == "proposal-delta":
        v = _json_input(a.input)
        _out(record_proposal_final_delta(a.overlay, v["project_id"], v["initial_proposal"],
                                         v["accepted_final"], v["delta"], v["acceptance_status"], a.actor, a.approval))
    elif a.cmd == "improvement-propose":
        v = _json_input(a.input)
        _out(propose_improvement(a.overlay, v["project_id"], v.get("payload", {}), a.actor, a.approval,
                                 v.get("proposal_delta_id")))
    elif a.cmd == "improvement-decide":
        _out(decide_improvement(a.overlay, a.project, a.candidate_id, a.status, a.rationale, a.actor, a.approval))
    elif a.cmd == "leak-scan":
        path = Path(a.path); _out({"path": str(path), "issues": scan_archive(str(path)) if path.suffix == ".zip" else scan_export(str(path))})
    elif a.cmd == "export-public":
        rows = [get_line(a.catalogue, code, public_safe=True) for code in a.code]
        payload = {"export_mode": "opaque_minimized", "results": rows}
        issues = scan_obj(payload)
        if issues:
            raise SystemExit("Refusing unsafe export: " + "; ".join(issues))
        Path(a.out).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        _out({"path": a.out, "count": len(rows), "leak_scan": "passed"})
    elif a.cmd == "package": _out(_package(Path(__file__).resolve().parents[1], Path(a.out).resolve()))
    elif a.cmd == "api":
        if a.host != "127.0.0.1":
            raise SystemExit("Refusing non-loopback bind. Use a reviewed reverse proxy/auth configuration.")
        try:
            import uvicorn
        except ImportError as e:
            raise SystemExit("FastAPI/uvicorn optional dependency unavailable; install .[api]") from e
        uvicorn.run(create_app(GordianService(a.catalogue, a.overlay)), host=a.host, port=a.port)


if __name__ == "__main__":
    main()
