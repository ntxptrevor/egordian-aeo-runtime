#!/usr/bin/env python3
"""Build/verification manifest generator.

Runs the test suite, byte-compiles the application, boots the ASGI app in
process, exercises the public and authenticated surfaces, and writes
``run_manifest.json`` with version hashes and verification results.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr)[-4000:]


def main() -> int:
    started = time.time()
    os.environ.setdefault("AUTH_MODE", "dev")
    os.environ.setdefault("DEPLOYMENT_ENV", "test")
    os.environ.setdefault("OVERLAY_DB_PATH", "/tmp/manifest_overlay.db")
    os.environ.setdefault("EGORDIAN_AUTH_PROVIDER", "none")

    tests_rc, tests_out = run([sys.executable, "-m", "pytest", "-p", "no:warnings"])
    import re
    match = re.findall(r"^(\d+ passed.*|\d+ failed.*)$", tests_out, re.M)
    counts = re.search(r"(\d+) passed", tests_out)
    summary = {"line": match[-1].strip() if match else tests_out.strip()[-200:],
               "passed": int(counts.group(1)) if counts else None}
    compile_rc, _ = run([sys.executable, "-m", "compileall", "-q", "app", "gordian_ctc"])

    from app.aeo.runner import version_hashes
    from app.catalogue_gateway import get_gateway
    from app.config import MCP_PROTOCOL_VERSION, SERVICE_VERSION
    from app.egordian.registry import get_registry
    from app.mcp import tools as tool_mod
    from app.mcp.resources import list_resources

    smoke: dict[str, object] = {}
    try:
        from fastapi.testclient import TestClient
        from app.main import create_app
        with TestClient(create_app()) as client:
            smoke["healthz"] = client.get("/healthz").status_code
            smoke["openapi"] = client.get("/openapi.json").status_code
            smoke["console"] = client.get("/").status_code
            smoke["docs"] = client.get("/docs-api").status_code
            smoke["mcp_get_blocked"] = client.get("/mcp").status_code
            discover = client.post(
                "/mcp",
                headers={"Authorization": "Bearer dev-local-token",
                         "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                         "Mcp-Method": "server/discover"},
                json={"jsonrpc": "2.0", "id": 1, "method": "server/discover",
                      "params": {"_meta": {"clientInfo": {"name": "manifest"}}}})
            smoke["server_discover"] = discover.status_code
            smoke["data_dir_not_served"] = client.get("/data/catalogue.sqlite").status_code
    except Exception as exc:  # pragma: no cover
        smoke["error"] = f"{type(exc).__name__}: {exc}"

    registry = get_registry()
    gateway = get_gateway()
    catalogue_path = Path(gateway.path)

    dist = ROOT / "dist" / "public"
    static_bundle = {
        "path": str(dist),
        "present": dist.is_dir(),
        "entry_point": "index.html",
        "files": sorted(str(p.relative_to(dist)) for p in dist.rglob("*") if p.is_file())
                 if dist.is_dir() else [],
        "api_routing": "__PORT_8080__ deployment placeholder (no same-origin /api calls)",
        "read_only": True,
        "browser_storage_used": False,
        "build_command": "python scripts/build_static_console.py",
    }

    registry_variant = {
        "dockerfile": "Dockerfile.registry",
        "dockerignore": "Dockerfile.registry.dockerignore",
        "entrypoint": "scripts/registry-entrypoint.sh",
        "seal_helper": "scripts/seal_catalogue.sh",
        "crypto_module": "scripts/catalogue_crypto.py",
        "compose": "docker-compose.hostinger.yml",
        "compose_public_build": "docker-compose.hostinger-build.yml",
        "compose_stock_image_bootstrap": "docker-compose.hostinger-bootstrap.yml",
        "compose_hostinger_single": "docker-compose.hostinger-single.yml",
        "single_service": {
            "services": 1,
            "image": "python:3.12-slim",
            "requires_build": False,
            "requires_depends_on": False,
            "launcher": "scripts/launch_runtime.py",
            "launcher_pinned_by": ["LAUNCHER_URL commit path", "LAUNCHER_SHA256"],
            "privilege_drop": "setgroups([]) -> setgid(10001) -> setuid(10001) before execve",
            "plaintext_catalogue_location": "/run/egordian tmpfs only",
            "persistent_state": "/runtime/state/data.db",
            "published_as": "docker-compose.single.yml",
        },
        "bootstrap": {
            "program": "scripts/bootstrap_runtime.py",
            "generator": "scripts/render_bootstrap_compose.py",
            "images": ["python:3.12-slim"],
            "requires_build": False,
            "requires_registry": False,
            "pinned_ref_placeholder": "8659f42",
            "secrets_in_bootstrap": False,
            "runtime_volume": "egordian_runtime (read-only at runtime)",
        },
        "public_build_context": "https://github.com/ntxptrevor/egordian-aeo-runtime.git#main",
        "public_build_repo_exists": False,
        "split_parts": {
            "reason": "sealed container exceeds GitHub's 100 MiB single-file limit",
            "part_size_bytes": 62914560,
            "manifest": "build/catalogue.enc.parts.json",
            "assembly": "multi-stage builder verifies + concatenates, staging discarded",
            "key_required": False,
        },
        "traefik_cert_resolver": "mytlschallenge",
        "catalogue_runtime_mount": "tmpfs uid=10001,gid=10001,mode=0700,size=256m",
        "overlay_mount": "named volume egordian_overlay (seeded, no nocopy)",
        "docs": "docs/REGISTRY_DEPLOY.md",
        "container_format": "EGCAT1",
        "algorithm": "aes-256-gcm-chunked (4 MiB chunks, per-chunk AAD position binding)",
        "kdf": "pbkdf2-hmac-sha256 (600000 iterations) or raw hex: key",
        "plaintext_catalogue_in_image": False,
        "required_runtime_env": ["CATALOGUE_DECRYPTION_KEY", "CATALOGUE_SHA256"],
        "runtime_catalogue_path": "/run/egordian/catalogue.sqlite (mode 0444)",
        "fail_closed_exit_codes": {"missing_key_or_pin": 78,
                                    "decrypt_or_verify_failed": 79},
        "sealed_blob_present": (ROOT / "build" / "catalogue.enc").is_file(),
    }

    manifest = {
        "manifest_schema": "egordian-aeo-mcp-run-manifest-1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": {"name": "egordian-aeo-mcp", "version": SERVICE_VERSION,
                    "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                    "stateless": True, "entrypoint": "app.main:app",
                    "default_port": 8080},
        "versions": version_hashes(gateway),
        "operation_registry": registry.validate(),
        "operation_counts": registry.counts(),
        "capability_gaps": registry.capability_gaps(),
        "mcp_tools": {"count": tool_mod.tool_count(),
                      "categories": tool_mod.categories(),
                      "names": sorted(tool_mod.TOOLS)},
        "mcp_resources": [r["uri"] for r in list_resources()],
        "catalogue": {
            "path": str(catalogue_path),
            "present": catalogue_path.is_file(),
            "size_bytes": catalogue_path.stat().st_size if catalogue_path.is_file() else 0,
            "sha256": sha256_file(catalogue_path) if catalogue_path.is_file() else None,
            "mode": oct(catalogue_path.stat().st_mode & 0o777) if catalogue_path.is_file() else None,
            "served_publicly": False,
        },
        "static_bundle": static_bundle,
        "registry_variant": registry_variant,
        "verification": {
            "tests": {"command": "python -m pytest", "exit_code": tests_rc,
                      "summary": summary},
            "byte_compile": {"command": "python -m compileall app gordian_ctc",
                             "exit_code": compile_rc},
            "rest_smoke": smoke,
            "container_build": {
                "dockerfile": "Dockerfile",
                "executed": False,
                "reason": "No container runtime is available in the build sandbox; "
                          "the image is built by the deployment target.",
            },
        },
        "policy": {
            "live_egordian_writes_executed": False,
            "live_egordian_deletes_executed": False,
            "live_egordian_calls_executed": False,
            "credentials_available_for_jocservice": False,
            "catalogue_bulk_export_possible": False,
        },
        "elapsed_s": round(time.time() - started, 2),
    }
    out = ROOT / "run_manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(out), "tests_exit_code": tests_rc,
                      "tests": summary, "tools": manifest["mcp_tools"]["count"],
                      "operations": manifest["operation_counts"]["total"]}, indent=2))
    return 0 if tests_rc == 0 and compile_rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
