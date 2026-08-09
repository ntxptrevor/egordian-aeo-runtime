"""FastAPI application: MCP endpoint, REST control surface, operator console.

Route map
---------
GET  /healthz         public liveness (no auth, no data)
GET  /readyz          authenticated readiness
POST /mcp             MCP 2026-07-28 JSON-RPC (the product)
GET  /mcp             405 - there is no event stream in this revision
GET  /api/*           authenticated operator/status API
GET  /openapi.json    OpenAPI document
GET  /                operator console (static, no secrets, no catalogue data)
GET  /docs-api        human-readable API + MCP client documentation

``data/`` is never mounted or served.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .aeo.machine import diagram
from .aeo.runner import version_hashes
from .catalogue_gateway import get_gateway
from .config import (MCP_PROTOCOL_VERSION, PROJECT_ROOT, SERVICE_NAME, SERVICE_VERSION,
                     get_settings)
from .egordian.client import EgordianClient
from .egordian.registry import get_registry
from .mcp import tools as tool_mod
from .mcp.dispatcher import Dispatcher, capabilities
from .mcp.protocol import (INTERNAL_ERROR, PARSE_ERROR, RATE_LIMITED, UNAUTHORIZED,
                           ProtocolError, failure, parse_request, success)
from .repo.factory import get_repository
from .security import (Authenticator, AuthError, Principal, RateLimited, RateLimiter,
                       correlation_id, redact)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("app")

CONSOLE_DIR = PROJECT_ROOT / "console"


def create_app() -> FastAPI:
    settings = get_settings()
    problems = settings.validate()
    if problems:
        raise RuntimeError("Invalid configuration: " + "; ".join(problems))

    app = FastAPI(
        title="eGordian AEO MCP Service",
        version=SERVICE_VERSION,
        description=(
            "Headless remote MCP 2026-07-28 service for the eGordian JOC platform: "
            "licensed CTC catalogue access behind a licensing firewall, an allowlisted "
            "eGordian operation registry, and the AEO nine-stage estimating operator."
        ),
        docs_url=None, redoc_url=None, openapi_url="/openapi.json",
    )

    authenticator = Authenticator(settings)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    app.state.settings = settings
    app.state.authenticator = authenticator
    app.state.limiter = limiter
    app.state.started_at = time.time()

    # --- middleware -------------------------------------------------------
    @app.middleware("http")
    async def guard(request: Request, call_next):
        cid = correlation_id()
        request.state.correlation_id = cid
        length = request.headers.get("content-length")
        if length and int(length) > settings.max_request_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "request_too_large",
                         "limit_bytes": settings.max_request_bytes,
                         "correlation_id": cid})
        response = await call_next(request)
        response.headers["X-Correlation-Id"] = cid
        response.headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # --- auth dependency --------------------------------------------------
    def principal_dep(authorization: str | None = Header(default=None)) -> Principal:
        try:
            principal = authenticator.authenticate(authorization)
        except AuthError as exc:
            raise _http(401, "unauthorized", str(exc))
        try:
            limiter.check(principal.token_id)
        except RateLimited as exc:
            raise _http(429, "rate_limited", str(exc))
        return principal

    def _dispatcher() -> Dispatcher:
        return Dispatcher(get_repository(), get_gateway(), EgordianClient(settings), settings)

    # --- health -----------------------------------------------------------
    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, Any]:
        """Public liveness probe. Contains no data and no secrets."""
        return {"status": "ok", "service": SERVICE_NAME, "version": SERVICE_VERSION,
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                "uptime_s": round(time.time() - app.state.started_at, 1)}

    @app.get("/readyz", tags=["health"])
    def readyz(principal: Principal = Depends(principal_dep)) -> dict[str, Any]:
        repo = get_repository()
        gateway = get_gateway()
        client = EgordianClient(settings)
        repo_health = repo.health()
        catalogue = gateway.status()
        ready = bool(repo_health.get("ok")) and bool(catalogue.get("available"))
        return {
            "ready": ready,
            "repository": repo_health,
            "catalogue": catalogue,
            "egordian": {k: client.status()[k] for k in ("state", "connected",
                                                         "writes_enabled", "write_mode")},
            "registry": get_registry().validate()["ok"],
        }

    # --- MCP --------------------------------------------------------------
    @app.post("/mcp", tags=["mcp"])
    async def mcp_endpoint(request: Request) -> JSONResponse:
        cid = request.state.correlation_id
        raw = await request.body()
        if len(raw) > settings.max_request_bytes:
            return JSONResponse(status_code=413,
                                content=failure(None, PARSE_ERROR, "Request body too large."))
        try:
            principal = authenticator.authenticate(request.headers.get("authorization"))
        except AuthError as exc:
            return JSONResponse(status_code=401,
                                content=failure(None, UNAUTHORIZED, str(exc)))
        try:
            limiter.check(principal.token_id)
        except RateLimited as exc:
            return JSONResponse(status_code=429,
                                content=failure(None, RATE_LIMITED, str(exc)))
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(status_code=400,
                                content=failure(None, PARSE_ERROR, "Body is not valid JSON."))
        try:
            parsed = parse_request(dict(request.headers), body,
                                   allow_legacy=settings.allow_legacy_2025_clients)
        except ProtocolError as exc:
            return JSONResponse(
                status_code=exc.http_status,
                content=failure(body.get("id") if isinstance(body, dict) else None,
                                exc.code, exc.message, exc.data))
        try:
            result = _dispatcher().handle(parsed, principal, cid)
        except ProtocolError as exc:
            return JSONResponse(status_code=200,
                                content=failure(parsed.id, exc.code, exc.message,
                                                {**exc.data, "correlationId": cid}))
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("dispatch failure cid=%s", cid)
            return JSONResponse(
                status_code=200,
                content=failure(parsed.id, INTERNAL_ERROR,
                                f"Internal error: {type(exc).__name__}", {"correlationId": cid}))
        extra = {"correlationId": cid, "protocolVersion": parsed.protocol_version}
        if parsed.legacy:
            extra["legacyClient"] = True
        return JSONResponse(status_code=200,
                            content=success(parsed.id, parsed.method, result, extra))

    @app.get("/mcp", tags=["mcp"])
    def mcp_no_stream() -> JSONResponse:
        return JSONResponse(
            status_code=405,
            content={"error": "method_not_allowed",
                     "message": ("MCP 2026-07-28 has no GET event stream and no sessions. "
                                 "Use POST /mcp."),
                     "allow": "POST"},
            headers={"Allow": "POST"},
        )

    # --- operator API -----------------------------------------------------
    @app.get("/api/status", tags=["operator"])
    def api_status(principal: Principal = Depends(principal_dep)) -> dict[str, Any]:
        client = EgordianClient(settings)
        gateway = get_gateway()
        repo = get_repository()
        registry = get_registry()
        return redact({
            "service": {"name": SERVICE_NAME, "version": SERVICE_VERSION,
                        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                        "deployment_env": settings.deployment_env,
                        "auth_mode": settings.auth_mode,
                        "stateless": True,
                        "uptime_s": round(time.time() - app.state.started_at, 1)},
            "principal": principal.public(),
            "repository": {"backend": repo.backend, **repo.health(), "counts": repo.counts()},
            "catalogue": gateway.status(),
            "egordian": client.status(),
            "registry": registry.validate(),
            "mcp": {"capabilities": capabilities(), "tools": tool_mod.tool_count(),
                    "tool_categories": tool_mod.categories()},
            "aeo": {"stages": diagram()},
            "versions": version_hashes(gateway),
        })

    @app.get("/api/operations", tags=["operator"])
    def api_operations(principal: Principal = Depends(principal_dep),
                       section: str | None = None, risk: str | None = None) -> dict[str, Any]:
        registry = get_registry()
        ops = [op.to_dict() for op in registry.all()
               if (not section or op.section == section) and (not risk or op.risk == risk)]
        return {"counts": registry.counts(), "sections": registry.sections(),
                "capability_gaps": registry.capability_gaps(), "operations": ops}

    @app.get("/api/tools", tags=["operator"])
    def api_tools(principal: Principal = Depends(principal_dep)) -> dict[str, Any]:
        return {"count": tool_mod.tool_count(), "categories": tool_mod.categories(),
                "tools": tool_mod.list_tools()}

    @app.get("/api/audit", tags=["operator"])
    def api_audit(principal: Principal = Depends(principal_dep),
                  project_id: str | None = None, limit: int = 50) -> dict[str, Any]:
        if project_id:
            principal.require_project(project_id)
        repo = get_repository()
        return {"results": redact(repo.list_audit(project_id, min(int(limit), 200)))}

    @app.get("/api/exceptions", tags=["operator"])
    def api_exceptions(project_id: str, status: str = "open", limit: int = 50,
                       principal: Principal = Depends(principal_dep)) -> dict[str, Any]:
        principal.require_project(project_id)
        repo = get_repository()
        return {"results": redact(repo.list_exceptions(project_id, None, status,
                                                       min(int(limit), 200)))}

    # --- docs & console ---------------------------------------------------
    @app.get("/docs-api", include_in_schema=False)
    def docs_page() -> FileResponse:
        return FileResponse(CONSOLE_DIR / "docs.html")

    @app.get("/", include_in_schema=False)
    def console_index() -> FileResponse:
        return FileResponse(CONSOLE_DIR / "index.html")

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> PlainTextResponse:
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    if (CONSOLE_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=str(CONSOLE_DIR / "assets")), name="assets")

    return app


def _http(status: int, code: str, message: str):
    from fastapi import HTTPException
    return HTTPException(status_code=status, detail={"error": code, "message": message})


app = create_app()
