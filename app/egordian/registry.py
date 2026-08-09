"""Exact allowlisted eGordian operation registry.

Every entry is derived deterministically from the fetched documentation
fixture ``fixtures/egordian_help_2026-08-07.md`` (source:
https://jocservice.egordian.com/Help). Routes are NEVER invented, edited, or
extrapolated: if the Help page does not document a route, this service has no
capability for it and reports a clean capability gap instead.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..config import PROJECT_ROOT

HELP_URL = "https://jocservice.egordian.com/Help"
FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "egordian_help_2026-08-07.md"
FIXTURE_FETCHED_AT = "2026-08-07T00:00:00Z"

# Sections the Help page documents, in page order. Used as an integrity check:
# a fixture that does not contain exactly these sections fails validation.
EXPECTED_SECTIONS: tuple[str, ...] = (
    "UsersV1", "CompanyForm", "AccessToken", "HealthCheck", "ContactsV1", "PicturesV1",
    "OwnersV1", "Requestor", "TrackingDatesV1", "FilesV1", "ConstructionTaskCatalogV1",
    "ThirdPartyMembers", "JobOrdersV1", "JobOrders", "NotesV1", "PriceProposalsV1",
)

# Risk levels ------------------------------------------------------------
RISK_READ = "read"
RISK_WRITE = "write"
RISK_DESTRUCTIVE = "destructive"
RISK_ADMIN = "admin"
RISK_AUTH = "auth"

_SECTION_RE = re.compile(r"^##\s+(?P<name>[A-Za-z0-9_]+)\s*$", re.M)
_ROW_RE = re.compile(r"^\|(?P<api>(?:GET|PUT|POST|DELETE|PATCH)\s+[^|]+)\|(?P<desc>[^|]*)\|\s*$")
_PATH_PARAM_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")

# Operations that mutate remote state even though the verb is GET.
_ADMIN_GET_ROUTES = {"api/HealthCheck/RefreshCache"}
_AUTH_ROUTES = {"api/AccessToken"}


@dataclass(frozen=True)
class Operation:
    operation_id: str
    section: str
    method: str
    route_template: str
    path_params: tuple[str, ...]
    query_params: tuple[str, ...]
    body_required: bool
    risk: str
    description: str
    source_url: str = HELP_URL
    binary_response: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def enabled_by_default(self) -> bool:
        return self.risk in (RISK_READ, RISK_AUTH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "section": self.section,
            "method": self.method,
            "route_template": self.route_template,
            "path_params": list(self.path_params),
            "query_params": list(self.query_params),
            "body_required": self.body_required,
            "risk": self.risk,
            "description": self.description,
            "source_documentation_url": self.source_url,
            "binary_response": self.binary_response,
            "enabled_by_default": self.enabled_by_default,
            "tags": list(self.tags),
        }


def _slug(method: str, path: str) -> str:
    tokens = []
    for part in path.split("/"):
        if not part:
            continue
        if part.startswith("{"):
            tokens.append("by_" + _PATH_PARAM_RE.findall(part)[0])
        else:
            tokens.append(re.sub(r"[^A-Za-z0-9]", "", part))
    return f"{method.lower()}_" + "_".join(t for t in tokens if t)


def _risk_for(method: str, path: str) -> str:
    if path in _AUTH_ROUTES:
        return RISK_AUTH
    if path in _ADMIN_GET_ROUTES:
        return RISK_ADMIN
    if method == "GET":
        return RISK_READ
    if method == "DELETE":
        return RISK_DESTRUCTIVE
    return RISK_WRITE


def _logical_rows(block: str) -> list[str]:
    """Rejoin documentation rows whose description wraps onto extra lines.

    The published Help page contains descriptions with hard line breaks inside
    a single markdown table cell; a naive line split would silently drop those
    operations (FilesV1, NotesV1, several DELETE routes).
    """
    rows: list[str] = []
    buffer: str | None = None
    for raw in block.splitlines():
        line = raw.strip()
        if buffer is not None:
            buffer = f"{buffer} {line}".strip()
            if line.endswith("|"):
                rows.append(buffer)
                buffer = None
            continue
        if not line.startswith("|"):
            continue
        if line.endswith("|") and line.count("|") >= 3:
            rows.append(line)
        else:
            buffer = line
    if buffer is not None:
        rows.append(buffer)
    return rows


def _parse_fixture(text: str) -> list[Operation]:
    ops: list[Operation] = []
    seen: set[str] = set()
    sections = list(_SECTION_RE.finditer(text))
    for idx, match in enumerate(sections):
        name = match.group("name")
        start = match.end()
        end = sections[idx + 1].start() if idx + 1 < len(sections) else len(text)
        for line in _logical_rows(text[start:end]):
            row = _ROW_RE.match(line.strip())
            if not row:
                continue
            api = row.group("api").strip()
            description = row.group("desc").strip()
            method, _, raw_path = api.partition(" ")
            raw_path = raw_path.strip()
            path, _, query = raw_path.partition("?")
            path = path.strip().lstrip("/")
            query_params = tuple(
                p.split("=")[0] for p in query.split("&") if p.strip()
            ) if query else ()
            method = method.upper()
            operation_id = _slug(method, path)
            # Documented duplicates (same verb+route in two sections) collapse
            # to the first occurrence; the route set stays exact.
            if operation_id in seen:
                continue
            seen.add(operation_id)
            tags = []
            if "Download" in path:
                tags.append("binary")
            ops.append(
                Operation(
                    operation_id=operation_id,
                    section=name,
                    method=method,
                    route_template=path,
                    path_params=tuple(_PATH_PARAM_RE.findall(path)),
                    query_params=query_params,
                    body_required=method in ("PUT", "POST"),
                    risk=_risk_for(method, path),
                    description=description or "No documentation available.",
                    binary_response="Download" in path,
                    tags=tuple(tags),
                )
            )
    return ops


class OperationRegistry:
    def __init__(self, fixture_path: Path | str = FIXTURE_PATH):
        self.fixture_path = Path(fixture_path)
        self.fixture_text = self.fixture_path.read_text(encoding="utf-8")
        self.fixture_sha256 = hashlib.sha256(self.fixture_text.encode()).hexdigest()
        self._ops = _parse_fixture(self.fixture_text)
        self._by_id = {op.operation_id: op for op in self._ops}
        self._by_route = {(op.method, op.route_template): op for op in self._ops}

    # --- access -----------------------------------------------------------
    def all(self) -> list[Operation]:
        return list(self._ops)

    def get(self, operation_id: str) -> Operation | None:
        return self._by_id.get(operation_id)

    def match(self, method: str, route_template: str) -> Operation | None:
        return self._by_route.get((method.upper(), route_template.lstrip("/")))

    def sections(self) -> list[str]:
        out: list[str] = []
        for op in self._ops:
            if op.section not in out:
                out.append(op.section)
        return out

    def by_risk(self, risk: str) -> list[Operation]:
        return [op for op in self._ops if op.risk == risk]

    def counts(self) -> dict[str, int]:
        out = {"total": len(self._ops)}
        for risk in (RISK_READ, RISK_WRITE, RISK_DESTRUCTIVE, RISK_ADMIN, RISK_AUTH):
            out[risk] = len(self.by_risk(risk))
        return out

    def validate(self) -> dict[str, Any]:
        found = self.sections()
        missing = [s for s in EXPECTED_SECTIONS if s not in found]
        unexpected = [s for s in found if s not in EXPECTED_SECTIONS]
        return {
            "ok": not missing and not unexpected,
            "expected_sections": list(EXPECTED_SECTIONS),
            "found_sections": found,
            "missing_sections": missing,
            "unexpected_sections": unexpected,
            "fixture_sha256": self.fixture_sha256,
            "fixture_fetched_at": FIXTURE_FETCHED_AT,
            "source_documentation_url": HELP_URL,
            "operation_count": len(self._ops),
        }

    # --- capability reporting --------------------------------------------
    def capability_gaps(self) -> list[dict[str, Any]]:
        """Documented-vs-required gaps that block the AEO write path."""
        gaps: list[dict[str, Any]] = []
        pp = [op for op in self._ops if op.section == "PriceProposalsV1"]
        pp_writes = [op for op in pp if op.method in ("PUT", "POST", "PATCH")]
        if not pp_writes:
            gaps.append({
                "capability": "price_proposal_draft_or_submit",
                "status": "blocked_undocumented_route",
                "detail": (
                    "The Help page documents only "
                    "GET v1/Owners/{ownerId}/PriceProposals for PriceProposalsV1. "
                    "No draft or submit route is published, so AEO stage 8 "
                    "(submit & log) cannot execute a write and remains assisted."
                ),
                "documented_operations": [op.operation_id for op in pp],
                "source_documentation_url": HELP_URL,
                "aeo_stage_blocked": 8,
            })
        if not any(op.section == "JobOrders" and op.method == "POST" and
                   op.route_template == "v1/JobRequests" for op in self._ops):  # pragma: no cover
            gaps.append({"capability": "job_request_create", "status": "not_documented"})
        gaps.append({
            "capability": "healthcheck_refresh_cache",
            "status": "disabled_by_default",
            "detail": ("GET api/HealthCheck/RefreshCache clears remote cache state. It is "
                       "classified admin/mutating and is disabled unless "
                       "ALLOW_ADMIN_OPERATIONS=true plus the admin scope."),
            "source_documentation_url": HELP_URL,
        })
        gaps.append({
            "capability": "delete_operations",
            "status": "human_gate_required",
            "detail": (f"{len(self.by_risk(RISK_DESTRUCTIVE))} documented DELETE routes are "
                       "registered but permanently disabled by default; they return "
                       "human_gate_required and are never executed by tests."),
            "source_documentation_url": HELP_URL,
        })
        return gaps


@lru_cache(maxsize=1)
def get_registry() -> OperationRegistry:
    return OperationRegistry()
