"""Licensing firewall in front of the immutable Gordian CTC catalogue.

Hard rules enforced here (and covered by leak tests):
  * The catalogue file is opened ``mode=ro&immutable=1`` only.
  * No endpoint can download, dump, export, or paginate the whole catalogue.
  * Result counts are capped; ``browse`` and ``search`` are bounded.
  * Cost fields are redacted unless the caller holds ``catalogue:read`` AND
    explicitly requests authorized cost disclosure.
  * Every returned row carries provenance and catalogue edition.
  * ``data/`` is never served statically (see app.main - no StaticFiles mount
    for the data directory).
"""
from __future__ import annotations

import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any

from gordian_ctc import query as ctc_query
from gordian_ctc.catalogue import catalogue_info, connect_readonly

from .config import get_settings

COST_FIELDS = (
    "direct_unit_cost", "demolition_unit_cost", "price_fields", "price_fields_json",
    "unit_price", "cost", "price", "total_cost",
)
BULK_TERMS = {"*", "%", "all", "everything", "dump", "export"}
MIN_QUERY_LENGTH = 2


class LicenseViolation(PermissionError):
    """A request would have exceeded the licensed disclosure boundary."""


class CatalogueUnavailable(RuntimeError):
    pass


def _cap(limit: Any, maximum: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        value = 20
    return max(1, min(value, maximum))


def redact_costs(item: dict[str, Any], authorized: bool) -> dict[str, Any]:
    if authorized:
        return item
    out = {k: v for k, v in item.items() if k not in COST_FIELDS}
    out["cost_fields"] = "redacted_unauthorized_scope"
    return out


class CatalogueGateway:
    def __init__(self, path: str | None = None):
        settings = get_settings()
        self.path = path or settings.catalogue_db_path
        self.max_results = settings.catalogue_max_results

    # --- availability -----------------------------------------------------
    @property
    def available(self) -> bool:
        return Path(self.path).is_file()

    def info(self) -> dict[str, Any]:
        if not self.available:
            raise CatalogueUnavailable(f"Catalogue database not present at {self.path}")
        data = catalogue_info(self.path)
        manifest = dict(data.get("manifest", {}))
        # Provenance yes; licensed source internals stay minimal.
        return {
            "edition": manifest.get("edition"),
            "owner": manifest.get("owner"),
            "parser_version": manifest.get("parser_version"),
            "source_sha256": manifest.get("source_sha256"),
            "row_content_sha256": manifest.get("row_content_sha256"),
            "sealed": bool(manifest.get("sealed")),
            "counts": data.get("counts", {}),
            "licensing": {
                "classification": "private-licensed",
                "bulk_export": "prohibited",
                "download": "prohibited",
                "max_results_per_call": self.max_results,
            },
        }

    def status(self) -> dict[str, Any]:
        try:
            info = self.info()
            return {"available": True, "edition": info["edition"],
                    "counts": info["counts"], "read_only": True, "immutable": True}
        except Exception as exc:
            return {"available": False, "error": type(exc).__name__, "read_only": True}

    def assert_read_only(self) -> dict[str, Any]:
        """Prove the catalogue connection cannot be written through."""
        con = connect_readonly(self.path)
        try:
            try:
                con.execute("CREATE TABLE leak_probe(x INTEGER)")
            except sqlite3.OperationalError as exc:
                return {"read_only": True, "error": str(exc)[:120]}
            raise LicenseViolation("Catalogue connection is writable; refusing to operate.")
        finally:
            con.close()

    # --- guarded operations ----------------------------------------------
    def _guard_query(self, term: str) -> str:
        cleaned = (term or "").strip()
        if len(cleaned) < MIN_QUERY_LENGTH:
            raise LicenseViolation(
                "A catalogue search requires a specific term of at least "
                f"{MIN_QUERY_LENGTH} characters; bulk retrieval is prohibited.")
        if cleaned.lower() in BULK_TERMS:
            raise LicenseViolation("Bulk or wildcard catalogue retrieval is prohibited.")
        return cleaned

    def search(self, term: str, limit: int = 20, *, cost_authorized: bool = False,
               public_safe: bool = False) -> dict[str, Any]:
        cleaned = self._guard_query(term)
        capped = _cap(limit, self.max_results)
        result = ctc_query.search(self.path, cleaned, capped, public_safe=public_safe)
        items = [redact_costs(dict(x), cost_authorized) for x in result.get("results", [])]
        return {
            **{k: v for k, v in result.items() if k != "results"},
            "results": items[:capped],
            "result_count": len(items[:capped]),
            "result_cap": capped,
            "cost_disclosure": "authorized" if cost_authorized else "redacted",
            "licensing": "private-licensed; no bulk export",
        }

    def get(self, code: str, *, include_modifiers: bool = True,
            cost_authorized: bool = False, public_safe: bool = False) -> dict[str, Any]:
        if not (code or "").strip():
            raise LicenseViolation("A specific CTC line code is required.")
        result = ctc_query.get_line(self.path, code, include_modifiers, public_safe)
        out = redact_costs(dict(result), cost_authorized)
        if isinstance(out.get("modifiers"), list):
            out["modifiers"] = [redact_costs(dict(m), cost_authorized)
                                for m in out["modifiers"][:self.max_results]]
        out["cost_disclosure"] = "authorized" if cost_authorized else "redacted"
        return out

    def browse(self, prefix: str, *, cost_authorized: bool = False,
               public_safe: bool = False) -> dict[str, Any]:
        cleaned = (prefix or "").strip()
        if len(cleaned) < 2:
            raise LicenseViolation(
                "Browsing requires a hierarchy prefix of at least 2 characters; "
                "whole-catalogue browsing is prohibited.")
        result = ctc_query.browse(self.path, cleaned, public_safe)
        for key in ("children", "rows", "results", "tasks"):
            if isinstance(result.get(key), list):
                result[key] = [redact_costs(dict(x), cost_authorized)
                               for x in result[key][:self.max_results]]
        result["result_cap"] = self.max_results
        result["cost_disclosure"] = "authorized" if cost_authorized else "redacted"
        return result


@lru_cache(maxsize=1)
def get_gateway() -> CatalogueGateway:
    return CatalogueGateway()
