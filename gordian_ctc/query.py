"""Offline-first CTC retrieval with evidence and bounded optional adapters."""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Protocol

from .catalogue import connect_readonly
from .util import norm_code, pretty_code, stable_id


class SemanticAdapter(Protocol):
    """Optional adapter. It must return candidate IDs/ranks, never unbounded text."""
    def rank(self, query: str, candidates: list[dict]) -> list[str]: ...


class RerankerAdapter(Protocol):
    def rank(self, query: str, candidates: list[dict]) -> list[str]: ...


class ReasoningAdapter(Protocol):
    def select(self, query: str, candidates: list[dict]) -> dict: ...


_TOKEN = re.compile(r"[A-Za-z0-9]+")


def _manifest(con: sqlite3.Connection) -> dict:
    return dict(con.execute("SELECT * FROM build_manifest WHERE manifest_id=1").fetchone())


def _row_out(row: sqlite3.Row, manifest: dict) -> dict:
    data = dict(row)
    data["line_code"] = data.get("line_code") or (pretty_code(data.get("parent_code")) if data.get("parent_code") else None)
    data["price_fields"] = json.loads(data.pop("price_fields_json"))
    data["parse_flags"] = json.loads(data.pop("parse_flags_json"))
    data["extraction"] = json.loads(data.pop("extraction_json"))
    data["edition"] = manifest["edition"]
    data["evidence"] = {
        "source_pdf_filename": manifest["source_filename"],
        "source_sha256": manifest["source_sha256"],
        "page": data["page_no"], "page_row": data["page_row"],
        "raw_line_hash": data["raw_line_hash"], "parser_version": manifest["parser_version"],
    }
    return data


def _public_item(item: dict) -> dict:
    """Opaque/minimized mode: do not disclose licensed code, description, or prices."""
    evidence = item.get("evidence", {})
    return {
        "opaque_id": stable_id("ctc", [item.get("code_normalized") or item.get("parent_code"),
                                       evidence.get("source_sha256"), item.get("row_id")]),
        "kind": item.get("kind"), "edition": item.get("edition"),
        "source_checksum": evidence.get("source_sha256"), "page": evidence.get("page"),
        "provenance_hash": evidence.get("raw_line_hash"), "outcome": item.get("outcome", "HIT"),
    }


def _fts_query(query: str) -> str:
    tokens = [x for x in _TOKEN.findall(query) if len(x) > 1]
    return " AND ".join(f'"{x}"' for x in tokens)


def get_line(catalogue_path: str, code: str, include_modifiers: bool = True,
             public_safe: bool = False) -> dict:
    digits = norm_code(code)
    if len(digits) != 12:
        return {"outcome": "MISS", "error": "A CTC line code must normalize to 12 digits."}
    con = connect_readonly(catalogue_path)
    try:
        manifest = _manifest(con)
        row = con.execute(
            "SELECT * FROM catalogue_row WHERE kind='task' AND code_normalized=? ORDER BY row_id LIMIT 1", (digits,)
        ).fetchone()
        if not row:
            return {"outcome": "MISS", "line_code": pretty_code(digits), "edition": manifest["edition"]}
        result = _row_out(row, manifest)
        if include_modifiers:
            mods = con.execute("SELECT * FROM catalogue_row WHERE kind='modifier' AND parent_code=? ORDER BY page_no,page_row",
                               (digits,)).fetchall()
            result["modifiers"] = [_row_out(x, manifest) for x in mods]
        result["outcome"] = "HIT"
        return _public_item(result) if public_safe else result
    finally:
        con.close()


def browse(catalogue_path: str, prefix: str = "", public_safe: bool = False) -> dict:
    digits = norm_code(prefix)
    if len(digits) not in (0, 2, 4, 6, 8):
        return {"outcome": "MISS", "error": "Browse prefix must be 0, 2, 4, 6, or 8 digits."}
    con = connect_readonly(catalogue_path)
    try:
        manifest = _manifest(con)
        next_level = len(digits) + 2
        if next_level <= 8:
            rows = con.execute(
                """SELECT h.code,h.parent_code,h.level,h.title,h.first_page,h.source,COUNT(r.row_id) AS task_count
                   FROM hierarchy h LEFT JOIN catalogue_row r ON r.kind='task' AND r.task_prefix LIKE h.code || '%'
                   WHERE h.level=? AND h.code LIKE ? GROUP BY h.code ORDER BY h.code""",
                (next_level // 2, digits + "%"),
            ).fetchall()
            out = [{"code": x["code"], "display_code": " ".join([x["code"][i:i+2] for i in range(0,len(x["code"]),2)]),
                    "title": x["title"], "task_count": x["task_count"], "first_page": x["first_page"],
                    "edition": manifest["edition"], "evidence": {"source_pdf_filename": manifest["source_filename"],
                    "source_sha256": manifest["source_sha256"], "page": x["first_page"]}} for x in rows]
            if public_safe:
                out = [{"opaque_id": stable_id("ctcnode", [x["code"], manifest["source_sha256"]]),
                        "level": next_level // 2, "edition": manifest["edition"],
                        "source_checksum": manifest["source_sha256"], "page": x["first_page"]}
                       for x in rows]
            return {"outcome": "HIT" if out else "MISS", "level": next_level//2, "children": out}
        rows = con.execute(
            "SELECT * FROM catalogue_row WHERE kind='task' AND code_normalized LIKE ? ORDER BY code_normalized LIMIT 200",
            (digits + "%",),
        ).fetchall()
        out = [_row_out(x, manifest) for x in rows]
        return {"outcome": "HIT" if out else "MISS", "children": [_public_item(x) for x in out] if public_safe else out}
    finally:
        con.close()


def _rrf(orderings: list[list[str]], k: int = 60) -> list[str]:
    scores: dict[str, float] = {}
    for ranking in orderings:
        for rank, item in enumerate(ranking, start=1):
            scores[item] = scores.get(item, 0.0) + 1.0 / (k + rank)
    return [x for x, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]


def search(catalogue_path: str, query: str, limit: int = 20, semantic: SemanticAdapter | None = None,
           reranker: RerankerAdapter | None = None, public_safe: bool = False) -> dict:
    """T1 exact/prefix, then T2 FTS. Adapters only rank retrieved candidates."""
    limit = max(1, min(int(limit), 100))
    con = connect_readonly(catalogue_path)
    try:
        manifest = _manifest(con)
        digits = norm_code(query)
        if digits and len(digits) == 12:
            exact = get_line(catalogue_path, digits, public_safe=public_safe)
            return {"tier": "T1", "mode": "exact", "outcome": exact["outcome"],
                    "results": [exact] if exact["outcome"] == "HIT" else [], "edition": manifest["edition"]}
        if digits and len(digits) in (2, 4, 6, 8):
            rows = con.execute(
                "SELECT * FROM catalogue_row WHERE kind='task' AND code_normalized LIKE ? ORDER BY code_normalized LIMIT ?",
                (digits + "%", limit),
            ).fetchall()
            results = [_row_out(x, manifest) for x in rows]
            if public_safe:
                results = [_public_item(x) for x in results]
            return {"tier": "T1", "mode": "prefix", "outcome": "HIT" if results else "MISS",
                    "results": results, "edition": manifest["edition"]}
        fts = _fts_query(query)
        if not fts:
            return {"tier": "T2", "mode": "fts", "outcome": "MISS", "results": [],
                    "error": "No searchable tokens."}
        try:
            rows = con.execute(
                """SELECT r.*, bm25(catalogue_fts) AS bm25,
                   snippet(catalogue_fts,1,'[',']','…',16) AS evidence_excerpt
                   FROM catalogue_fts JOIN catalogue_row r ON r.row_id=catalogue_fts.rowid
                   WHERE catalogue_fts MATCH ? ORDER BY bm25 LIMIT ?""", (fts, limit * 3)
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        candidates = [_row_out(x, manifest) for x in rows]
        for item, dbrow in zip(candidates, rows):
            item["lexical_score"] = -float(dbrow["bm25"])
            item["evidence"]["excerpt"] = dbrow["evidence_excerpt"]
        baseline = [str(x["row_id"]) for x in candidates]
        orders = [baseline]
        if semantic and candidates:
            proposed = semantic.rank(query, candidates)
            allowed = set(baseline)
            semantic_order = [x for x in proposed if x in allowed]
            orders.append(semantic_order)
        fused = _rrf(orders)
        by_id = {str(x["row_id"]): x for x in candidates}
        candidates = [by_id[x] for x in fused if x in by_id]
        if reranker and candidates:
            proposed = reranker.rank(query, candidates)
            allowed = set(str(x["row_id"]) for x in candidates)
            order = [x for x in proposed if x in allowed]
            missing = [str(x["row_id"]) for x in candidates if str(x["row_id"]) not in order]
            candidates = [by_id[x] for x in order + missing]
        candidates = candidates[:limit]
        if public_safe:
            candidates = [_public_item(x) for x in candidates]
        return {"tier": "T3" if semantic else "T2", "mode": "fts_rrf" if semantic else "fts",
                "outcome": "HIT" if candidates else "MISS", "results": candidates, "edition": manifest["edition"],
                "semantic_used": bool(semantic), "reranker_used": bool(reranker)}
    finally:
        con.close()


def bounded_reason(query: str, candidates: list[dict], adapter: ReasoningAdapter | None) -> dict:
    """T4 only chooses a retrieved row ID or abstains; no fabricated code can pass."""
    if not adapter:
        return {"outcome": "ABSTAIN", "reason": "No reasoning adapter registered."}
    valid = {str(x["row_id"]): x for x in candidates}
    choice = adapter.select(query, candidates)
    selected = str(choice.get("row_id", ""))
    if choice.get("outcome") == "ABSTAIN":
        return {"outcome": "ABSTAIN", "reason": choice.get("reason", "adapter abstained")}
    if selected not in valid:
        return {"outcome": "ABSTAIN", "reason": "Adapter selected a candidate outside retrieved set."}
    return {"outcome": "HIT", "tier": "T4", "result": valid[selected], "adapter_rationale": choice.get("rationale")}
