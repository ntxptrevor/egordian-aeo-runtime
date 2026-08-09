"""Immutable licensed catalogue builder and read-only access."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
from collections import Counter
from pathlib import Path
from typing import Any

from .parser import PARSER_VERSION, ParsedRow, parse_pdf, row_content_hash
from .util import canonical_json, ensure_parent, norm_code, now, pretty_code, sha256_file

SCHEMA_VERSION = 1

CATALOGUE_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE hierarchy (
  code TEXT PRIMARY KEY, parent_code TEXT, level INTEGER NOT NULL, title TEXT,
  first_page INTEGER, source TEXT NOT NULL DEFAULT 'derived'
);
CREATE TABLE catalogue_row (
  row_id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('task','modifier')),
  line_code TEXT, code_normalized TEXT, parent_code TEXT, division TEXT,
  csi_section TEXT, csi_subsection TEXT, task_prefix TEXT,
  unit TEXT, description TEXT, direct_unit_cost REAL, demolition_unit_cost REAL,
  price_fields_json TEXT NOT NULL, page_no INTEGER NOT NULL, page_row INTEGER NOT NULL,
  raw_line_hash TEXT NOT NULL, extraction_json TEXT NOT NULL, parse_flags_json TEXT NOT NULL
);
CREATE INDEX idx_row_code ON catalogue_row(code_normalized);
CREATE INDEX idx_row_prefix ON catalogue_row(task_prefix);
CREATE INDEX idx_row_division ON catalogue_row(division);
CREATE INDEX idx_row_parent ON catalogue_row(parent_code);
CREATE TABLE parse_exception (
  exception_id INTEGER PRIMARY KEY, page_no INTEGER NOT NULL, page_row INTEGER NOT NULL,
  category TEXT NOT NULL, detail TEXT NOT NULL, raw_line_hash TEXT NOT NULL
);
CREATE TABLE build_manifest (
  manifest_id INTEGER PRIMARY KEY CHECK(manifest_id=1), source_filename TEXT NOT NULL,
  source_sha256 TEXT NOT NULL, edition TEXT NOT NULL, owner TEXT, parser_version TEXT NOT NULL,
  provenance_json TEXT NOT NULL, row_content_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
  sealed INTEGER NOT NULL DEFAULT 0
);
CREATE VIRTUAL TABLE catalogue_fts USING fts5(
  line_code, description, unit, csi_section,
  content='catalogue_row', content_rowid='row_id', tokenize='unicode61'
);
CREATE TRIGGER catalogue_ai AFTER INSERT ON catalogue_row BEGIN
  INSERT INTO catalogue_fts(rowid,line_code,description,unit,csi_section)
  VALUES(new.row_id,new.line_code,new.description,new.unit,new.csi_section);
END;
"""


def _connect_rw(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=DELETE")
    return con


def connect_readonly(path: str) -> sqlite3.Connection:
    resolved = Path(path).expanduser().resolve()
    con = sqlite3.connect(f"file:{resolved}?mode=ro&immutable=1", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _hierarchy_rows(rows: list[ParsedRow], titles: dict[str, str]) -> list[tuple]:
    all_codes: set[str] = set(titles)
    first_pages: dict[str, int] = {}
    for r in rows:
        if not r.code_normalized:
            continue
        for n in (2, 4, 6, 8):
            code = r.code_normalized[:n]
            all_codes.add(code)
            first_pages.setdefault(code, r.page_no)
    out = []
    for code in sorted(all_codes, key=lambda c: (len(c), c)):
        parent = code[:-2] if len(code) > 2 else None
        out.append((code, parent, len(code)//2, titles.get(code), first_pages.get(code), "pdf_heading" if code in titles else "derived"))
    return out


def build_catalogue(pdf_path: str, catalogue_path: str, edition: str, owner: str | None = None,
                    report_path: str | None = None) -> dict[str, Any]:
    """Build a sealed DB from the supplied text-native PDF. Existing output is replaced."""
    if not edition.strip():
        raise ValueError("edition is required")
    pdf = Path(pdf_path).expanduser().resolve()
    if not pdf.is_file():
        raise FileNotFoundError(pdf)
    out = Path(catalogue_path).expanduser().resolve()
    ensure_parent(out)
    if out.exists():
        out.chmod(stat.S_IWRITE | stat.S_IREAD)
        out.unlink()
    rows, exceptions, headings, provenance = parse_pdf(str(pdf))
    con = _connect_rw(str(out))
    try:
        con.executescript(CATALOGUE_SCHEMA)
        for code, parent, level, title, first_page, source in _hierarchy_rows(rows, headings):
            con.execute("INSERT INTO hierarchy VALUES(?,?,?,?,?,?)",
                        (code, parent, level, title, first_page, source))
        for r in rows:
            digits = r.code_normalized
            con.execute(
                """INSERT INTO catalogue_row(kind,line_code,code_normalized,parent_code,division,csi_section,
                   csi_subsection,task_prefix,unit,description,direct_unit_cost,demolition_unit_cost,
                   price_fields_json,page_no,page_row,raw_line_hash,extraction_json,parse_flags_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (r.kind, r.line_code, digits, r.parent_code, digits[:2] if digits else None,
                 digits[:6] if digits else None, digits[:8] if digits else None,
                 digits[:8] if digits else (r.parent_code[:8] if r.parent_code else None),
                 r.unit, r.description, r.direct_unit_cost, r.demolition_unit_cost,
                 canonical_json(r.price_fields), r.page_no, r.page_row, r.raw_line_hash,
                 canonical_json({"parser_version": PARSER_VERSION, "raw_line_hash": r.raw_line_hash}),
                 canonical_json(r.parse_flags)))
        con.executemany(
            "INSERT INTO parse_exception(page_no,page_row,category,detail,raw_line_hash) VALUES(?,?,?,?,?)",
            [(e.page_no, e.page_row, e.category, e.detail, e.raw_line_hash) for e in exceptions],
        )
        duplicates = con.execute(
            """SELECT code_normalized, COUNT(*) n FROM catalogue_row
               WHERE kind='task' AND code_normalized IS NOT NULL GROUP BY code_normalized HAVING n>1"""
        ).fetchall()
        direct_count = con.execute("SELECT COUNT(*) FROM catalogue_row WHERE direct_unit_cost IS NOT NULL").fetchone()[0]
        demo_count = con.execute("SELECT COUNT(*) FROM catalogue_row WHERE demolition_unit_cost IS NOT NULL").fetchone()[0]
        invalid_prices = con.execute(
            "SELECT COUNT(*) FROM catalogue_row WHERE direct_unit_cost IS NOT NULL AND typeof(direct_unit_cost)!='real'"
        ).fetchone()[0]
        content_hash = row_content_hash(rows)
        con.execute(
            "INSERT INTO build_manifest VALUES(1,?,?,?,?,?,?,?,?,1)",
            (pdf.name, sha256_file(pdf), edition, owner, PARSER_VERSION, canonical_json(provenance), content_hash, now()),
        )
        con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        con.commit()
        # FTS integrity command demonstrates index consistency where supported.
        try:
            con.execute("INSERT INTO catalogue_fts(catalogue_fts) VALUES('integrity-check')")
        except sqlite3.OperationalError:
            pass
        counts = {
            "rows_total": con.execute("SELECT COUNT(*) FROM catalogue_row").fetchone()[0],
            "task_rows": con.execute("SELECT COUNT(*) FROM catalogue_row WHERE kind='task'").fetchone()[0],
            "modifier_rows": con.execute("SELECT COUNT(*) FROM catalogue_row WHERE kind='modifier'").fetchone()[0],
            "hierarchy_nodes": con.execute("SELECT COUNT(*) FROM hierarchy").fetchone()[0],
            "parse_exceptions": len(exceptions), "duplicate_codes": len(duplicates),
            "direct_unit_cost_present": direct_count, "demolition_unit_cost_present": demo_count,
            "invalid_price_storage": invalid_prices,
            "divisions": [r[0] for r in con.execute(
                "SELECT DISTINCT division FROM catalogue_row WHERE division IS NOT NULL ORDER BY division")],
            "sections": con.execute("SELECT COUNT(*) FROM hierarchy WHERE level=3").fetchone()[0],
        }
    finally:
        con.close()
    # seal only after SQLite closes.
    try:
        out.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass
    report = {
        "system": "egordian-proposal-generator", "schema_version": SCHEMA_VERSION,
        "catalogue_path": str(out), "source_pdf_filename": pdf.name,
        "source_sha256": sha256_file(pdf), "edition": edition, "owner": owner,
        "parser_provenance": provenance, "row_content_sha256": content_hash,
        "catalogue_file_sha256": sha256_file(out), "counts": counts,
        "duplicate_code_samples": [dict(x) for x in duplicates[:100]],
        "arithmetic_validation": {
            "status": "not_applicable_for_component_arithmetic",
            "reason": "Observed catalogue pages expose total direct and optional demolition unit cost only; no material/labor/equipment components were present to sum.",
            "price_field_storage_valid": invalid_prices == 0,
        },
        "quarantine_policy": "Ambiguous rows are recorded in parse_exception; no missing value is inferred.",
    }
    if report_path:
        ensure_parent(report_path)
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def verify_catalogue(catalogue_path: str) -> dict[str, Any]:
    con = connect_readonly(catalogue_path)
    try:
        manifest = dict(con.execute("SELECT * FROM build_manifest WHERE manifest_id=1").fetchone() or {})
        if not manifest or manifest.get("sealed") != 1:
            raise ValueError("Catalogue is not sealed.")
        task_count = con.execute("SELECT COUNT(*) FROM catalogue_row WHERE kind='task'").fetchone()[0]
        fts_count = con.execute("SELECT COUNT(*) FROM catalogue_fts").fetchone()[0]
        missing_prov = con.execute(
            "SELECT COUNT(*) FROM catalogue_row WHERE raw_line_hash='' OR extraction_json=''"
        ).fetchone()[0]
        return {"ok": task_count > 0 and fts_count == task_count + con.execute(
            "SELECT COUNT(*) FROM catalogue_row WHERE kind='modifier'").fetchone()[0] and missing_prov == 0,
                "task_count": task_count, "fts_count": fts_count, "missing_provenance": missing_prov,
                "manifest": manifest, "catalogue_file_sha256": sha256_file(catalogue_path)}
    finally:
        con.close()


def catalogue_info(catalogue_path: str) -> dict[str, Any]:
    con = connect_readonly(catalogue_path)
    try:
        return {
            "manifest": dict(con.execute("SELECT * FROM build_manifest WHERE manifest_id=1").fetchone()),
            "counts": {k: con.execute(q).fetchone()[0] for k, q in {
                "rows": "SELECT COUNT(*) FROM catalogue_row", "tasks": "SELECT COUNT(*) FROM catalogue_row WHERE kind='task'",
                "modifiers": "SELECT COUNT(*) FROM catalogue_row WHERE kind='modifier'",
                "exceptions": "SELECT COUNT(*) FROM parse_exception", "divisions": "SELECT COUNT(DISTINCT division) FROM catalogue_row WHERE division IS NOT NULL",
                "sections": "SELECT COUNT(*) FROM hierarchy WHERE level=3"}.items()},
        }
    finally:
        con.close()
