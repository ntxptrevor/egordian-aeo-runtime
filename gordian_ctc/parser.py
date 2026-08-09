"""Deterministic text-native CTC PDF parser.

The supplied October 2024 CTC pages show a task-row format:
``01 56 26 00-0011  LF  Description .... 12.12 [14.88 demolition]``.
The parser never completes missing fields. Ambiguity becomes a parse exception.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

from .util import money, norm_code, sha256_bytes

PARSER_VERSION = "ctc-layout-v1.0.0"
TASK_RE = re.compile(
    r"^\s*(?P<code>\d{2}\s+\d{2}\s+\d{2}\s+\d{2}-\d{4})(?:\s+(?P<rest>\S.*?))?\s*$"
)
HEADER_RE = re.compile(r"^\s*(?P<code>\d{2}(?:\s+\d{2}){0,2})\s+(?P<title>[A-Z][A-Za-z0-9 ,/&'()\-]+?)\s*$")
AMOUNT_RE = re.compile(r"(?<![\w.])(?P<amount>-?\$?\(?\d{1,3}(?:,\d{3})*\.\d{2}\)?)(?![\w.])")
UNIT_RE = re.compile(r"^(?P<unit>%|[A-Z]{1,6}\.?)(?:\s+|$)(?P<tail>.*)$")
MODIFIER_RE = re.compile(
    r"^\s*(?P<desc>(?:For\b|Each\b|Mobilization\b|Add\b|Deduct\b|Credit\b|Remove\b).+?)(?:\.{3,}|\s{3,})(?P<prices>-?\$?\(?\d[\d,]*\.\d{2}\)?(?:\s+-?\$?\(?\d[\d,]*\.\d{2}\)?)?)\s*$",
    re.IGNORECASE,
)
SKIP_RE = re.compile(
    r"(TOTAL\s+DIRECT|MINOR\s+CSI|CSI\s+UOM\s+DESCRIPTION|copyright\s+2024|Public Building Commission|^\s*Page\s+\d{2}\s*-\s*\d+|^\s*2024\s*$|^\s*XXXXXXX\s*$|^\s*\.\s*$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ParsedRow:
    kind: str
    line_code: str | None
    code_normalized: str | None
    parent_code: str | None
    unit: str | None
    description: str | None
    direct_unit_cost: float | None
    demolition_unit_cost: float | None
    price_fields: list[float] = field(default_factory=list)
    page_no: int = 0
    page_row: int = 0
    raw_line_hash: str = ""
    raw_line: str = ""
    parse_flags: list[str] = field(default_factory=list)

    def json(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ParseException:
    page_no: int
    page_row: int
    category: str
    detail: str
    raw_line_hash: str

    def json(self) -> dict:
        return asdict(self)


def extractor_version() -> str:
    try:
        output = subprocess.run(["pdftotext", "-v"], capture_output=True, text=True, check=False)
        return (output.stderr or output.stdout).splitlines()[0].strip()
    except FileNotFoundError:
        return "pdftotext unavailable"


def extract_layout(pdf_path: str) -> str:
    """Run exactly one deterministic text-native extraction command."""
    cp = subprocess.run(
        ["pdftotext", "-layout", "-enc", "UTF-8", pdf_path, "-"],
        capture_output=True, check=False,
    )
    if cp.returncode:
        raise RuntimeError(f"pdftotext failed ({cp.returncode}): {cp.stderr.decode('utf-8', 'replace')[:500]}")
    return cp.stdout.decode("utf-8", "replace")


def _amounts(text: str) -> list[float]:
    return [x for x in (money(m.group("amount")) for m in AMOUNT_RE.finditer(text)) if x is not None]


def _parse_rest(rest: str) -> tuple[str | None, str | None, list[float], list[str]]:
    rest = (rest or "").rstrip()
    flags: list[str] = []
    prices = _amounts(rest)
    # The visible dotted leader distinguishes description from right-hand price columns.
    before = re.split(r"\.{3,}", rest, maxsplit=1)[0].rstrip()
    if not before and rest:
        before = rest
    if prices and not re.search(r"\.{3,}", rest):
        # No reliable visible column separator: do not remove terminal numbers from text.
        flags.append("price_without_dotted_leader")
        prices = []
    unit = None
    desc = before.strip() or None
    m = UNIT_RE.match(before.strip())
    if m:
        token = m.group("unit").rstrip(".")
        # Unit cells in this catalogue are uppercase compact tokens; descriptive
        # heading words are not accepted as units.
        if token and (token == "%" or token.isupper()) and len(token) <= 6:
            unit, desc = token, (m.group("tail").strip() or None)
    if prices and not desc:
        flags.append("missing_description")
    if len(prices) > 2:
        flags.append("more_than_two_price_columns")
    return unit, desc, prices, flags


def _header(line: str) -> tuple[str, str] | None:
    m = HEADER_RE.match(line)
    if not m:
        return None
    code = norm_code(m.group("code"))
    # Headers are up to CSI section (six digits); line code has 12 digits.
    if len(code) not in (2, 4, 6):
        return None
    return code, m.group("title")


def parse_layout(layout_text: str) -> tuple[list[ParsedRow], list[ParseException], dict[str, str]]:
    """Parse full layout text, retaining page boundaries and raw-line hashes."""
    rows: list[ParsedRow] = []
    exceptions: list[ParseException] = []
    hierarchy: dict[str, str] = {}
    current_parent: str | None = None
    for page_no, page in enumerate(layout_text.split("\f"), start=1):
        # Form-feed terminal produces an empty last part. Retaining it is harmless.
        for page_row, raw in enumerate(page.splitlines(), start=1):
            line = raw.rstrip()
            if not line.strip() or SKIP_RE.search(line):
                continue
            h = _header(line)
            if h:
                hierarchy.setdefault(h[0], h[1])
                continue
            m = TASK_RE.match(line)
            if m:
                code = norm_code(m.group("code"))
                unit, desc, prices, flags = _parse_rest(m.group("rest") or "")
                if not desc:
                    exceptions.append(ParseException(
                        page_no, page_row, "ambiguous_task_row",
                        "Task code observed without a parseable description; preserved as exception.",
                        sha256_bytes(raw.encode("utf-8")),
                    ))
                row = ParsedRow(
                    kind="task", line_code=m.group("code"), code_normalized=code,
                    parent_code=None, unit=unit, description=desc,
                    direct_unit_cost=prices[0] if len(prices) >= 1 else None,
                    demolition_unit_cost=prices[1] if len(prices) >= 2 else None,
                    price_fields=prices, page_no=page_no, page_row=page_row,
                    raw_line_hash=sha256_bytes(raw.encode("utf-8")), raw_line=raw,
                    parse_flags=flags,
                )
                rows.append(row)
                current_parent = code
                continue
            mm = MODIFIER_RE.match(line)
            if mm:
                prices = _amounts(mm.group("prices"))
                rows.append(ParsedRow(
                    kind="modifier", line_code=None, code_normalized=None,
                    parent_code=current_parent, unit=None, description=mm.group("desc").strip(),
                    direct_unit_cost=prices[0] if prices else None,
                    demolition_unit_cost=prices[1] if len(prices) > 1 else None,
                    price_fields=prices, page_no=page_no, page_row=page_row,
                    raw_line_hash=sha256_bytes(raw.encode("utf-8")), raw_line=raw,
                ))
                if not current_parent:
                    exceptions.append(ParseException(page_no, page_row, "orphan_modifier",
                        "Priced modifier has no preceding task code on current parse stream.",
                        sha256_bytes(raw.encode("utf-8"))))
    return rows, exceptions, hierarchy


def parse_pdf(pdf_path: str) -> tuple[list[ParsedRow], list[ParseException], dict[str, str], dict]:
    text = extract_layout(pdf_path)
    rows, exceptions, hierarchy = parse_layout(text)
    provenance = {
        "parser_version": PARSER_VERSION,
        "extractor": extractor_version(),
        "command": ["pdftotext", "-layout", "-enc", "UTF-8", "<source_pdf>", "-"],
        "page_count_extracted": len(text.split("\f")) - (1 if text.endswith("\f") else 0),
        "layout_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    return rows, exceptions, hierarchy, provenance


def row_content_hash(rows: Iterator[ParsedRow] | list[ParsedRow]) -> str:
    h = hashlib.sha256()
    for row in rows:
        h.update(repr(row.json()).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()
