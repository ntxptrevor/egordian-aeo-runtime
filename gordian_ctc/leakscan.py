"""License-leak scanning for public exports and archives."""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

FORBIDDEN_KEYS = {
    "description", "line_description", "private_description", "direct_unit_cost",
    "demolition_unit_cost", "unit_price", "price", "cost", "price_fields",
    "price_fields_json", "raw_line", "page_text", "crew", "labor", "material",
    "equipment", "productivity",
}
FORBIDDEN_SUFFIXES = {".pdf", ".sqlite", ".db"}
FORBIDDEN_NAME = re.compile(r"(catalogue|gordian|ctc).*\.(pdf|sqlite|db)$", re.I)


def scan_obj(obj: Any, path: str = "$") -> list[str]:
    problems: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                problems.append(f"{path}.{key}: forbidden licensed-data field")
            problems.extend(scan_obj(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            problems.extend(scan_obj(value, f"{path}[{i}]"))
    return problems


def scan_export(path: str) -> list[str]:
    """Scan JSON or JSONL export artifacts, not explanatory documentation."""
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    try:
        return scan_obj(json.loads(text))
    except json.JSONDecodeError:
        issues = []
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                issues.extend(scan_obj(json.loads(line), f"line[{i}]"))
            except json.JSONDecodeError:
                issues.append(f"line[{i}]: non-JSON content cannot be certified as a minimized export")
        return issues


def scan_archive(path: str) -> list[str]:
    issues: list[str] = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            lower = name.lower()
            suffix = Path(lower).suffix
            if suffix in FORBIDDEN_SUFFIXES or FORBIDDEN_NAME.search(name):
                issues.append(f"{name}: prohibited private/licensed file in public archive")
    return issues
