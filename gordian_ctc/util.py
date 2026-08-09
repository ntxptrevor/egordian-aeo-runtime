from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_code(value: str | None) -> str:
    return re.sub(r"[^0-9]", "", value or "")


def pretty_code(value: str | None) -> str:
    digits = norm_code(value)
    if len(digits) != 12:
        return value or ""
    return f"{digits[0:2]} {digits[2:4]} {digits[4:6]} {digits[6:8]}-{digits[8:12]}"


def money(value: str | None) -> float | None:
    if not value:
        return None
    s = value.strip().replace(",", "").replace("$", "").replace("(", "-").replace(")", "")
    try:
        return float(Decimal(s).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError):
        return None


def ensure_parent(path: str | os.PathLike[str]) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def stable_id(prefix: str, value: Any, n: int = 20) -> str:
    return f"{prefix}_{sha256_bytes(canonical_json(value).encode())[:n]}"


def redact_for_public(value: dict) -> dict:
    forbidden = {"description", "direct_unit_cost", "demolition_unit_cost", "raw_line",
                 "price_fields_json", "unit_price", "cost", "price", "page_text"}
    return {k: v for k, v in value.items() if k not in forbidden}
