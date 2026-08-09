"""Retrieval evaluation using a private user-created eval set."""
from __future__ import annotations

import json
from pathlib import Path

from .query import search
from .util import norm_code


def run_eval(catalogue_path: str, eval_path: str) -> dict:
    cases = json.loads(Path(eval_path).read_text(encoding="utf-8")).get("cases", [])
    outcomes = []
    for case in cases:
        result = search(catalogue_path, case["query"], int(case.get("k", 10)))
        got = [norm_code(x.get("code_normalized") or x.get("line_code")) for x in result.get("results", [])]
        expected = norm_code(case["expected_code"])
        outcomes.append({"id": case.get("id"), "expected_code": expected, "retrieved": got,
                         "hit_at_k": expected in got, "rank": (got.index(expected) + 1 if expected in got else None)})
    total = len(outcomes)
    hits = sum(1 for x in outcomes if x["hit_at_k"])
    return {"total": total, "hits": hits, "recall_at_k": (hits / total if total else 0.0), "cases": outcomes}
