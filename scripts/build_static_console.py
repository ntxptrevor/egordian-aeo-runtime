#!/usr/bin/env python3
"""Build the deploy-ready static console bundle at dist/public.

The backend is unchanged. This script only produces a *static* copy of the
operator console whose every backend call is routed through the
``__PORT_8080__`` placeholder that ``deploy_website`` rewrites to the
authenticated proxy path at deploy time.

Invariants enforced by this build (and asserted by tests/test_static_bundle.py):

* every backend URL is built from a single ``API`` base derived from
  ``__PORT_8080__`` - never a same-origin ``/api/...`` path;
* every asset/link reference is *relative* so the bundle works from any iframe
  sub-path (``/computer/a/<id>/index.html``);
* no ``localStorage`` / ``sessionStorage`` / ``document.cookie`` usage;
* read-only: the only HTTP method the bundle can issue is GET;
* no secrets, no bearer token defaults, no ``data/`` or catalogue paths.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
DIST = ROOT / "dist" / "public"

PORT_PLACEHOLDER = "__PORT_8080__"

# --- rewrites applied to the copied HTML -----------------------------------
HTML_REWRITES: list[tuple[str, str]] = [
    # absolute asset/link paths -> relative, so any iframe sub-path works
    ('href="/assets/', 'href="./assets/'),
    ('src="/assets/', 'src="./assets/'),
    ('href="/docs-api"', 'href="./docs.html"'),
    ('href="/openapi.json"', 'href="#" id="openapi-link"'),
    ('<a href="/">', '<a href="./index.html">'),
]


def rewrite_html(text: str, *, page: str) -> str:
    for old, new in HTML_REWRITES:
        text = text.replace(old, new)
    banner = (
        '<div class="notice" style="margin-bottom:16px">'
        "<strong>Static operator console.</strong> Read-only. All data is fetched "
        "live from the service API through the authenticated deployment proxy "
        "path; this bundle ships no service data, no credentials and no "
        "catalogue content. Paste an operator bearer token to load status."
        "</div>"
    )
    if page == "index":
        text = text.replace('<div class="notice" id="intro">',
                            banner + '\n  <div class="notice" id="intro">')
    return text


def main() -> int:
    if DIST.exists():
        shutil.rmtree(DIST)
    (DIST / "assets").mkdir(parents=True)

    # 1. styles - copied verbatim (no network calls beyond the font CDNs)
    shutil.copy2(CONSOLE / "assets" / "console.css", DIST / "assets" / "console.css")

    # 2. pages
    index = rewrite_html((CONSOLE / "index.html").read_text(encoding="utf-8"), page="index")
    docs = rewrite_html((CONSOLE / "docs.html").read_text(encoding="utf-8"), page="docs")
    index = index.replace('src="/assets/console.js"', 'src="./assets/console.js"')
    docs = docs.replace("</body>", '<script src="./assets/console.js"></script>\n</body>')
    (DIST / "index.html").write_text(index, encoding="utf-8")
    (DIST / "docs.html").write_text(docs, encoding="utf-8")

    # 3. static-bundle console script (proxy-aware, read-only)
    shutil.copy2(ROOT / "console" / "static" / "console.static.js",
                 DIST / "assets" / "console.js")

    # 4. crawler policy for the static host
    (DIST / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")

    # --- self-check --------------------------------------------------------
    problems: list[str] = []
    for path in sorted(DIST.rglob("*")):
        if path.is_dir():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"""fetch\(\s*['"`]/(api|readyz|healthz)""", text):
            problems.append(f"{path.name}: same-origin backend fetch")
        if re.search(r"localStorage|sessionStorage|document\.cookie", text):
            problems.append(f"{path.name}: browser storage usage")
        if re.search(r'(href|src)="/(?!/)', text):
            problems.append(f"{path.name}: absolute root-relative reference")
        if "dev-local-token" in text or "SERVICE_TOKENS=" in text:
            problems.append(f"{path.name}: token material")
        if "catalogue.sqlite" in text or re.search(r'["\']/data/', text):
            problems.append(f"{path.name}: data path reference")
    if problems:
        print("BUILD FAILED:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1

    files = sorted(str(p.relative_to(DIST)) for p in DIST.rglob("*") if p.is_file())
    print("built", DIST)
    for name in files:
        print("  ", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
