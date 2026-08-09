#!/usr/bin/env python3
"""Render docker-compose.hostinger-bootstrap.yml from its parts.

The bootstrap program must be inlined into the compose file (the deployment
uses stock images and cannot build or mount a script), but a duplicated copy
would drift. This generator keeps `scripts/bootstrap_runtime.py` as the single
source of truth and embeds it verbatim; `tests/test_bootstrap_deployment.py`
fails if the compose file is out of sync.

    python3 scripts/render_bootstrap_compose.py            # write
    python3 scripts/render_bootstrap_compose.py --check    # verify only
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts" / "bootstrap_runtime.py"
TEMPLATE = ROOT / "scripts" / "bootstrap_compose_template.yml"
OUTPUT = ROOT / "docker-compose.hostinger-bootstrap.yml"
MARKER = "        # @@BOOTSTRAP_PROGRAM@@"
INDENT = " " * 8


def render() -> str:
    program = SOURCE.read_text(encoding="utf-8")
    body = "\n".join(INDENT + line if line.strip() else "" for line in program.splitlines())
    template = TEMPLATE.read_text(encoding="utf-8")
    if MARKER not in template:
        raise SystemExit(f"marker {MARKER!r} not found in {TEMPLATE}")
    return template.replace(MARKER, body)


def main(argv: list[str]) -> int:
    rendered = render()
    if "--check" in argv:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current != rendered:
            print("docker-compose.hostinger-bootstrap.yml is out of date; run "
                  "python3 scripts/render_bootstrap_compose.py", file=sys.stderr)
            return 1
        print("bootstrap compose is in sync")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(rendered)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
