#!/usr/bin/env python3
"""QA-only harness that emulates the deploy-time proxy.

It copies ``dist/public`` to a temp dir, applies the same ``__PORT_8080__`` ->
``port/8080`` rewrite that ``deploy_website`` performs, serves the result from a
nested sub-path (``/computer/a/<id>/``) to mimic the iframe app URL, and
forwards ``<subpath>/port/8080/*`` to the real backend. Nothing here ships in
the bundle or changes backend behaviour.

Usage: python scripts/preview_proxy.py [listen_port] [backend_port]
"""
from __future__ import annotations

import http.server
import shutil
import socketserver
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist" / "public"
STAGE = Path("/tmp/aeo_preview_stage")
SUBPATH = "/computer/a/aeo-preview"

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
BACKEND = f"http://127.0.0.1:{sys.argv[2] if len(sys.argv) > 2 else 8080}"


def stage() -> Path:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    shutil.copytree(DIST, STAGE)
    for path in STAGE.rglob("*"):
        if path.is_file() and path.suffix in (".js", ".html", ".css"):
            text = path.read_text(encoding="utf-8")
            if "__PORT_8080__" in text:
                path.write_text(text.replace("__PORT_8080__", "port/8080"), encoding="utf-8")
    return STAGE


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STAGE), **kwargs)

    def translate_path(self, path: str) -> str:
        if path.startswith(SUBPATH):
            path = path[len(SUBPATH):] or "/"
        return super().translate_path(path)

    def do_GET(self):  # noqa: N802
        marker = f"{SUBPATH}/port/8080/"
        if marker in self.path:
            target = BACKEND + "/" + self.path.split(marker, 1)[1]
            request = urllib.request.Request(target, method="GET")
            for header in ("authorization", "accept"):
                if header in self.headers:
                    request.add_header(header, self.headers[header])
            try:
                with urllib.request.urlopen(request, timeout=30) as upstream:
                    body, status = upstream.read(), upstream.status
                    ctype = upstream.headers.get("content-type", "application/json")
            except urllib.error.HTTPError as exc:
                body, status = exc.read(), exc.code
                ctype = exc.headers.get("content-type", "application/json")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    stage()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", LISTEN_PORT), Handler) as httpd:
        print(f"preview on http://0.0.0.0:{LISTEN_PORT}{SUBPATH}/index.html -> {BACKEND}",
              flush=True)
        httpd.serve_forever()
