#!/usr/bin/env python3
"""Pinned public launcher for the single-service Hostinger deployment.

Hostinger's Compose parser rejected the two-service file (`depends_on` with
`condition: service_completed_successfully`), so the whole deployment has to be
**one service running a stock `python:3.12-slim`**. The compose `command` is a
ten-line stdlib downloader that fetches this file at a pinned ref and runs it;
everything else happens here.

Sequence (root for the first phase only):

  1. download the approved public repo archive for the pinned ``RUNTIME_REF``;
  2. extract it with full path-traversal / link / device checks;
  3. verify the encrypted catalogue parts (contiguous indices, per-part size and
     SHA-256, overall SHA-256, ``EGCAT1`` magic) and concatenate them;
  4. ``pip install --target`` the dependencies into the named ``/runtime`` volume;
  5. stage code, decryptor and entrypoint; create the persistent state directory
     at ``/runtime/state``; chown everything to 10001:10001;
  6. make code and ciphertext read-only while state stays writable;
  7. **drop privileges irreversibly** - ``os.setgroups([]) ; setgid ; setuid`` -
     assert the drop cannot be undone, then ``execve`` the existing registry
     entrypoint, which unseals the catalogue into the ``/run/egordian`` tmpfs and
     starts uvicorn.

The launcher never sees a secret: the decryption key and service tokens are
runtime environment variables consumed by the entrypoint *after* the drop. No
plaintext catalogue is ever written to the named volume - only to tmpfs.

Post-extraction work is delegated to ``scripts/bootstrap_runtime.py`` from the
verified archive, so the staging logic has a single source of truth. Download
and extraction are implemented here because they must run before anything from
the archive can be trusted.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

MAGIC = b"EGCAT1"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
DEFAULT_ENTRYPOINT = "/runtime/bin/registry-entrypoint.sh"
SECRET_NAMES = ("CATALOGUE_DECRYPTION_KEY", "SERVICE_TOKENS", "EGORDIAN_PASSWORD",
                "EGORDIAN_BEARER_TOKEN", "EGORDIAN_HEADER_MAP", "DATABASE_URL")


def log(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} launcher: {message}",
          file=sys.stderr, flush=True)


def die(message: str, code: int = 78):
    log(f"FATAL: {message}")
    raise SystemExit(code)


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


# ---------------------------------------------------------------------------
# download + secure extraction (must not trust the archive yet)
# ---------------------------------------------------------------------------

def archive_url(repo: str, ref: str) -> str:
    if "/" not in repo or repo.strip("/") != repo:
        die(f"RUNTIME_REPO must be owner/name, got {repo!r}")
    if not ref or ref.startswith("/") or ref.endswith("/") or ".." in ref or "//" in ref:
        die(f"RUNTIME_REF must be a bare commit SHA or branch name, got {ref!r}")
    for char in ref:
        if not (char.isalnum() or char in "._-/"):
            die(f"RUNTIME_REF contains an unsafe character: {ref!r}")
    return f"https://github.com/{repo}/archive/{ref}.tar.gz"


def download(url: str, destination: Path, expected_sha256: str = "") -> str:
    log(f"downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "egordian-launcher/1"})
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            if response.status != 200:
                die(f"archive download returned HTTP {response.status}")
            with destination.open("wb") as out:
                while True:
                    block = response.read(1 << 20)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_ARCHIVE_BYTES:
                        die("archive exceeds the maximum allowed size")
                    digest.update(block)
                    out.write(block)
    except urllib.error.HTTPError as exc:
        die(f"archive download failed with HTTP {exc.code} (is {url} public?)")
    except urllib.error.URLError as exc:
        die(f"archive download failed: {exc.reason}")
    actual = digest.hexdigest()
    if expected_sha256 and actual != expected_sha256.strip().lower():
        die(f"archive SHA-256 mismatch: expected {expected_sha256[:16]}…, got {actual[:16]}…")
    log(f"downloaded {total} bytes, sha256 {actual}")
    return actual


def safe_extract(archive: Path, target: Path) -> Path:
    """Extract a tarball, refusing anything that could escape ``target``."""
    target.mkdir(parents=True, exist_ok=True)
    resolved_target = target.resolve()
    roots: set[str] = set()
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            name = member.name
            if member.issym() or member.islnk():
                die(f"archive contains a link member: {name}")
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                die(f"archive contains a device/fifo member: {name}")
            if not (member.isfile() or member.isdir()):
                die(f"archive contains an unsupported member type: {name}")
            if name.startswith("/") or name.startswith("\\"):
                die(f"archive member has an absolute path: {name}")
            parts = Path(name).parts
            if ".." in parts:
                die(f"archive member attempts path traversal: {name}")
            destination = (resolved_target / name).resolve()
            if destination != resolved_target and resolved_target not in destination.parents:
                die(f"archive member escapes the extraction root: {name}")
            member.mode = 0o755 if member.isdir() else 0o644
            member.uid = member.gid = 0
            member.uname = member.gname = "root"
            if parts:
                roots.add(parts[0])
            members.append(member)
        if len(roots) != 1:
            die(f"archive must contain exactly one top-level directory, found {sorted(roots)}")
        tar.extractall(resolved_target, members=members)  # nosec - members validated above
    extracted = resolved_target / roots.pop()
    if not extracted.is_dir():
        die("archive did not produce the expected top-level directory")
    return extracted


def load_bootstrap(source_root: Path):
    """Import the staging helpers from the verified archive (one source of truth)."""
    module_path = source_root / "scripts" / "bootstrap_runtime.py"
    if not module_path.is_file():
        die("published repo is missing scripts/bootstrap_runtime.py")
    spec = importlib.util.spec_from_file_location("egordian_bootstrap", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for attribute in ("assemble_catalogue", "install_dependencies", "stage"):
        if not hasattr(module, attribute):
            die(f"bootstrap module is missing {attribute}()")
    return module


# ---------------------------------------------------------------------------
# permissions
# ---------------------------------------------------------------------------

def chown_tree(path: Path, uid: int, gid: int) -> None:
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    try:
        os.chown(path, uid, gid)
    except (PermissionError, FileNotFoundError):
        return
    for child in path.rglob("*"):
        try:
            os.chown(child, uid, gid, follow_symlinks=False)
        except (PermissionError, FileNotFoundError):  # pragma: no cover
            pass


def set_tree_mode(path: Path, *, writable: bool) -> None:
    """Lock code/ciphertext down to read-only, or reopen it for re-staging."""
    dir_mode = 0o755 if writable else 0o555
    file_mode = 0o644 if writable else 0o444
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_symlink():
            continue
        try:
            keep_exec = child.is_file() and bool(child.stat().st_mode & stat.S_IXUSR)
            if child.is_dir():
                os.chmod(child, dir_mode)
            else:
                os.chmod(child, (0o755 if writable else 0o555) if keep_exec else file_mode)
        except (PermissionError, FileNotFoundError):  # pragma: no cover
            pass
    try:
        os.chmod(path, dir_mode)
    except (PermissionError, FileNotFoundError):  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# privilege drop
# ---------------------------------------------------------------------------

def drop_privileges(uid: int, gid: int) -> None:
    """Irreversibly drop to the unprivileged runtime account."""
    if not hasattr(os, "geteuid"):  # pragma: no cover - non-POSIX
        die("privilege drop is unsupported on this platform")
    if os.geteuid() != 0:
        if os.geteuid() != uid:
            die(f"launcher must start as root or as uid {uid}, got {os.geteuid()}")
        log(f"already running as uid {uid}; no privilege drop needed")
        return
    if uid == 0 or gid == 0:
        die("refusing to run the service as root")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getuid() != uid or os.geteuid() != uid or os.getgid() != gid:
        die("privilege drop failed", 79)
    try:
        os.setuid(0)
    except OSError:
        pass
    else:  # pragma: no cover - would mean the drop was reversible
        die("privilege drop was reversible; refusing to continue", 79)
    log(f"dropped privileges to uid {uid} gid {gid} with no supplementary groups")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    repo = env("RUNTIME_REPO", "ntxptrevor/egordian-aeo-runtime")
    ref = env("RUNTIME_REF", "8659f42")
    runtime_root = Path(env("RUNTIME_ROOT", "/runtime"))
    uid = int(env("RUNTIME_UID", "10001"))
    gid = int(env("RUNTIME_GID", "10001"))
    archive_pin = env("ARCHIVE_SHA256")
    enc_pin = env("CATALOGUE_ENC_SHA256")
    force = env("FORCE_BOOTSTRAP") == "1"
    entrypoint = env("RUNTIME_ENTRYPOINT", DEFAULT_ENTRYPOINT)
    exec_service = env("LAUNCHER_EXEC", "1") == "1"

    state_dir = runtime_root / "state"
    catalogue_enc = runtime_root / "catalogue.enc"
    stamp_path = runtime_root / ".bootstrap-complete.json"
    code_paths = [runtime_root / "app", runtime_root / "bin",
                  runtime_root / "site-packages"]

    runtime_root.mkdir(parents=True, exist_ok=True)
    if not os.access(runtime_root, os.W_OK):
        die(f"runtime volume {runtime_root} is not writable")

    import json
    ready = False
    if stamp_path.is_file() and not force:
        try:
            stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        except ValueError:
            stamp = {}
        ready = (stamp.get("repo") == repo and stamp.get("ref") == ref
                 and stamp.get("enc_pin", "") == enc_pin
                 and catalogue_enc.is_file()
                 and all(p.is_dir() for p in code_paths))
        if ready:
            log(f"runtime volume already prepared for {repo}@{ref}; skipping bootstrap")

    if not ready:
        if ref in ("main", "master", "HEAD"):
            log(f"WARNING: RUNTIME_REF={ref} is mutable; pin a commit SHA")
        for path in code_paths:
            set_tree_mode(path, writable=True)
        if catalogue_enc.exists():
            os.chmod(catalogue_enc, 0o644)
        if stamp_path.exists():
            os.chmod(stamp_path, 0o644)

        with tempfile.TemporaryDirectory(prefix="egordian-launch-") as work:
            workdir = Path(work)
            archive = workdir / "runtime.tar.gz"
            archive_sha = download(archive_url(repo, ref), archive, archive_pin)
            source_root = safe_extract(archive, workdir / "src")
            bootstrap = load_bootstrap(source_root)

            catalogue = bootstrap.assemble_catalogue(source_root, catalogue_enc, enc_pin)
            bootstrap.install_dependencies(source_root, runtime_root / "site-packages")
            bootstrap.stage(source_root, runtime_root)

        stamp_path.write_text(json.dumps({
            "repo": repo, "ref": ref, "enc_pin": enc_pin,
            "archive_sha256": archive_sha,
            "catalogue_encrypted_sha256": catalogue["sha256"],
            "catalogue_part_count": catalogue["part_count"],
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "launcher": "single-service",
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Persistent, writable state (the SQLite control plane) lives here only.
    state_dir.mkdir(parents=True, exist_ok=True)

    for path in code_paths:
        chown_tree(path, uid, gid)
    chown_tree(state_dir, uid, gid)
    for path in (catalogue_enc, stamp_path):
        if path.exists():
            chown_tree(path, uid, gid)

    # Code and ciphertext read-only; state writable.
    for path in code_paths:
        set_tree_mode(path, writable=False)
    if catalogue_enc.exists():
        os.chmod(catalogue_enc, 0o444)
    if stamp_path.exists():
        os.chmod(stamp_path, 0o444)
    os.chmod(state_dir, 0o700)

    if not catalogue_enc.is_file():
        die("sealed catalogue is missing after staging", 79)
    with catalogue_enc.open("rb") as handle:
        head = handle.read(15)
    if head[:6] != MAGIC:
        die("staged catalogue is not an EGCAT1 container", 79)
    if head == b"SQLite format 3":  # pragma: no cover - defensive
        die("refusing to run: plaintext catalogue found on the runtime volume", 79)

    child_env = {k: v for k, v in os.environ.items()}
    child_env.setdefault("CATALOGUE_ENC_PATH", str(catalogue_enc))
    child_env.setdefault("CATALOGUE_CRYPTO_PATH", str(runtime_root / "bin" / "catalogue_crypto.py"))
    child_env.setdefault("APP_ROOT", str(runtime_root / "app"))
    child_env.setdefault("RUNTIME_SITE_PACKAGES", str(runtime_root / "site-packages"))
    child_env.setdefault("OVERLAY_DB_PATH", str(state_dir / "data.db"))
    child_env.setdefault("CATALOGUE_RUNTIME_DIR", "/run/egordian")
    child_env.setdefault("CATALOGUE_DB_PATH", "/run/egordian/catalogue.sqlite")
    child_env.setdefault("HOME", "/tmp")
    for name in ("LAUNCHER_URL", "LAUNCHER_SHA256"):
        child_env.pop(name, None)

    drop_privileges(uid, gid)

    if not exec_service:
        log("LAUNCHER_EXEC=0: preparation complete, not starting the service")
        return 0
    if not os.access(entrypoint, os.X_OK):
        die(f"entrypoint {entrypoint} is missing or not executable", 79)
    log(f"exec {entrypoint}")
    os.execve(entrypoint, [entrypoint], child_env)
    die("execve returned unexpectedly", 79)  # pragma: no cover
    return 79


if __name__ == "__main__":
    raise SystemExit(main())
