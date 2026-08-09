#!/usr/bin/env python3
"""One-shot runtime bootstrap - stock `python:3.12-slim`, no custom image.

Hostinger's create-project runner stores a compose file but never builds a
remote git `build.context`, so the deployment must work with **stock images
only**. This program is what the bootstrap service runs. It:

  1. downloads the approved public repo archive for a pinned ref
     (``RUNTIME_REF``, default a commit SHA - never a mutable branch unless the
     operator overrides it) using the Python standard library only;
  2. extracts it **securely** - every member is checked for absolute paths,
     ``..`` traversal, symlinks/hardlinks/devices and post-resolution escape;
  3. verifies the encrypted catalogue parts against
     ``build/catalogue.enc.parts.json`` (per-part size + SHA-256, contiguous
     indices), concatenates them in order, verifies the overall encrypted
     SHA-256 and the ``EGCAT1`` magic;
  4. installs the Python dependencies into a persistent private runtime volume
     with ``pip install --target``;
  5. stages the application code, the decryptor, the entrypoint and the
     ciphertext into that volume, owned by uid/gid 10001;
  6. writes an idempotency stamp and exits 0.

It never sees a secret: no decryption key, no service tokens. The plaintext
catalogue is never produced here - only the sealed container is staged, and it
is unsealed later into tmpfs by the runtime service.

Environment (all non-secret):
  RUNTIME_REPO      owner/name of the public encrypted-source repo
  RUNTIME_REF       commit SHA (preferred) or branch name
  RUNTIME_ROOT      target volume mount, default /runtime
  RUNTIME_UID/GID   ownership for the staged tree, default 10001
  ARCHIVE_SHA256    optional pin for the downloaded tarball
  CATALOGUE_ENC_SHA256  optional pin for the reassembled ciphertext
  FORCE_BOOTSTRAP   "1" re-runs even when the stamp matches
  PIP_INDEX_URL     optional mirror
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

STAMP_NAME = ".bootstrap-complete.json"
MAGIC = b"EGCAT1"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
STAGE_DIRS = ("app", "gordian_ctc", "profiles", "schemas", "console", "fixtures")
REQUIREMENTS = ("requirements-registry.txt", "requirements.txt")


def log(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} bootstrap: {message}",
          file=sys.stderr, flush=True)


def die(message: str, code: int = 78) -> "NoReturn":  # type: ignore[valid-type]
    log(f"FATAL: {message}")
    raise SystemExit(code)


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------

def archive_url(repo: str, ref: str) -> str:
    if "/" not in repo or repo.strip("/") != repo:
        die(f"RUNTIME_REPO must be owner/name, got {repo!r}")
    if not ref or ref.startswith("/") or ref.endswith("/"):
        die(f"RUNTIME_REF must be a bare commit SHA or branch name, got {ref!r}")
    if ".." in ref or "//" in ref:
        die(f"RUNTIME_REF must not contain path traversal: {ref!r}")
    for char in ref:
        if not (char.isalnum() or char in "._-/"):
            die(f"RUNTIME_REF contains an unsafe character: {ref!r}")
    return f"https://github.com/{repo}/archive/{ref}.tar.gz"


def download(url: str, destination: Path, expected_sha256: str = "") -> str:
    log(f"downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "egordian-bootstrap/1"})
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
        die(f"archive download failed with HTTP {exc.code} "
            f"(does {url} exist and is the repo public?)")
    except urllib.error.URLError as exc:
        die(f"archive download failed: {exc.reason}")
    actual = digest.hexdigest()
    if expected_sha256 and actual != expected_sha256.strip().lower():
        die(f"archive SHA-256 mismatch: expected {expected_sha256[:16]}…, got {actual[:16]}…")
    log(f"downloaded {total} bytes, sha256 {actual}")
    return actual


# ---------------------------------------------------------------------------
# secure extraction
# ---------------------------------------------------------------------------

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
            if ":" in name and os.name == "nt":  # pragma: no cover
                die(f"archive member has a drive-relative path: {name}")
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
    log(f"extracted {sum(1 for _ in extracted.rglob('*'))} entries")
    return extracted


# ---------------------------------------------------------------------------
# ciphertext verification + assembly
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def assemble_catalogue(source_root: Path, destination: Path, pin: str = "") -> dict:
    build_dir = source_root / "build"
    manifest_path = build_dir / "catalogue.enc.parts.json"
    if not manifest_path.is_file():
        die("build/catalogue.enc.parts.json is missing from the published repo")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_schema") != "egcat-parts-1":
        die("unsupported parts manifest schema")
    entries = sorted(manifest.get("parts") or [], key=lambda p: p["index"])
    if not entries:
        die("parts manifest lists no parts")
    if [p["index"] for p in entries] != list(range(len(entries))):
        die("parts manifest indices are not contiguous from 0")
    if len(entries) != int(manifest.get("part_count", -1)):
        die("parts manifest part_count does not match the list")

    overall = hashlib.sha256()
    written = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(".partial")
    try:
        with tmp.open("wb") as out:
            for entry in entries:
                part = build_dir / entry["name"]
                if not part.is_file():
                    die(f"missing ciphertext part: {entry['name']}")
                if part.stat().st_size != entry["size"]:
                    die(f"part {entry['name']} has the wrong size")
                digest = hashlib.sha256()
                with part.open("rb") as handle:
                    for block in iter(lambda: handle.read(1 << 20), b""):
                        digest.update(block)
                        overall.update(block)
                        out.write(block)
                        written += len(block)
                if digest.hexdigest() != entry["sha256"]:
                    die(f"part {entry['name']} failed its SHA-256 check", 79)
        if written != int(manifest["encrypted_size"]):
            die("reassembled size does not match the manifest", 79)
        if overall.hexdigest() != manifest["encrypted_sha256"]:
            die("reassembled ciphertext does not match the manifest SHA-256", 79)
        if pin and overall.hexdigest() != pin.strip().lower():
            die("reassembled ciphertext does not match CATALOGUE_ENC_SHA256", 79)
        with tmp.open("rb") as handle:
            if handle.read(6) != MAGIC:
                die("reassembled file is not an EGCAT1 sealed container", 79)
        with tmp.open("rb") as handle:
            if handle.read(15) == b"SQLite format 3":  # pragma: no cover - defensive
                die("refusing to stage a plaintext SQLite file", 79)
        os.replace(tmp, destination)
    finally:
        if tmp.exists():
            tmp.unlink()
    log(f"catalogue ciphertext assembled: {written} bytes, sha256 {overall.hexdigest()}")
    return {"size": written, "sha256": overall.hexdigest(), "part_count": len(entries)}


# ---------------------------------------------------------------------------
# dependency install + staging
# ---------------------------------------------------------------------------

def install_dependencies(source_root: Path, site_packages: Path) -> list[str]:
    requirement = next((source_root / name for name in REQUIREMENTS
                        if (source_root / name).is_file()), None)
    if requirement is None:
        die("no requirements file found in the published repo")
    site_packages.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pip", "install", "--no-cache-dir",
               "--no-warn-script-location", "--target", str(site_packages),
               "-r", str(requirement)]
    log(f"installing dependencies from {requirement.name}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout[-4000:] + result.stderr[-4000:])
        die("dependency installation failed", 80)
    return [requirement.name]


def stage(source_root: Path, runtime_root: Path) -> None:
    app_root = runtime_root / "app"
    if app_root.exists():
        shutil.rmtree(app_root)
    app_root.mkdir(parents=True)
    for name in STAGE_DIRS:
        source = source_root / name
        if not source.is_dir():
            die(f"published repo is missing {name}/")
        shutil.copytree(source, app_root / name)
    bin_dir = runtime_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, mode in (("catalogue_crypto.py", 0o644), ("registry-entrypoint.sh", 0o755)):
        source = source_root / "scripts" / name
        if not source.is_file():
            die(f"published repo is missing scripts/{name}")
        shutil.copy2(source, bin_dir / name)
        os.chmod(bin_dir / name, mode)


def can_chown() -> bool:
    """Only a root-run bootstrap can hand the tree to another uid."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def chown_tree(path: Path, uid: int, gid: int) -> None:
    if not can_chown():
        log(f"WARNING: not running as root; leaving ownership of {path} unchanged. "
            "In the compose deployment the bootstrap service runs as 0:0 so the "
            "runtime volume ends up owned by uid 10001.")
        return
    os.chown(path, uid, gid)
    for child in path.rglob("*"):
        try:
            os.chown(child, uid, gid, follow_symlinks=False)
        except (PermissionError, FileNotFoundError):  # pragma: no cover
            pass


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

    for secret in ("CATALOGUE_DECRYPTION_KEY", "SERVICE_TOKENS",
                   "EGORDIAN_PASSWORD", "EGORDIAN_BEARER_TOKEN"):
        if os.environ.get(secret):
            die(f"{secret} must not be provided to the bootstrap service; "
                "runtime secrets are runtime-only")

    runtime_root.mkdir(parents=True, exist_ok=True)
    if not os.access(runtime_root, os.W_OK):
        die(f"runtime volume {runtime_root} is not writable")

    stamp_path = runtime_root / STAMP_NAME
    catalogue_enc = runtime_root / "catalogue.enc"
    if catalogue_enc.exists():
        os.chmod(catalogue_enc, 0o644)
    wanted = {"repo": repo, "ref": ref, "enc_pin": enc_pin}
    if stamp_path.is_file() and not force:
        try:
            stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        except ValueError:
            stamp = {}
        same = all(stamp.get(k) == v for k, v in wanted.items())
        if same and catalogue_enc.is_file() and (runtime_root / "app" / "app").is_dir() \
                and (runtime_root / "site-packages").is_dir():
            log(f"already bootstrapped at {stamp.get('completed_at')} for ref {ref}; "
                "nothing to do")
            return 0
        log("stamp does not match the requested ref/state; re-bootstrapping")

    url = archive_url(repo, ref)
    if ref in ("main", "master", "HEAD"):
        log(f"WARNING: RUNTIME_REF={ref} is mutable; pin a commit SHA for reproducibility")

    with tempfile.TemporaryDirectory(prefix="egordian-bootstrap-") as work:
        workdir = Path(work)
        archive = workdir / "runtime.tar.gz"
        archive_sha = download(url, archive, archive_pin)
        source_root = safe_extract(archive, workdir / "src")

        catalogue = assemble_catalogue(source_root, catalogue_enc, enc_pin)
        os.chmod(catalogue_enc, 0o444)

        install_dependencies(source_root, runtime_root / "site-packages")
        stage(source_root, runtime_root)

    for target in (runtime_root / "app", runtime_root / "bin",
                   runtime_root / "site-packages"):
        chown_tree(target, uid, gid)
    if can_chown():
        os.chown(catalogue_enc, uid, gid)
    os.chmod(catalogue_enc, 0o444)

    stamp = {
        **wanted,
        "archive_url": url,
        "archive_sha256": archive_sha,
        "catalogue_encrypted_sha256": catalogue["sha256"],
        "catalogue_part_count": catalogue["part_count"],
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runtime_uid": uid,
        "python": sys.version.split()[0],
    }
    if stamp_path.exists():
        os.chmod(stamp_path, 0o644)
    stamp_path.write_text(json.dumps(stamp, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    if can_chown():
        os.chown(stamp_path, uid, gid)
    os.chmod(stamp_path, 0o444)
    log(f"bootstrap complete for {repo}@{ref}; runtime volume ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
