#!/usr/bin/env python3
"""Authenticated encryption for the licensed catalogue database.

Container/registry layers must never contain the plaintext catalogue. This
module produces and consumes ``build/catalogue.enc``: a streamed,
**AES-256-GCM** container (format ``EGCAT1``) whose every chunk is
authenticated and bound to its position, so truncation, reordering, or
splicing is detected.

Format ``EGCAT1`` (all integers big-endian)::

    header (82 bytes, authenticated as AAD on every chunk)
      0  magic         6   b"EGCAT1"
      6  version       1   0x01
      7  alg           1   0x01 = AES-256-GCM, chunked
      8  kdf           1   0x00 = raw 32-byte key, 0x01 = PBKDF2-HMAC-SHA256
      9  reserved      1   0x00
     10  iterations    4   PBKDF2 iterations (0 when kdf = 0)
     14  salt         16   PBKDF2 salt (zero-filled when kdf = 0)
     30  nonce_base    8   per-chunk nonce = nonce_base || chunk_index(4)
     38  chunk_size    4   plaintext bytes per chunk
     42  plain_size    8   total plaintext length
     50  plain_sha256 32   SHA-256 of the plaintext (pinned, authenticated)
    body
      repeat: ciphertext(<= chunk_size) || GCM tag(16)
      AAD per chunk = header || chunk_index(4) || final_flag(1)

Key material comes from ``CATALOGUE_DECRYPTION_KEY`` (or ``--key-env``) and is
never accepted on the command line, never echoed, and never written to a log.
A value of the form ``hex:<64 hex chars>`` is used as a raw 32-byte key;
anything else is treated as a passphrase and stretched with PBKDF2-HMAC-SHA256.

An alternative OpenSSL AES-256-CBC + PBKDF2 + separate HMAC-SHA256
(encrypt-then-MAC) path is documented in ``docs/REGISTRY_DEPLOY.md`` for hosts
that refuse the ``cryptography`` wheel; it is *not* the default because CBC has
no built-in authentication and needs a second full-file pass.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

MAGIC = b"EGCAT1"
VERSION = 1
ALG_AES_256_GCM = 1
KDF_NONE = 0
KDF_PBKDF2_SHA256 = 1
HEADER_LEN = 82
TAG_LEN = 16
DEFAULT_CHUNK = 4 * 1024 * 1024
DEFAULT_ITERATIONS = 600_000
KEY_ENV_DEFAULT = "CATALOGUE_DECRYPTION_KEY"

# GitHub rejects single files above 100 MiB (and warns above 50 MiB), so the
# sealed container is shipped to the public build repo as deterministic parts.
DEFAULT_PART_SIZE = 60 * 1024 * 1024
PARTS_MANIFEST_NAME = "catalogue.enc.parts.json"
PARTS_MANIFEST_SCHEMA = "egcat-parts-1"
GITHUB_FILE_LIMIT = 100 * 1024 * 1024


class CatalogueCryptoError(RuntimeError):
    """Raised for any failure. Messages never contain key material."""


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - dependency is pinned in the image
        raise CatalogueCryptoError(
            "The 'cryptography' package is required for AES-256-GCM. Install "
            "requirements-registry.txt, or rebuild the blob with the documented "
            "OpenSSL AES-256-CBC + HMAC fallback."
        ) from exc
    return AESGCM


def read_key_material(env_name: str = KEY_ENV_DEFAULT) -> str:
    value = os.environ.get(env_name, "")
    if not value or not value.strip():
        raise CatalogueCryptoError(
            f"{env_name} is not set. The catalogue cannot be decrypted and the "
            "service must not start."
        )
    return value.strip()


def derive_key(material: str, salt: bytes, iterations: int) -> tuple[bytes, int, int, bytes]:
    """Return (key, kdf_id, iterations, salt). Raw keys skip the KDF."""
    if material.startswith("hex:"):
        raw = material[4:].strip()
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise CatalogueCryptoError("hex: key material is not valid hex.") from exc
        if len(key) != 32:
            raise CatalogueCryptoError("hex: key material must decode to exactly 32 bytes.")
        return key, KDF_NONE, 0, b"\x00" * 16
    key = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"), salt, iterations, dklen=32)
    return key, KDF_PBKDF2_SHA256, iterations, salt


def _pack_header(*, kdf: int, iterations: int, salt: bytes, nonce_base: bytes,
                 chunk_size: int, plain_size: int, plain_sha256: bytes) -> bytes:
    header = (
        MAGIC
        + bytes([VERSION, ALG_AES_256_GCM, kdf, 0])
        + struct.pack(">I", iterations)
        + salt
        + nonce_base
        + struct.pack(">I", chunk_size)
        + struct.pack(">Q", plain_size)
        + plain_sha256
    )
    assert len(header) == HEADER_LEN, len(header)
    return header


def parse_header(header: bytes) -> dict:
    if len(header) != HEADER_LEN or header[:6] != MAGIC:
        raise CatalogueCryptoError("Encrypted catalogue header is missing or malformed.")
    version, alg, kdf, _reserved = header[6], header[7], header[8], header[9]
    if version != VERSION:
        raise CatalogueCryptoError(f"Unsupported container version {version}.")
    if alg != ALG_AES_256_GCM:
        raise CatalogueCryptoError(f"Unsupported algorithm id {alg}.")
    if kdf not in (KDF_NONE, KDF_PBKDF2_SHA256):
        raise CatalogueCryptoError(f"Unsupported KDF id {kdf}.")
    return {
        "version": version,
        "alg": alg,
        "kdf": kdf,
        "iterations": struct.unpack(">I", header[10:14])[0],
        "salt": header[14:30],
        "nonce_base": header[30:38],
        "chunk_size": struct.unpack(">I", header[38:42])[0],
        "plain_size": struct.unpack(">Q", header[42:50])[0],
        "plain_sha256": header[50:82],
    }


def _nonce(nonce_base: bytes, index: int) -> bytes:
    return nonce_base + struct.pack(">I", index)


def _aad(header: bytes, index: int, final: bool) -> bytes:
    return header + struct.pack(">I", index) + (b"\x01" if final else b"\x00")


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

def encrypt_file(source: Path, destination: Path, material: str, *,
                 chunk_size: int = DEFAULT_CHUNK,
                 iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Stream-encrypt ``source`` into ``destination``.

    Only two files ever exist: the caller's original plaintext and the
    encrypted output. No temporary plaintext copy is created.
    """
    if not source.is_file():
        raise CatalogueCryptoError(f"Plaintext catalogue not found: {source}")
    AESGCM = _aesgcm()

    plain_size = source.stat().st_size
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    plain_sha256 = digest.digest()

    salt = secrets.token_bytes(16)
    key, kdf, iterations_used, salt = derive_key(material, salt, iterations)
    nonce_base = secrets.token_bytes(8)
    header = _pack_header(kdf=kdf, iterations=iterations_used, salt=salt,
                          nonce_base=nonce_base, chunk_size=chunk_size,
                          plain_size=plain_size, plain_sha256=plain_sha256)
    aead = AESGCM(key)

    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(destination.parent),
                                        prefix=".catalogue.enc.")
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)
    try:
        os.chmod(tmp_path, 0o600)
        written = 0
        with source.open("rb") as src, tmp_path.open("wb") as out:
            out.write(header)
            index = 0
            pending = src.read(chunk_size)
            while True:
                nxt = src.read(chunk_size)
                final = not nxt
                out.write(aead.encrypt(_nonce(nonce_base, index),
                                       pending, _aad(header, index, final)))
                written += len(pending)
                index += 1
                if final:
                    break
                pending = nxt
            if plain_size == 0:  # pragma: no cover - defensive
                out.write(aead.encrypt(_nonce(nonce_base, 0), b"", _aad(header, 0, True)))
        os.chmod(tmp_path, 0o444)
        os.replace(tmp_path, destination)
    finally:
        if tmp_path.exists():  # pragma: no cover - only on failure
            tmp_path.unlink(missing_ok=True)
    del key, material
    return {
        "encrypted_path": str(destination),
        "encrypted_size": destination.stat().st_size,
        "plain_size": plain_size,
        "plain_sha256": plain_sha256.hex(),
        "chunk_size": chunk_size,
        "kdf": "pbkdf2-hmac-sha256" if kdf == KDF_PBKDF2_SHA256 else "raw-key",
        "iterations": iterations_used,
        "alg": "aes-256-gcm-chunked",
        "format": "EGCAT1",
    }


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

def decrypt_file(source: Path, destination: Path, material: str, *,
                 expected_sha256: str | None = None,
                 mode: int = 0o444) -> dict:
    """Stream-decrypt into ``destination`` and verify both pinned hashes.

    On any failure the partially written output is removed, so a service can
    never come up on a half-decrypted or unauthenticated catalogue.
    """
    if not source.is_file():
        raise CatalogueCryptoError(f"Encrypted catalogue not found: {source}")
    AESGCM = _aesgcm()

    with source.open("rb") as handle:
        header = handle.read(HEADER_LEN)
        meta = parse_header(header)
        key, _kdf, _iters, _salt = derive_key(material, meta["salt"], meta["iterations"])
        if meta["kdf"] == KDF_NONE and not material.startswith("hex:"):
            raise CatalogueCryptoError(
                "This container was sealed with a raw key; supply hex:<64 hex chars>.")
        if meta["kdf"] == KDF_PBKDF2_SHA256 and material.startswith("hex:"):
            raise CatalogueCryptoError(
                "This container was sealed with a passphrase; supply the passphrase.")
        aead = AESGCM(key)

        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(destination.parent),
                                            prefix=".catalogue.part.")
        os.close(tmp_fd)
        tmp_path = Path(tmp_name)
        digest = hashlib.sha256()
        total = 0
        try:
            os.chmod(tmp_path, 0o600)
            with tmp_path.open("wb") as out:
                index = 0
                blob = handle.read(meta["chunk_size"] + TAG_LEN)
                if not blob:
                    raise CatalogueCryptoError("Encrypted catalogue contains no chunks.")
                while True:
                    nxt = handle.read(meta["chunk_size"] + TAG_LEN)
                    final = not nxt
                    try:
                        plain = aead.decrypt(_nonce(meta["nonce_base"], index), blob,
                                             _aad(header, index, final))
                    except Exception as exc:  # InvalidTag and friends
                        raise CatalogueCryptoError(
                            "Authenticated decryption failed: wrong "
                            "CATALOGUE_DECRYPTION_KEY or the encrypted catalogue has "
                            f"been altered (chunk {index})."
                        ) from None
                    out.write(plain)
                    digest.update(plain)
                    total += len(plain)
                    index += 1
                    if final:
                        break
                    blob = nxt
            if total != meta["plain_size"]:
                raise CatalogueCryptoError(
                    f"Decrypted size {total} does not match the sealed size "
                    f"{meta['plain_size']}.")
            actual = digest.digest()
            if not hmac.compare_digest(actual, meta["plain_sha256"]):
                raise CatalogueCryptoError(
                    "Decrypted catalogue does not match the SHA-256 sealed in the "
                    "container header.")
            if expected_sha256:
                pinned = expected_sha256.strip().lower()
                if not hmac.compare_digest(actual.hex(), pinned):
                    raise CatalogueCryptoError(
                        "Decrypted catalogue does not match the pinned "
                        f"CATALOGUE_SHA256 (expected {pinned[:16]}…, got "
                        f"{actual.hex()[:16]}…).")
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, destination)
            tmp_path = None  # type: ignore[assignment]
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
        del key, material
    return {
        "path": str(destination),
        "size": total,
        "sha256": actual.hex(),
        "mode": oct(mode),
        "alg": "aes-256-gcm-chunked",
        "verified": ["container-header-sha256"] + (["pinned-sha256"] if expected_sha256 else []),
    }


# ---------------------------------------------------------------------------
# deterministic split / join (no key required - ciphertext only)
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def part_name(index: int) -> str:
    return f"catalogue.enc.part-{index:03d}"


def split_blob(source: Path, out_dir: Path, *,
               part_size: int = DEFAULT_PART_SIZE) -> dict:
    """Split the sealed container into deterministic, hash-pinned parts.

    Pure byte slicing of ciphertext: no key is needed, no plaintext is touched,
    and the same input always yields byte-identical parts and manifest.
    """
    if not source.is_file():
        raise CatalogueCryptoError(f"Sealed catalogue not found: {source}")
    if part_size <= 0 or part_size > GITHUB_FILE_LIMIT:
        raise CatalogueCryptoError(
            f"part size must be between 1 and {GITHUB_FILE_LIMIT} bytes")
    with source.open("rb") as handle:
        if handle.read(6) != MAGIC:
            raise CatalogueCryptoError(
                "Refusing to split: input is not an EGCAT1 sealed container.")

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in sorted(out_dir.glob("catalogue.enc.part-*")):
        stale.unlink()

    parts: list[dict] = []
    total = 0
    with source.open("rb") as handle:
        index = 0
        while True:
            block = handle.read(part_size)
            if not block and index > 0:
                break
            target = out_dir / part_name(index)
            target.write_bytes(block)
            os.chmod(target, 0o444)
            parts.append({"name": target.name, "index": index,
                          "size": len(block), "sha256": _sha256_file(target)})
            total += len(block)
            index += 1
            if len(block) < part_size:
                break

    manifest = {
        "manifest_schema": PARTS_MANIFEST_SCHEMA,
        "container_format": "EGCAT1",
        "encrypted_sha256": _sha256_file(source),
        "encrypted_size": total,
        "part_size_bytes": part_size,
        "part_count": len(parts),
        "parts": parts,
        "reassemble": "cat catalogue.enc.part-* > catalogue.enc  # ascending index order",
    }
    manifest_path = out_dir / PARTS_MANIFEST_NAME
    import json as _json
    manifest_path.write_text(_json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    os.chmod(manifest_path, 0o444)
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def join_parts(manifest_path: Path, destination: Path, *,
               parts_dir: Path | None = None,
               expected_sha256: str | None = None) -> dict:
    """Verify every part, concatenate in order, verify the whole.

    Any missing part, wrong size, wrong per-part hash, wrong overall hash, or
    wrong magic aborts and removes the partial output.
    """
    import json as _json
    if not manifest_path.is_file():
        raise CatalogueCryptoError(f"Parts manifest not found: {manifest_path}")
    manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_schema") != PARTS_MANIFEST_SCHEMA:
        raise CatalogueCryptoError("Unsupported parts manifest schema.")
    directory = parts_dir or manifest_path.parent
    entries = sorted(manifest.get("parts") or [], key=lambda p: p["index"])
    if not entries:
        raise CatalogueCryptoError("Parts manifest lists no parts.")
    if [p["index"] for p in entries] != list(range(len(entries))):
        raise CatalogueCryptoError("Parts manifest indices are not contiguous from 0.")
    if len(entries) != int(manifest.get("part_count", -1)):
        raise CatalogueCryptoError("Parts manifest part_count does not match the list.")

    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(destination.parent),
                                        prefix=".catalogue.join.")
    os.close(tmp_fd)
    tmp_path: Path | None = Path(tmp_name)
    overall = hashlib.sha256()
    written = 0
    try:
        os.chmod(tmp_path, 0o600)
        with tmp_path.open("wb") as out:
            for entry in entries:
                part = directory / entry["name"]
                if not part.is_file():
                    raise CatalogueCryptoError(f"Missing part: {entry['name']}")
                if part.stat().st_size != entry["size"]:
                    raise CatalogueCryptoError(
                        f"Part {entry['name']} has size {part.stat().st_size}, "
                        f"expected {entry['size']}.")
                digest = hashlib.sha256()
                with part.open("rb") as handle:
                    for block in iter(lambda: handle.read(1 << 20), b""):
                        digest.update(block)
                        overall.update(block)
                        out.write(block)
                        written += len(block)
                if not hmac.compare_digest(digest.hexdigest(), entry["sha256"]):
                    raise CatalogueCryptoError(
                        f"Part {entry['name']} failed its SHA-256 check.")
        if written != int(manifest["encrypted_size"]):
            raise CatalogueCryptoError(
                f"Reassembled size {written} does not match the manifest "
                f"({manifest['encrypted_size']}).")
        if not hmac.compare_digest(overall.hexdigest(), manifest["encrypted_sha256"]):
            raise CatalogueCryptoError(
                "Reassembled container does not match the manifest encrypted_sha256.")
        if expected_sha256 and not hmac.compare_digest(
                overall.hexdigest(), expected_sha256.strip().lower()):
            raise CatalogueCryptoError(
                "Reassembled container does not match the externally pinned "
                "encrypted SHA-256.")
        with tmp_path.open("rb") as handle:
            if handle.read(6) != MAGIC:
                raise CatalogueCryptoError(
                    "Reassembled file is not an EGCAT1 container.")
        os.chmod(tmp_path, 0o444)
        os.replace(tmp_path, destination)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return {
        "path": str(destination),
        "size": written,
        "encrypted_sha256": overall.hexdigest(),
        "part_count": len(entries),
        "magic": "EGCAT1",
        "verified": ["per-part-sha256", "manifest-encrypted-sha256", "magic"]
                    + (["pinned-encrypted-sha256"] if expected_sha256 else []),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fail(message: str) -> int:
    print(f"catalogue-crypto: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="catalogue_crypto",
        description="Seal/unseal the licensed catalogue with AES-256-GCM. "
                    "Key material is read from an environment variable only.")
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("encrypt", help="seal a plaintext catalogue")
    seal.add_argument("--in", dest="source", required=True)
    seal.add_argument("--out", dest="destination", required=True)
    seal.add_argument("--key-env", default=KEY_ENV_DEFAULT)
    seal.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)
    seal.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)

    unseal = sub.add_parser("decrypt", help="unseal into a runtime directory")
    unseal.add_argument("--in", dest="source", required=True)
    unseal.add_argument("--out", dest="destination", required=True)
    unseal.add_argument("--key-env", default=KEY_ENV_DEFAULT)
    unseal.add_argument("--expect-sha256", default=os.environ.get("CATALOGUE_SHA256", ""))
    unseal.add_argument("--mode", default="0444")

    info = sub.add_parser("info", help="print container metadata (no key needed)")
    info.add_argument("--in", dest="source", required=True)

    split = sub.add_parser("split", help="split a sealed container into hash-pinned parts")
    split.add_argument("--in", dest="source", required=True)
    split.add_argument("--out-dir", dest="out_dir", required=True)
    split.add_argument("--part-size", type=int, default=DEFAULT_PART_SIZE)

    join = sub.add_parser("join", help="verify and reassemble parts (no key needed)")
    join.add_argument("--manifest", required=True)
    join.add_argument("--out", dest="destination", required=True)
    join.add_argument("--parts-dir", default="")
    join.add_argument("--expect-sha256", default="")

    args = parser.parse_args(argv)
    try:
        if args.command == "info":
            with open(args.source, "rb") as handle:
                meta = parse_header(handle.read(HEADER_LEN))
            meta["salt"] = meta["salt"].hex()
            meta["nonce_base"] = meta["nonce_base"].hex()
            meta["plain_sha256"] = meta["plain_sha256"].hex()
            import json
            print(json.dumps(meta, indent=2, sort_keys=True))
            return 0

        if args.command == "split":
            import json
            print(json.dumps(split_blob(Path(args.source), Path(args.out_dir),
                                        part_size=args.part_size),
                             indent=2, sort_keys=True))
            return 0

        if args.command == "join":
            import json
            print(json.dumps(join_parts(
                Path(args.manifest), Path(args.destination),
                parts_dir=Path(args.parts_dir) if args.parts_dir else None,
                expected_sha256=args.expect_sha256 or None), indent=2, sort_keys=True))
            return 0

        material = read_key_material(args.key_env)
        if args.command == "encrypt":
            result = encrypt_file(Path(args.source), Path(args.destination), material,
                                  chunk_size=args.chunk_size, iterations=args.iterations)
        else:
            result = decrypt_file(Path(args.source), Path(args.destination), material,
                                  expected_sha256=args.expect_sha256 or None,
                                  mode=int(args.mode, 8))
        import json
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except CatalogueCryptoError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
