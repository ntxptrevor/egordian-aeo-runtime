#!/bin/sh
# Registry-variant container entrypoint.
#
# The image layers contain only the AES-256-GCM sealed catalogue. At start-up
# this script:
#   1. refuses to run without CATALOGUE_DECRYPTION_KEY and CATALOGUE_SHA256;
#   2. decrypts the sealed blob into a private runtime directory
#      (a named volume or tmpfs mounted at /run/egordian) with mode 0444;
#   3. verifies the pinned SHA-256 (twice: the hash sealed inside the
#      authenticated header, and the externally pinned CATALOGUE_SHA256);
#   4. drops the key from the environment and execs the FastAPI service.
#
# Key material is never echoed, never traced, never passed as an argv value,
# and never written to disk. Any failure exits non-zero *before* the service
# starts - the service never runs on an unverified catalogue.
set -eu
set +x                       # never enable tracing: the key is in the env
umask 077

log() { printf '%s registry-entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >&2; }
die() { log "FATAL: $1"; exit "${2:-78}"; }

ENC_PATH="${CATALOGUE_ENC_PATH:-/opt/egordian/catalogue.enc}"
# Location of the decryptor and of the application tree. Defaults match the
# custom image; the stock-image bootstrap deployment overrides them to point at
# the prepared runtime volume.
CRYPTO_PATH="${CATALOGUE_CRYPTO_PATH:-/opt/egordian/catalogue_crypto.py}"
APP_ROOT="${APP_ROOT:-/app}"
RUNTIME_DIR="${CATALOGUE_RUNTIME_DIR:-/run/egordian}"
CATALOGUE_DB_PATH="${CATALOGUE_DB_PATH:-${RUNTIME_DIR}/catalogue.sqlite}"
OVERLAY_DB_PATH="${OVERLAY_DB_PATH:-/var/lib/egordian/data.db}"
export CATALOGUE_DB_PATH OVERLAY_DB_PATH

# --- 1. mandatory secrets ---------------------------------------------------
# Support *_FILE indirection (docker/compose secrets) without ever printing.
if [ -n "${CATALOGUE_DECRYPTION_KEY_FILE:-}" ]; then
    [ -r "${CATALOGUE_DECRYPTION_KEY_FILE}" ] || \
        die "CATALOGUE_DECRYPTION_KEY_FILE is not readable"
    CATALOGUE_DECRYPTION_KEY="$(cat "${CATALOGUE_DECRYPTION_KEY_FILE}")"
    export CATALOGUE_DECRYPTION_KEY
fi

[ -n "${CATALOGUE_DECRYPTION_KEY:-}" ] || die \
    "CATALOGUE_DECRYPTION_KEY is not set; refusing to start without the catalogue key"
[ -n "${CATALOGUE_SHA256:-}" ] || die \
    "CATALOGUE_SHA256 (pinned plaintext hash) is not set; refusing to start unpinned"

case "${CATALOGUE_SHA256}" in
    [0-9a-f][0-9a-f]*) ;;
    *) die "CATALOGUE_SHA256 must be lowercase hex" ;;
esac
[ "$(printf '%s' "${CATALOGUE_SHA256}" | wc -c)" -eq 64 ] || \
    die "CATALOGUE_SHA256 must be exactly 64 hex characters"

[ -f "${ENC_PATH}" ] || die "sealed catalogue missing from the image: ${ENC_PATH}"
[ -f "${CRYPTO_PATH}" ] || die "decryptor missing: ${CRYPTO_PATH} (set CATALOGUE_CRYPTO_PATH)"
[ -d "${APP_ROOT}" ] || die "application root missing: ${APP_ROOT} (set APP_ROOT)"

# --- 2. runtime directory ---------------------------------------------------
mkdir -p "${RUNTIME_DIR}" 2>/dev/null || true
[ -d "${RUNTIME_DIR}" ] || die "runtime directory ${RUNTIME_DIR} does not exist"
[ -w "${RUNTIME_DIR}" ] || die "runtime directory ${RUNTIME_DIR} is not writable"

# --- 3. decrypt (idempotent across restarts) --------------------------------
reuse=0
if [ -f "${CATALOGUE_DB_PATH}" ]; then
    existing="$(sha256sum "${CATALOGUE_DB_PATH}" | cut -d' ' -f1)"
    if [ "${existing}" = "${CATALOGUE_SHA256}" ]; then
        log "catalogue already present and matches the pinned hash; reusing"
        reuse=1
    else
        log "existing catalogue does not match the pinned hash; re-decrypting"
        rm -f "${CATALOGUE_DB_PATH}"
    fi
fi

if [ "${reuse}" -eq 0 ]; then
    log "decrypting sealed catalogue (aes-256-gcm) into ${CATALOGUE_DB_PATH}"
    # Key is read from the environment by the decryptor; it is never an argv
    # value, so it cannot appear in /proc/<pid>/cmdline or in `ps` output.
    if ! python3 "${CRYPTO_PATH}" decrypt \
            --in "${ENC_PATH}" \
            --out "${CATALOGUE_DB_PATH}" \
            --key-env CATALOGUE_DECRYPTION_KEY \
            --expect-sha256 "${CATALOGUE_SHA256}" \
            --mode 0444 >/dev/null; then
        rm -f "${CATALOGUE_DB_PATH}"
        die "catalogue decryption or verification failed (wrong key, wrong pinned hash, or tampered blob)" 79
    fi
fi

# --- 4. post-conditions -----------------------------------------------------
chmod 0444 "${CATALOGUE_DB_PATH}" 2>/dev/null || true
final="$(sha256sum "${CATALOGUE_DB_PATH}" | cut -d' ' -f1)"
[ "${final}" = "${CATALOGUE_SHA256}" ] || {
    rm -f "${CATALOGUE_DB_PATH}"
    die "post-decryption hash mismatch" 79
}
perms="$(stat -c '%a' "${CATALOGUE_DB_PATH}")"
[ "${perms}" = "444" ] || die "catalogue mode is ${perms}, expected 444" 79
log "catalogue verified: sha256 ${CATALOGUE_SHA256} mode ${perms}"

mkdir -p "$(dirname "${OVERLAY_DB_PATH}")" 2>/dev/null || true

# --- 5. drop the key and hand off ------------------------------------------
unset CATALOGUE_DECRYPTION_KEY CATALOGUE_DECRYPTION_KEY_FILE

# Verification-only mode used by tests/test_registry_deployment.py. It runs the
# identical key/hash/permission path and stops immediately before exec, so the
# failure modes can be proven without starting the service or a container.
if [ "${ENTRYPOINT_DRY_RUN:-0}" = "1" ]; then
    log "dry run: catalogue verified, key dropped, service not started"
    exit 0
fi

# PYTHONPATH lets the runtime import dependencies installed by the bootstrap
# service into a read-only volume, without any custom image.
if [ -n "${RUNTIME_SITE_PACKAGES:-}" ]; then
    PYTHONPATH="${RUNTIME_SITE_PACKAGES}${PYTHONPATH:+:${PYTHONPATH}}"
fi
PYTHONPATH="${APP_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONPATH
cd "${APP_ROOT}" || die "cannot enter APP_ROOT ${APP_ROOT}"

log "starting service on ${HOST:-0.0.0.0}:${PORT:-8080} (key dropped from environment)"

exec python3 -c '
import os, sys
# Defence in depth: the application process must never see the key.
for name in ("CATALOGUE_DECRYPTION_KEY", "CATALOGUE_DECRYPTION_KEY_FILE"):
    os.environ.pop(name, None)
import uvicorn
uvicorn.run("app.main:app", host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "8080")),
            workers=int(os.environ.get("WEB_CONCURRENCY", "2")),
            proxy_headers=True, server_header=False, access_log=True)
'
