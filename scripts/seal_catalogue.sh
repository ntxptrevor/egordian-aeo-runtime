#!/usr/bin/env bash
# Build helper: seal the local plaintext catalogue into build/catalogue.enc.
#
# Runs on the operator's machine only. It streams the plaintext straight into
# an AES-256-GCM container and never creates an extra plaintext copy, never
# writes the key anywhere, and never echoes key material.
#
#   export CATALOGUE_DECRYPTION_KEY='<passphrase>'      # or hex:<64 hex chars>
#   ./scripts/seal_catalogue.sh                          # data/catalogue.sqlite
#   ./scripts/seal_catalogue.sh /path/to/catalogue.sqlite
#   ./scripts/seal_catalogue.sh --no-split               # single blob only
#
# Outputs (all ciphertext or hashes - safe to publish in the build repo):
#   build/catalogue.enc              ciphertext, mode 0444 (local/registry builds)
#   build/catalogue.enc.part-000...  deterministic parts <= 60 MiB (GitHub build)
#   build/catalogue.enc.parts.json   ordered part SHA-256 + overall encrypted SHA-256
#   build/catalogue.enc.meta.json    algorithm/size metadata + pinned plaintext hash
#   build/catalogue.sha256           the value to set as CATALOGUE_SHA256
#
# The sealed container is 120,205,858 bytes, above GitHub's 100 MiB single-file
# limit, so the public build repo must carry the parts, not the whole blob.
set -euo pipefail
set +x                      # never trace: the key lives in the environment
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SPLIT=1
case "${1:-}" in
  --no-split) SPLIT=0; shift ;;
esac
SOURCE="${1:-${ROOT_DIR}/data/catalogue.sqlite}"
PART_SIZE="${CATALOGUE_PART_SIZE:-62914560}"     # 60 MiB
BUILD_DIR="${ROOT_DIR}/build"
OUT="${BUILD_DIR}/catalogue.enc"
META="${BUILD_DIR}/catalogue.enc.meta.json"
PIN="${BUILD_DIR}/catalogue.sha256"
PYTHON_BIN="${PYTHON_BIN:-python3}"

die() { printf 'seal-catalogue: %s\n' "$1" >&2; exit "${2:-2}"; }

[ -f "${SOURCE}" ] || die "plaintext catalogue not found: ${SOURCE}"
[ -n "${CATALOGUE_DECRYPTION_KEY:-}" ] || die \
  "CATALOGUE_DECRYPTION_KEY is not set. Export it in this shell (prefix the
  command with a space so it stays out of shell history) and re-run." 78

if [ "${#CATALOGUE_DECRYPTION_KEY}" -lt 20 ] && \
   [ "${CATALOGUE_DECRYPTION_KEY#hex:}" = "${CATALOGUE_DECRYPTION_KEY}" ]; then
  die "passphrase is shorter than 20 characters; use a long passphrase or hex:<64 hex>" 78
fi

"${PYTHON_BIN}" - <<'PY' || die "the 'cryptography' package is required (pip install -r requirements-registry.txt)"
import sys
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
except Exception:
    sys.exit(1)
PY

mkdir -p "${BUILD_DIR}"

# Previous outputs are 0444 by design; clear them so re-sealing is idempotent.
for stale in "${OUT}" "${META}" "${PIN}" "${BUILD_DIR}"/catalogue.enc.part-* \
             "${BUILD_DIR}/catalogue.enc.parts.json"; do
  [ -e "${stale}" ] && { chmod u+w "${stale}" 2>/dev/null || true; rm -f "${stale}"; }
done

printf 'seal-catalogue: sealing %s -> %s\n' "${SOURCE}" "${OUT}" >&2

# The Python helper streams source -> ciphertext via a single 0600 temp file in
# build/ that is renamed into place; no plaintext copy is ever produced.
"${PYTHON_BIN}" "${SCRIPT_DIR}/catalogue_crypto.py" encrypt \
  --in "${SOURCE}" --out "${OUT}" --key-env CATALOGUE_DECRYPTION_KEY > "${META}"

chmod 0444 "${OUT}"
chmod 0444 "${META}"
"${PYTHON_BIN}" - "$META" "$PIN" <<'PY'
import json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_text(meta["plain_sha256"] + "\n")
PY
chmod 0444 "${PIN}"

ENC_SHA="$(sha256sum "${OUT}" | cut -d' ' -f1)"

PARTS_NOTE="(skipped: --no-split)"
if [ "${SPLIT}" -eq 1 ]; then
  printf 'seal-catalogue: splitting ciphertext into <=%s byte parts\n' "${PART_SIZE}" >&2
  "${PYTHON_BIN}" "${SCRIPT_DIR}/catalogue_crypto.py" split \
    --in "${OUT}" --out-dir "${BUILD_DIR}" --part-size "${PART_SIZE}" >/dev/null
  PARTS_NOTE="$(ls -1 "${BUILD_DIR}"/catalogue.enc.part-* | wc -l) part(s), manifest ${BUILD_DIR}/catalogue.enc.parts.json"
  # Fail loudly if any part would be rejected by GitHub.
  for part in "${BUILD_DIR}"/catalogue.enc.part-*; do
    size="$(stat -c%s "${part}")"
    [ "${size}" -le 104857600 ] || die "part ${part} is ${size} bytes, above GitHub's 100 MiB limit"
  done
fi

cat >&2 <<EOF

seal-catalogue: done.
  ciphertext          ${OUT} ($(stat -c%s "${OUT}") bytes)
  ciphertext sha256   ${ENC_SHA}
  parts               ${PARTS_NOTE}
  CATALOGUE_SHA256    $(cat "${PIN}")

Next (registry build, single blob):
  DOCKER_BUILDKIT=1 docker build -f Dockerfile.registry -t \$EGORDIAN_IMAGE .
  docker push \$EGORDIAN_IMAGE

Next (public GitHub build, parts - no registry credentials needed):
  git -C <build-repo> add build/catalogue.enc.part-* build/catalogue.enc.parts.json
  docker compose -f docker-compose.hostinger-build.yml --env-file ./egordian.env up -d --build

Never commit the key. Set CATALOGUE_DECRYPTION_KEY and CATALOGUE_SHA256 on the
host only (compose env file with mode 0600).
EOF
