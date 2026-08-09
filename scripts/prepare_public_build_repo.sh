#!/usr/bin/env bash
# Stage the exact file set for the public encrypted-source build repo
# (default: ntxptrevor/egordian-aeo-runtime), then leak-scan it before you push.
#
#   ./scripts/seal_catalogue.sh                     # produces parts + manifest
#   ./scripts/prepare_public_build_repo.sh /tmp/egordian-aeo-runtime
#
# What ships: application source, the AES-256-GCM ciphertext parts and their
# manifest, the Dockerfile/compose/entrypoint. What never ships: data/, the
# plaintext catalogue, data.db, dist/, run_manifest.json, env files, any key.
set -euo pipefail
set +x
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TARGET="${1:-/tmp/egordian-aeo-runtime}"
BUILD_DIR="${ROOT_DIR}/build"

die() { printf 'prepare-public-repo: %s\n' "$1" >&2; exit "${2:-2}"; }

[ -f "${BUILD_DIR}/catalogue.enc.parts.json" ] || die \
  "build/catalogue.enc.parts.json is missing - run ./scripts/seal_catalogue.sh first" 78
compgen -G "${BUILD_DIR}/catalogue.enc.part-*" >/dev/null || die \
  "no build/catalogue.enc.part-* files - run ./scripts/seal_catalogue.sh first" 78

mkdir -p "${TARGET}"
rm -rf "${TARGET:?}/app" "${TARGET:?}/gordian_ctc" "${TARGET:?}/profiles" \
       "${TARGET:?}/schemas" "${TARGET:?}/console" "${TARGET:?}/fixtures" \
       "${TARGET:?}/vendor_docs" "${TARGET:?}/scripts" "${TARGET:?}/docs" \
       "${TARGET:?}/build"

for item in app gordian_ctc profiles schemas console fixtures vendor_docs scripts docs; do
  cp -R "${ROOT_DIR}/${item}" "${TARGET}/${item}"
done
for item in Dockerfile.registry Dockerfile.registry.dockerignore .dockerignore \
            docker-compose.hostinger.yml docker-compose.hostinger-build.yml \
            docker-compose.hostinger-bootstrap.yml \
            requirements.txt requirements-postgres.txt requirements-registry.txt \
            env.example egordian.env.example LICENSE README.md; do
  cp "${ROOT_DIR}/${item}" "${TARGET}/${item}"
done

mkdir -p "${TARGET}/build"
cp "${BUILD_DIR}"/catalogue.enc.part-* "${TARGET}/build/"
cp "${BUILD_DIR}/catalogue.enc.parts.json" "${TARGET}/build/"
chmod 0644 "${TARGET}"/build/catalogue.enc.part-* "${TARGET}/build/catalogue.enc.parts.json"

# Strip anything that must never be published.
find "${TARGET}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "${TARGET}"/build/catalogue.enc "${TARGET}"/build/catalogue.sha256 \
      "${TARGET}"/build/catalogue.enc.meta.json "${TARGET}"/egordian.env

# --- leak scan --------------------------------------------------------------
fail=0
while IFS= read -r -d '' file; do
  case "${file}" in *.png|*.jpg|*.ico|*.woff|*.woff2) continue ;; esac
  if [ "$(head -c 15 "${file}" 2>/dev/null)" = "SQLite format 3" ]; then
    printf 'LEAK: sqlite payload %s\n' "${file}" >&2; fail=1
  fi
  case "${file}" in
    *.sqlite|*.sqlite3|*.db|*.pdf|*.csv|*.xlsx)
      printf 'LEAK: forbidden artefact %s\n' "${file}" >&2; fail=1 ;;
  esac
done < <(find "${TARGET}" -path "${TARGET}/.git" -prune -o -type f -print0)

for part in "${TARGET}"/build/catalogue.enc.part-*; do
  size="$(stat -c%s "${part}")"
  [ "${size}" -le 104857600 ] || { printf 'LEAK/LIMIT: %s is %s bytes (>100 MiB)\n' \
      "${part}" "${size}" >&2; fail=1; }
  [ "$(head -c 15 "${part}")" != "SQLite format 3" ] || fail=1
done
[ "${fail}" -eq 0 ] || die "leak scan failed - nothing was pushed" 79

PARTS="$(ls -1 "${TARGET}"/build/catalogue.enc.part-* | wc -l)"
cat >&2 <<EOF

prepare-public-repo: staged ${TARGET}
  ciphertext parts    ${PARTS} (all <= 100 MiB, leak scan clean)
  plaintext catalogue absent
  keys / env files    absent

Publish:
  cd ${TARGET}
  git init -b main && git add -A
  git commit -m "eGordian AEO runtime: encrypted catalogue parts + registry build"
  git remote add origin https://github.com/ntxptrevor/egordian-aeo-runtime.git
  git push -u origin main

Note the pushed commit SHA and set RUNTIME_REF to it in ./egordian.env.

Then on the VPS (stock images only - no build, no registry):
  docker compose -f docker-compose.hostinger-bootstrap.yml --env-file ./egordian.env up -d
EOF
