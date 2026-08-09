# Registry-safe deployment (no SSH upload)

When the licensed catalogue cannot be uploaded to the host over SSH, the image has to
travel through a container registry. **No registry layer may ever contain the plaintext
catalogue.** This variant seals the catalogue with AES-256-GCM before the build, ships only
the ciphertext, and materialises the plaintext at start-up into a private volume — and only
when the operator supplies the decryption key *and* the pinned SHA-256.

| Artefact | Purpose |
|---|---|
| `scripts/catalogue_crypto.py` | AES-256-GCM streaming seal/unseal (format `EGCAT1`) |
| `scripts/seal_catalogue.sh` | Build helper: plaintext DB → `build/catalogue.enc` |
| `scripts/registry-entrypoint.sh` | Start-up: require key + hash → decrypt → verify → exec |
| `Dockerfile.registry` | Multi-stage image: assembles ciphertext parts, ships blob only |
| `Dockerfile.registry.dockerignore` | Keeps `data/`, `*.sqlite`, `*.pdf` out of the context |
| `requirements-registry.txt` | Base requirements + `cryptography` |
| `docker-compose.hostinger.yml` | Traefik ingress, hardened runtime, named volumes |
| `docker-compose.hostinger-build.yml` | Same runtime, built from the public repo (needs a runner that builds git contexts) |
| `docker-compose.hostinger-single.yml` | **ONE service, stock image, narrow-parser safe (use this on Hostinger)** |
| `scripts/launch_runtime.py` | Pinned public launcher: stage, lock down, drop privileges, exec |
| `docker-compose.hostinger-bootstrap.yml` | Two-service stock-image variant (rejected by Hostinger's parser) |
| `scripts/bootstrap_runtime.py` | The one-shot bootstrap program (inlined into that compose file) |
| `scripts/render_bootstrap_compose.py` | Regenerates the bootstrap compose from its source |
| `scripts/prepare_public_build_repo.sh` | Stage + leak-scan the publishable file set |
| `tests/test_registry_deployment.py` | 74 crypto / parts / leak-scan / fail-closed tests |

---

## 1. Seal the catalogue (operator machine, once per catalogue edition)

```bash
cd /home/user/workspace/egordian-mcp-cloud
pip install -r requirements-registry.txt

# Leading space keeps the key out of shell history (bash: HISTCONTROL=ignorespace).
 export CATALOGUE_DECRYPTION_KEY='<long passphrase, 20+ chars>'
# or a raw key:  export CATALOGUE_DECRYPTION_KEY="hex:$(openssl rand -hex 32)"

./scripts/seal_catalogue.sh                      # defaults to data/catalogue.sqlite
# ./scripts/seal_catalogue.sh /path/to/catalogue.sqlite
```

Writes, with no extra plaintext copy at any point:

```
build/catalogue.enc              # ciphertext, mode 0444 (local/registry build)
build/catalogue.enc.part-000     # 62,914,560 B  ) deterministic parts for the
build/catalogue.enc.part-001     # 57,291,298 B  ) public GitHub build context
build/catalogue.enc.parts.json   # ordered per-part SHA-256 + overall encrypted SHA-256
build/catalogue.enc.meta.json    # alg/size metadata + pinned plaintext SHA-256
build/catalogue.sha256           # the value for CATALOGUE_SHA256
```

**Why parts.** The sealed container is 120,205,858 bytes — above GitHub's 100 MiB
single-file hard limit. `seal_catalogue.sh` therefore also splits the ciphertext into
deterministic ≤ 60 MiB parts and fails loudly if any part would exceed 100 MiB. Splitting
and rejoining are pure ciphertext operations: **no key is required and no plaintext is
involved.** Use `--no-split` to skip parts when only the single-blob path is needed.

```bash
python3 scripts/catalogue_crypto.py split --in build/catalogue.enc --out-dir build
python3 scripts/catalogue_crypto.py join  --manifest build/catalogue.enc.parts.json \
        --out /tmp/check.enc --expect-sha256 "$(sha256sum build/catalogue.enc | cut -d' ' -f1)"
```

Inspect a sealed blob without the key:

```bash
python3 scripts/catalogue_crypto.py info --in build/catalogue.enc
```

## 2. Build and push

```bash
export EGORDIAN_IMAGE=registry.example.com/joctools/egordian-aeo-mcp:1.0.0
export CATALOGUE_SHA256="$(cat build/catalogue.sha256)"
export CATALOGUE_ENC_SHA256="$(sha256sum build/catalogue.enc | cut -d' ' -f1)"

DOCKER_BUILDKIT=1 docker build \
  -f Dockerfile.registry \
  --build-arg CATALOGUE_ENC_SHA256="$CATALOGUE_ENC_SHA256" \
  -t "$EGORDIAN_IMAGE" .

docker push "$EGORDIAN_IMAGE"
```

`Dockerfile.registry` is **multi-stage**:

1. `catalogue-assembler` copies **only** `build/catalogue.enc.part-*` and
   `build/catalogue.enc.parts.json`, verifies every part's size and SHA-256, rejects gaps
   or reordering, concatenates in ascending index order, verifies the overall encrypted
   SHA-256 and the `EGCAT1` magic, then deletes the part staging.
2. The runtime stage takes `COPY --from=catalogue-assembler /staging/catalogue.enc` only —
   so the parts never exist in a shipped layer and the ciphertext is stored once.

BuildKit reads `Dockerfile.registry.dockerignore` (and `.dockerignore` for remote git
contexts), so `data/`, every `*.sqlite`, `*.db`, `*.pdf`, `*.csv`, `*.xlsx`, `dist/` and
`tests/` are excluded; only `build/catalogue.enc`, `build/catalogue.enc.part-*` and
`build/catalogue.enc.parts.json` are admitted from `build/`. The build fails if any
`catalogue.enc.part-*` survives into the final image, if any `*.sqlite`/`*.db` reaches
`/app` or `/opt`, if the blob starts with `SQLite format`, or if it is not `EGCAT1`.

Verify the pushed image locally before deploying:

```bash
docker run --rm --entrypoint sh "$EGORDIAN_IMAGE" -c \
  'head -c 6 /opt/egordian/catalogue.enc; echo; find /app /opt -name "*.sqlite*" | wc -l'
# expected: EGCAT1
#           0
```

## 2b. Public GitHub build (no registry credentials)

When no registry account is available, Hostinger builds the image itself from the approved
public encrypted-source repository. Only ciphertext parts are published.

```bash
./scripts/seal_catalogue.sh
./scripts/prepare_public_build_repo.sh /tmp/egordian-aeo-runtime   # stages + leak-scans

cd /tmp/egordian-aeo-runtime
git init -b main && git add -A
git commit -m "eGordian AEO runtime: encrypted catalogue parts + registry build"
git remote add origin https://github.com/ntxptrevor/egordian-aeo-runtime.git
git push -u origin main
```

On the VPS — `build.context` is the git URL, so nothing is pulled from a registry:

```bash
docker compose -f docker-compose.hostinger-build.yml --env-file ./egordian.env build --no-cache
docker compose -f docker-compose.hostinger-build.yml --env-file ./egordian.env up -d
```

Optionally pin the reassembled ciphertext by exporting
`CATALOGUE_ENC_SHA256="$(sha256sum build/catalogue.enc | cut -d' ' -f1)"` before the build;
the build then fails unless the concatenated parts hash to exactly that value. The
decryption key is **never** a build arg, label, or layer — it is runtime-only.

## 2c. Single-service deployment (USE THIS ON HOSTINGER)

Hostinger's Compose editor marked the two-service file invalid with Deploy disabled, and
its URL import created zero containers - its parser does not accept
`depends_on.condition: service_completed_successfully` (and does not build remote git
contexts). `docker-compose.hostinger-single.yml` is written for that narrow parser:

* exactly **one** service, image `python:3.12-slim`
* no `build`, no `depends_on`, no `profiles`, no `configs`/`secrets`/`extends`
* no YAML anchors, aliases, merge keys or `x-` extension fields
* short volume strings only (`egordian_runtime:/runtime`), no host ports
* a **twelve-line** `command` that downloads the pinned launcher and runs it

```bash
docker compose -f docker-compose.hostinger-single.yml --env-file ./egordian.env up -d
docker compose -f docker-compose.hostinger-single.yml --env-file ./egordian.env logs -f
```

In the published repo the same file is also available at the root as
`docker-compose.single.yml` for URL import.

**What the launcher does** (`scripts/launch_runtime.py`, fetched from
`LAUNCHER_URL`, optionally pinned with `LAUNCHER_SHA256`):

1. downloads the repo archive for `RUNTIME_REF` and extracts it with the same
   traversal/link/device checks as the bootstrap module;
2. verifies the ciphertext parts (contiguous indices, per-part size and SHA-256, overall
   SHA-256, `EGCAT1` magic) and concatenates them to `/runtime/catalogue.enc`;
3. `pip install --target /runtime/site-packages`, stages `app/` and `bin/`, creates
   `/runtime/state`, chowns everything to `10001:10001`;
4. locks code, dependencies and ciphertext to **read-only** (`0555`/`0444`, executables
   keep their bit) while `/runtime/state` stays `0700` writable;
5. **drops privileges irreversibly** - `os.setgroups([])`, `os.setgid(10001)`,
   `os.setuid(10001)`, verifies the drop and that `setuid(0)` now fails;
6. `os.execve`s `/runtime/bin/registry-entrypoint.sh`, which unseals the catalogue into
   the `/run/egordian` **tmpfs** (mode 0700, uid 10001) and starts uvicorn.

Root is used only for step 3-4 and only with `CHOWN`, `DAC_OVERRIDE`, `FOWNER` on top of
`cap_drop: ALL`, with `no-new-privileges` and a read-only root filesystem. The plaintext
catalogue exists only in tmpfs; the persistent control plane is `/runtime/state/data.db`.

After pushing a revision, pin both the ref and the launcher:

```bash
LAUNCHER_SHA256=$(sha256sum scripts/launch_runtime.py | cut -d' ' -f1)
LAUNCHER_URL=https://raw.githubusercontent.com/ntxptrevor/egordian-aeo-runtime/<sha>/scripts/launch_runtime.py
RUNTIME_REF=<sha>
```

## 2d. Two-service stock-image variant (kept for other hosts)

Hostinger's create-project runner stores a compose file but **does not build a remote git
`build.context`** - it reported success with zero containers. Use
`docker-compose.hostinger-bootstrap.yml`, which needs **no custom image, no build step and
no registry**: both services run `python:3.12-slim` straight from Docker Hub.

```bash
docker compose -f docker-compose.hostinger-bootstrap.yml --env-file ./egordian.env up -d
docker compose -f docker-compose.hostinger-bootstrap.yml --env-file ./egordian.env logs -f egordian-bootstrap
```

**Service A - `egordian-bootstrap`** (one-shot, `restart: "no"`, no ports, **no secrets**):

1. downloads `https://github.com/$RUNTIME_REPO/archive/$RUNTIME_REF.tar.gz` with the Python
   standard library (optional `ARCHIVE_SHA256` pin);
2. extracts it securely - absolute paths, `..` traversal, symlinks, hardlinks, devices and
   post-resolution escapes are all rejected, modes are normalised, and exactly one
   top-level directory is required;
3. verifies `build/catalogue.enc.parts.json`: contiguous indices, per-part size and
   SHA-256, overall encrypted SHA-256 (optional `CATALOGUE_ENC_SHA256` pin) and the
   `EGCAT1` magic, then concatenates the parts into `/runtime/catalogue.enc` (0444);
4. `pip install --target /runtime/site-packages` from `requirements-registry.txt`;
5. stages `app/`, `gordian_ctc/`, `profiles/`, `schemas/`, `console/`, `fixtures/` into
   `/runtime/app` and the decryptor + entrypoint into `/runtime/bin`, all chowned to
   `10001:10001`;
6. writes `/runtime/.bootstrap-complete.json` and exits 0.

It runs as `0:0` **only** so it can chown a fresh volume, with `cap_drop: ALL` plus
`CHOWN,DAC_OVERRIDE,FOWNER`, `no-new-privileges`, `read_only: true` and a tmpfs `/tmp`.

**Service B - `egordian-mcp`** waits on
`depends_on: {egordian-bootstrap: {condition: service_completed_successfully}}`, then runs
as `10001:10001`, `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, with
`/runtime` mounted **read-only**, `egordian_overlay` read-write, and the catalogue
decrypted into the uid-owned tmpfs `/run/egordian`. Secrets come from the env file at
runtime only - never a build arg, layer, or label.

Paths are supplied to the entrypoint by environment, so no custom image layout is assumed:

| Variable | Value |
|---|---|
| `CATALOGUE_ENC_PATH` | `/runtime/catalogue.enc` |
| `CATALOGUE_CRYPTO_PATH` | `/runtime/bin/catalogue_crypto.py` |
| `APP_ROOT` | `/runtime/app` |
| `RUNTIME_SITE_PACKAGES` | `/runtime/site-packages` |

**Idempotency and updates.** A matching stamp short-circuits the whole bootstrap. After
publishing a new revision:

```bash
# in ./egordian.env
RUNTIME_REF=<new commit sha>
FORCE_BOOTSTRAP=1        # only needed if the ref is unchanged
docker compose -f docker-compose.hostinger-bootstrap.yml --env-file ./egordian.env up -d --force-recreate
```

**`RUNTIME_REF` is a placeholder.** It defaults to `8659f42`; that commit does not exist
until the parent pushes the revision containing this compose file and the ciphertext parts.
Set `RUNTIME_REF` in `egordian.env` to the real SHA (or temporarily to `main`, which the
bootstrap accepts while logging a reproducibility warning).

**Never edit `docker-compose.hostinger-bootstrap.yml` by hand** - it is generated:

```bash
python3 scripts/render_bootstrap_compose.py          # regenerate
python3 scripts/render_bootstrap_compose.py --check  # CI guard (a test runs this)
```

## 3. Host configuration (Hostinger VPS)

```bash
umask 077
cat > ./egordian.env <<'ENVFILE'
EGORDIAN_IMAGE=registry.example.com/joctools/egordian-aeo-mcp:1.0.0
SERVICE_TOKENS=<token>|<user>|<project,...>|catalogue:read,egordian:read,aeo:run,aeo:approve
CATALOGUE_DECRYPTION_KEY=<the passphrase used in step 1>
CATALOGUE_SHA256=<contents of build/catalogue.sha256>
# optional, all default to "disconnected but healthy":
# EGORDIAN_AUTH_PROVIDER=basic
# EGORDIAN_USERNAME=
# EGORDIAN_PASSWORD=
# DATABASE_URL=postgresql://…
ENVFILE
chmod 0600 ./egordian.env

docker network inspect n8n_default >/dev/null   # must already exist (external)

docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env pull
docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env up -d
docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env logs -f egordian-mcp
```

Health and smoke:

```bash
docker inspect --format '{{.State.Health.Status}}' egordian-mcp
curl -sS https://egordian.joctools.com/healthz
curl -sS https://egordian.joctools.com/readyz -H "Authorization: Bearer <token>"
```

Rotate the key or ship a new catalogue edition:

```bash
# re-seal with the new key, rebuild, push, then:
docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env down
docker volume rm egordian_catalogue        # forces a fresh verified decrypt
docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env up -d
```

---

## 4. Runtime behaviour

`scripts/registry-entrypoint.sh` runs before the service and, in order:

1. refuses to start (exit **78**) if `CATALOGUE_DECRYPTION_KEY` is missing, or if
   `CATALOGUE_SHA256` is missing / not 64 lowercase hex characters, or if the sealed blob is
   absent from the image;
2. reuses an already-decrypted catalogue when its SHA-256 matches the pin (fast restarts);
   otherwise deletes it and decrypts again;
3. decrypts `/opt/egordian/catalogue.enc` into `${CATALOGUE_RUNTIME_DIR:-/run/egordian}/catalogue.sqlite`
   with mode **0444**, verifying **two** hashes — the one sealed inside the authenticated
   header and the externally pinned `CATALOGUE_SHA256`;
4. exits **79** and removes any partial output if authentication, size, or either hash check
   fails, so the service never runs on an unverified catalogue;
5. `unset`s the key, pops it again inside the Python bootstrap, then `exec`s uvicorn.

Key hygiene: `set +x`, `umask 077`, the key is only ever read from the environment (or
`CATALOGUE_DECRYPTION_KEY_FILE`), never appears in argv (so never in `ps` or
`/proc/<pid>/cmdline`), never in a log line, and never reaches the application process.

`ENTRYPOINT_DRY_RUN=1` runs the identical verification path and stops immediately before
`exec` — used by the test suite to prove the failure modes without starting anything.

---

## 5. Container format `EGCAT1`

```
header (82 bytes, authenticated as AAD on every chunk)
  magic "EGCAT1" | version | alg=AES-256-GCM | kdf | reserved
  iterations(4) | salt(16) | nonce_base(8) | chunk_size(4)
  plain_size(8) | plain_sha256(32)
body
  repeat: ciphertext(<= chunk_size) || GCM tag(16)
  AAD per chunk = header || chunk_index(4) || final_flag(1)
```

* **AES-256-GCM**, 4 MiB chunks — streams a 115 MiB catalogue in constant memory.
* Per-chunk nonce = `nonce_base || chunk_index`; the AAD binds every chunk to the header,
  its index, and the final-chunk flag, so **truncation, reordering and splicing are
  detected**, not just bit flips.
* Key: `hex:<64 hex chars>` is used raw; anything else is stretched with
  PBKDF2-HMAC-SHA256 (600 000 iterations, 16-byte salt).
* The plaintext SHA-256 is inside the authenticated header, so the pin itself cannot be
  swapped without failing decryption.

## 6. OpenSSL fallback — and its limitation

`cryptography` is a manylinux wheel and installs cleanly on `python:3.12-slim`, so
AES-256-GCM is the default and the only path exercised by tests. If a host forbids the
wheel, use OpenSSL **encrypt-then-MAC** (AES-256-CBC + PBKDF2, plus a separate
HMAC-SHA256):

```bash
# seal
 openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
   -in data/catalogue.sqlite -out build/catalogue.cbc.enc -pass env:CATALOGUE_DECRYPTION_KEY
 openssl dgst -sha256 -hmac "$CATALOGUE_HMAC_KEY" -binary \
   build/catalogue.cbc.enc > build/catalogue.cbc.hmac
 sha256sum data/catalogue.sqlite | cut -d' ' -f1 > build/catalogue.sha256

# unseal (verify the MAC first, then decrypt, then check the pin)
 openssl dgst -sha256 -hmac "$CATALOGUE_HMAC_KEY" -binary \
   /opt/egordian/catalogue.cbc.enc | cmp -s - /opt/egordian/catalogue.cbc.hmac \
   || { echo "MAC mismatch"; exit 79; }
 openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
   -in /opt/egordian/catalogue.cbc.enc -out /run/egordian/catalogue.sqlite \
   -pass env:CATALOGUE_DECRYPTION_KEY
 echo "$CATALOGUE_SHA256  /run/egordian/catalogue.sqlite" | sha256sum -c -
```

**Limitations of that fallback, accepted explicitly:**

1. CBC is **not** an authenticated mode. Integrity depends entirely on the separate
   HMAC being verified *before* decryption, and on a **second, independent** key
   (`CATALOGUE_HMAC_KEY`) — reusing the encryption key for the MAC is not supported here.
2. It requires **two full passes** over 115 MiB (MAC verify, then decrypt), roughly
   doubling start-up I/O versus the single streaming GCM pass.
3. It is **not chunk-bound**: a valid MAC over a whole file is all-or-nothing, so it gives
   no per-chunk position binding and no early failure.
4. `-pass env:` exposes the variable name (not the value) in argv; the value still lands in
   the OpenSSL process environment.
5. Two secrets must now be distributed and rotated together instead of one.

`age`/`sops` were not adopted: both add a binary (or a full KMS dependency) to the image
and a key-management story that this single-catalogue, single-operator deployment does not
need. AES-256-GCM via the already-required `cryptography` wheel delivers the same
authenticated-encryption guarantee with no new supply-chain surface.

---

## 7. What the tests prove

`python -m pytest tests/test_registry_deployment.py` — 39 tests, no container is built or run:

* sealed blob is `EGCAT1`, not SQLite, contains no licensed prose, is high-entropy;
* tamper, truncation, wrong key, missing key and wrong pin all fail — and leave **no**
  output file behind;
* round-trip restores byte-identical content at mode 0444 and the DB opens read-only;
* the entrypoint (executed for real, dry-run) exits 78 without key/pin, 79 on wrong
  key/pin, 0 on success, reuses a matching catalogue and replaces a mismatched one;
* key material never appears in stdout/stderr, never in argv, never in the app environment;
* the docker build context contains no `*.sqlite`/`*.db`/`*.pdf`/`*.csv`/`*.xlsx`, no SQLite
  magic bytes, and none of 50+ real task descriptions sampled from the live catalogue;
* the compose file publishes no host port, is `read_only`, drops all capabilities, sets
  `no-new-privileges`, uses named volumes only, and keeps eGordian credentials optional.


---

## 8. Hostinger-specific runtime notes

**TLS resolver.** The existing Traefik project on this host defines the certificate
resolver **`mytlschallenge`**, not `letsencrypt`. Both compose files use
`traefik.http.routers.egordian.tls.certresolver: "mytlschallenge"`; a test asserts it and
fails if the string `letsencrypt` reappears.

**Why `/run/egordian` is a tmpfs, not a named volume.** With `read_only: true`,
`cap_drop: [ALL]`, `no-new-privileges` and `user: "10001:10001"`, a freshly created named
volume mounted with `nocopy: true` stays **root-owned** — the entrypoint cannot create the
decrypted catalogue and the container fails to start. Instead:

```yaml
tmpfs:
  - /run/egordian:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700
```

The short-form `tmpfs:` list is used deliberately: the long `type: tmpfs` syntax cannot
express `uid`/`gid`. This is a net security gain — the plaintext catalogue is memory-only,
never touches host disk, and disappears on stop. Unsealing the full 115 MiB takes under a
second, so there is nothing to persist. Budget ~256 MiB of RAM for it.

**Why the overlay volume dropped `nocopy`.** `/var/lib/egordian` (the `data.db` control
plane) *must* persist. Docker seeds an **empty** named volume from the image directory and
copies its ownership and mode, so the image creates `/var/lib/egordian` owned by
`10001:10001`, mode `0700`, containing a `.keep` file. `nocopy: true` would skip exactly
that seeding and leave a root-owned mount, so it is removed. No init container, no chown
sidecar, and no capability is re-granted.

**The public build repo must exist first.** `https://github.com/ntxptrevor/egordian-aeo-runtime`
did not resolve at the time of writing. Create it (public, branch `main`) and push the
output of `scripts/prepare_public_build_repo.sh` before running the build compose file.
