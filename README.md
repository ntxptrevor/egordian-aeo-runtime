# eGordian AEO MCP Service

A **remote, headless, horizontally stateless** MCP service that exposes:

- the **AEO** (Assignment Estimate Operator) nine-stage deterministic estimating pipeline,
- the private, licensed **Gordian CTC catalogue** behind a hard licensing firewall,
- an **exact allowlist** of every operation documented on
  [the eGordian JOC Service Help page](https://jocservice.egordian.com/Help),

over **MCP protocol revision `2026-07-28`** at a single `POST /mcp` endpoint, plus a minimal
REST/status surface and an operator console.

The backend is the product. The console exists only to observe the service.

---

## 1. What it is (and is not)

| Property | Value |
|---|---|
| MCP revision | `2026-07-28` — no `initialize` handshake, no `Mcp-Session-Id`, no `GET` event stream, no sticky sessions |
| Transport | `POST /mcp`, JSON-RPC 2.0, one request object per call |
| Methods | `server/discover`, `tools/list`, `tools/call`, `resources/list`, `resources/read` |
| State | None in-process. All cross-call state lives behind a repository abstraction |
| Auth | Bearer only, private by default; `/healthz` is the sole public route |
| Writes | Disabled by default; require scope **and** actor **and** approval object **and** idempotency key |
| DELETE | Registered but permanently blocked (`human_gate_required`), never executed |
| Price proposal submit | **Capability-blocked** — no write route is documented (see §7) |

---

## 2. Quick start (container)

```bash
docker build -t egordian-aeo-mcp .
docker run --rm -p 8080:8080 \
  -e DEPLOYMENT_ENV=production \
  -e AUTH_MODE=bearer \
  -e 'SERVICE_TOKENS=REPLACE_TOKEN|trevor|P-1|catalogue:read,egordian:read,aeo:run,aeo:approve' \
  egordian-aeo-mcp
```

The service listens on `0.0.0.0:$PORT` (default `8080`). Nothing else needs to be run
locally — clients connect to the deployed URL.

Local development only:

```bash
pip install -r requirements-dev.txt
AUTH_MODE=dev DEPLOYMENT_ENV=preview uvicorn app.main:app --host 0.0.0.0 --port 8080
python -m pytest
```

`AUTH_MODE=dev` is **refused** whenever `DEPLOYMENT_ENV=production`.

---

## 3. Remote MCP client configuration

The service is a plain HTTP MCP endpoint: URL + bearer token. There is no local process,
no stdio bridge, and no session to keep alive.

**Claude (remote/custom MCP connector):**

```json
{
  "mcpServers": {
    "egordian-aeo": {
      "type": "http",
      "url": "https://YOUR-HOST/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}
```

**Perplexity (remote MCP connector):** add a custom connector with
`Server URL = https://YOUR-HOST/mcp` and header `Authorization: Bearer YOUR_TOKEN`.

**Any other 2026-07-28 client:** point it at `https://YOUR-HOST/mcp` with the bearer header.
The client must send `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, and — for
`tools/call` / `resources/read` — a matching `Mcp-Name`.

**Raw call:**

```bash
curl -sS https://YOUR-HOST/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: server/discover" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover",
       "params":{"_meta":{"clientInfo":{"name":"curl","version":"8"}}}}'
```

Legacy stateless 2025 clients are refused unless `ALLOW_LEGACY_2025_CLIENTS=true`; even then
they run on an isolated path that still creates no session and still rejects `initialize`.

### First calls

1. `tools/call handle_create {"project_ids":["P-1"]}` → opaque, user- and project-bound,
   expiring handle.
2. Pass `handle` + `project_id` on every subsequent tool call.
3. Any side-effecting tool additionally needs `actor`, `approval`
   `{approved, actor, rationale, approved_at}`, and `idempotency_key`.

---

## 4. Deployment notes

### Perplexity private deploy (preview)

Two pieces:

1. **Backend** — run the service in the sandbox on **port 8080**, bound to `0.0.0.0`:
   `uvicorn app.main:app --host 0.0.0.0 --port 8080`. Set `AUTH_MODE=bearer` and
   `SERVICE_TOKENS`. The SQLite overlay (`data.db`) plus the bundled read-only catalogue
   are sufficient. Treat this as **preview**: the container filesystem is not durable.
2. **Static console bundle** — `python scripts/build_static_console.py` writes
   `dist/public/` (`index.html`, `docs.html`, `assets/`, `robots.txt`). Deploy that
   directory. Every backend call in the bundle is built from the `__PORT_8080__`
   placeholder, which the deploy proxy rewrites to `port/8080`, so the console reaches
   the sandbox backend through the same authenticated proxy as the static assets.

The bundle is read-only (GET-only, endpoint allowlist), uses no cookies or web storage,
uses only relative links so it works from any `/computer/a/<id>/` iframe path, and ships
no service data, credentials, or catalogue content. `scripts/preview_proxy.py` emulates
the deploy proxy locally for QA; it is not part of the bundle.

MCP clients still talk to the **backend URL** (`https://…/mcp`), not to the static bundle.

### Vercel — limitations

Vercel's serverless functions are ephemeral and read-only apart from `/tmp`, cap the
deployment bundle well below the 115 MiB catalogue, and recycle instances between requests.
That is incompatible with the bundled immutable catalogue and with a SQLite overlay.
If you must use Vercel: set `DATABASE_URL` to an external PostgreSQL instance **and** host
the catalogue-backed tools elsewhere, or accept catalogue tools reporting `unavailable`.
Vercel is not a supported target for the full service.

### Registry-safe variant (no SSH upload) — `Dockerfile.registry`

When the catalogue cannot be uploaded to the host over SSH and the image must travel
through a container registry, use the registry variant: **no layer ever contains the
plaintext catalogue.** The catalogue is sealed with AES-256-GCM before the build; the
plaintext exists only inside a private volume at run time, and only when
`CATALOGUE_DECRYPTION_KEY` and the pinned `CATALOGUE_SHA256` are both supplied.

```bash
 export CATALOGUE_DECRYPTION_KEY='<long passphrase>'   # leading space: no shell history
./scripts/seal_catalogue.sh          # -> build/catalogue.enc + <=60 MiB parts + manifest

# A) registry path
DOCKER_BUILDKIT=1 docker build -f Dockerfile.registry -t "$EGORDIAN_IMAGE" .
docker push "$EGORDIAN_IMAGE"
docker compose -f docker-compose.hostinger.yml --env-file ./egordian.env up -d

# B) public-source path - no registry credentials
./scripts/prepare_public_build_repo.sh /tmp/egordian-aeo-runtime   # stages + leak-scans
docker compose -f docker-compose.hostinger-build.yml --env-file ./egordian.env up -d --build
```

The sealed container is above GitHub's 100 MiB single-file limit, so the public repo carries
deterministic ciphertext parts plus a hash manifest; a throwaway builder stage verifies and
reassembles them inside the image.

Full procedure, container format, fail-closed behaviour and the OpenSSL fallback (with its
limitations) are in [`docs/REGISTRY_DEPLOY.md`](docs/REGISTRY_DEPLOY.md).

### Recommended durable deployment — Hostinger VPS + Supabase

1. **Compute:** Hostinger VPS (or any container host) running the image above with a
   persistent volume for `/app/data`.
2. **Control plane:** Supabase PostgreSQL. Set `DATABASE_URL=postgresql://...` and the
   service switches to `PostgresRepository` automatically; migrations run at start-up.
   No local filesystem is then required for state.
3. **Catalogue:** ship the licensed SQLite catalogue inside the image (private registry) or
   mount it read-only. It is never served, never listed, never downloadable.
4. **TLS + secrets:** terminate TLS at the reverse proxy; inject `SERVICE_TOKENS` and any
   eGordian credentials from the platform's secret store.
5. **Scaling:** run N replicas behind a plain round-robin load balancer. No session
   affinity is needed or supported.

---

## 5. Configuration

See `env.example` for the full list (names only, never values). Key variables:

| Variable | Purpose |
|---|---|
| `SERVICE_TOKENS` | `token\|user\|projects\|scopes` entries separated by `;` |
| `DATABASE_URL` | Set → PostgreSQL control plane; unset → SQLite `data.db` |
| `CATALOGUE_DB_PATH` | Immutable licensed catalogue (read-only, `immutable=1`) |
| `EGORDIAN_AUTH_PROVIDER` | `none` \| `basic` \| `bearer` \| `headers` |
| `ALLOW_EGORDIAN_WRITES` | Default `false`; writes also need scope + approval envelope |
| `ALLOW_ADMIN_OPERATIONS` | Default `false`; gates `HealthCheck/RefreshCache` |

**No eGordian credentials are currently available for `jocservice.egordian.com`.** With
`EGORDIAN_AUTH_PROVIDER=none` the service runs normally: status shows `disconnected` and
eGordian tools return an actionable `credential_required` error instead of crashing.

---

## 6. Scopes

`catalogue:read`, `egordian:read`, `egordian:write`, `aeo:run`, `aeo:approve`, `admin`
(`admin` implies all). Writes require **both** the scope and the approval envelope.

---

## 7. Deliberate refusals

| Refusal | Why |
|---|---|
| `human_gate_required` on every documented `DELETE` | Destructive; a named human acts directly in eGordian |
| `admin_operation_disabled` on `GET api/HealthCheck/RefreshCache` | Mutates remote cache state |
| `capability_not_documented` on price-proposal draft/submit | The Help page documents only `GET v1/Owners/{ownerId}/PriceProposals`; no write route exists to call, and this service never invents one. AEO stage 8 therefore stays **assisted** and emits a submission packet for a human to file |
| Licensing firewall | No download, dump, bulk browse or export of catalogue content; result counts capped; cost fields redacted without authorization; `data/` is never served |

---

## 8. AEO pipeline

| # | Stage | Tier |
|---|---|---|
| 0 | Detect & authenticate | T1 |
| 1 | Assemble the assignment dossier | T1 |
| 2 | Build the knowledge base (input gates) | T2 |
| 3 | Quantify takeoff with N-run consensus | T2 |
| 4 | Crosswalk scope → CTC catalogue | T1 |
| 5 | Assemble the price proposal (**known-target reconciliation**, never estimate-from-scratch) | T1 |
| 6 | Self-check & confidence tier | T1 |
| 7 | **Human gate** (mandatory before any dollar commitment) | T3 |
| 8 | Submit & log (**capability-blocked**, assisted only) | T1 |

Code owns every transition. Stages 2–4 may propose candidates but can never invent a
catalogue line, a quantity, or a price. Every run emits a manifest with version hashes,
evidence spans, exceptions and the gate decision — *no manifest, no deliverable*.

---

## 9. Project layout

```
app/
  main.py               FastAPI app: /mcp, REST, console, OpenAPI
  config.py             environment-only settings
  security.py           auth, RBAC, approval envelopes, rate limits, redaction
  catalogue_gateway.py  licensing firewall over the sealed catalogue
  mcp/                  protocol.py · dispatcher.py · tools.py · resources.py
  egordian/             registry.py · client.py · auth.py
  aeo/                  machine.py · runner.py
  repo/                 base.py · sqlite_repo.py · postgres_repo.py · migrations.py
gordian_ctc/            the existing deterministic engine (imported unchanged)
fixtures/               fetched eGordian Help page snapshot (registry source of truth)
console/                operator console + API documentation page
data/catalogue.sqlite   licensed, immutable, never served
tests/                  144 tests
```

---

## 10. Licensing

Private and contract-bound. The catalogue is supplied for an authorized owner/contract and
must never be exported, published, mined, or placed in a model prompt. See
`vendor_docs/licensing-boundaries.md`.
