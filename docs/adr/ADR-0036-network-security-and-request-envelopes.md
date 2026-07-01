# ADR-0036: Network security and signed request envelopes

Status: Proposed (2026-07-01)

## Context

Olympus v0.10 is a Rust/Tauri desktop app with an embedded Axum HTTP server and
embedded PostgreSQL. The retired FastAPI/Go services are not part of the live
runtime. The live network model is:

- local app zone: Tauri webview, Axum on loopback, local verifier tooling;
- embedded data zone: `pg_embed` PostgreSQL on loopback;
- public verification zone: read/verify endpoints, including the Tor-facing
  federation subset when the `federation` feature is enabled;
- federation zone: Tor hidden-service proxying to a separate loopback listener.

The current backend already has important local-hardening controls:

- `server::start` binds Axum to `127.0.0.1` and refuses non-loopback binds;
- `start_tor_listener` uses a separate loopback listener with only public
  read/verify and federation peer routes;
- `validate_loopback_host` rejects non-loopback `Host` headers to reduce DNS
  rebinding risk;
- CORS allows fixed Tauri origins plus exact `CORS_ORIGINS` entries and ignores
  wildcard entries;
- `db::patch_pg_conf` forces embedded PostgreSQL to `listen_addresses =
  '127.0.0.1'`;
- shared auth extractors reject expired/revoked API keys and ignore
  `X-Forwarded-For` unless `OLYMPUS_TRUST_FORWARDED_FOR=true`.

## Decision

Treat network security as its own roadmap, separate from experimental crypto.
The first implementation slice is local lockdown:

- Vite dev server binds explicitly to `127.0.0.1:5173` with `strictPort`;
- Tauri dev URL points at `http://127.0.0.1:5173`;
- `scripts/doctor-network-windows.ps1` fails when watched Olympus/dev ports are
  listening on `0.0.0.0` or `::`.

The next protocol slice should be a signed request envelope for sensitive
network-facing actions:

```text
SignedRequestV1 {
  operator_id,
  key_id,
  method,
  path,
  body_hash,
  timestamp_utc,
  nonce,
  scope,
  signature_alg,
  signature
}
```

The signed message must be domain-separated and length-prefixed:

```text
BLAKE3(
  OLY:REQUEST:V1 ||
  lp(operator_id) ||
  lp(key_id) ||
  lp(method) ||
  lp(path) ||
  body_hash_32 ||
  timestamp_be_i64 ||
  lp(nonce) ||
  lp(scope)
)
```

Verification order is fail-closed and split by cost:

1. parse the envelope and check method, path, body hash, domain, and timestamp;
2. verify the cheap Ed25519 leg against the operator/key registry;
3. reserve `(key_id, nonce)` in the replay cache;
4. verify expensive hybrid/PQC legs, if policy requires them, on a blocking
   worker thread;
5. roll back the reserved nonce if expensive verification fails;
6. deserialize the inner payload and let the handler enforce the route's exact
   required scope.

This keeps invalid signatures from touching shared replay state while avoiding
the asymmetric DoS trap where an attacker forces ML-DSA verification before
replay rejection. The replay cache is touched only after Ed25519 proves
cryptographic intent, and expensive verification is isolated from Tokio's async
worker threads.

The initial wire body carries `payload_canonical_b64`, not an arbitrary nested
JSON object. The decoded bytes must already be JCS canonical JSON and
`body_hash` is `BLAKE3(payload_canonical_bytes)`. That avoids hashing a
parser-dependent reserialization of the request body.

## Scope Matrix Direction

Existing route handlers already use `AuthenticatedKey`, `require_admin_auth`,
and local scope checks. A follow-up should turn the current implicit policy into
a tested matrix:

| Endpoint family | Required boundary |
| --- | --- |
| `/health`, `/public/*`, `/v1/public/*`, `/zk/verify` | public/read-only |
| `/ingest/*`, `/ledger/ingest/*` | authenticated write/commit scope |
| `/redaction/*` mutating routes | authenticated redaction/create scope |
| `/credentials` issue/revoke | credential issue/revoke policy |
| `/admin/*`, `/key/admin/*`, `/admin/shards` | admin role plus admin scope or configured operator key |
| federation Tor routes | peer registry identity plus signed artifact verification |

## Consequences

- No ledger hash, SMT, ZK circuit, ceremony, or database change in the local
  lockdown slice.
- Public bind remains opt-in only via a future, separately reviewed deployment
  mode; localhost remains the desktop default.
- Signed request envelopes use a persistence-backed replay cache
  (`signed_request_nonces`) before they become mandatory on mutating endpoints.
- The default freshness window is five minutes, tunable by
  `OLYMPUS_SIGNED_REQUEST_FRESHNESS_SECS` and capped at one hour to tolerate
  desktop clock drift without making replay windows unbounded.
- mTLS remains a channel protection for future public/federated deployment; it
  does not replace Olympus artifact signatures or signed request envelopes.

## Non-goals

This ADR does not add:

- direct public Axum binding;
- TLS termination inside the desktop app;
- a second API authority in the frontend;
- new Python or Go services;
- changes to existing BJJ, Ed25519, Groth16, or SMT semantics.
