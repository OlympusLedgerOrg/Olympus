# Federation runbook

_Audience: operators running an Olympus node that participates in a
multi-node federation over Tor hidden services._

This document covers the operational side of `src-tauri/src/federation/`.
For the protocol design, see the module-level docs in
`src-tauri/src/federation/mod.rs`. For the security audit findings that
motivated each procedure below, see
[`docs/audits/2026-05-25-zk-anchoring-federation.md`](audits/2026-05-25-zk-anchoring-federation.md).

---

## 1. Status in v0.10

Federation is **feature-gated** (`--features federation`) and **off in the
default ship** (the Tor stack isn't compiled in, so a vanilla build never
pretends to federate). To run it:

1. Build with `--features federation`:
   ```bash
   cargo tauri build --features federation
   # or, for dev:  cargo tauri dev -- --features federation
   ```
2. Persist a BJJ authority key (`OLYMPUS_BJJ_AUTHORITY_KEY`, or let bootstrap
   generate one) — checkpoints are signed under it.
3. Set `OLYMPUS_FEDERATION_ENABLED=1`.

On startup `main.rs` then bootstraps the Tor hidden service
(`tor::start_hidden_service`) and spawns the gossip loop (`gossip::spawn`).
The bootstrap runs off the critical path (it can take 30-60s); the new
`.onion` address is logged once it's live (`federation: hidden service live
at <addr>.onion`). Gossip push/pull is routed through the embedded Tor
client — peers are reached at their `.onion` addresses.

If `OLYMPUS_FEDERATION_ENABLED` is unset, the feature compiles but the Tor
bootstrap and gossip loop are skipped and the Tor-exposed routes report
`Federation not enabled`.

The persistence + admin surfaces (peer management, identity rotation,
gossip-error tracking) are live whenever the feature is compiled in, so
operators get a fully-instrumented federation.

### Security status — outstanding audit findings

Before enabling `OLYMPUS_FEDERATION_ENABLED=1`, operators should understand
where the federation hot path stands against the May 2026 audit (see
[`docs/audits/2026-05-25-zk-anchoring-federation.md`](audits/2026-05-25-zk-anchoring-federation.md)).
Status reflects the v0.10 tree:

| ID | Title | Status | Operator-visible impact |
|---|---|---|---|
| **H-5** | Silent wrong-circuit verifier fallback | **Addressed** | `verify::verify_checkpoint_proof` uses a single fixed verifier matched to the producer's circuit (`document_existence`) — no silent fallback chain to a circuit with a different public-signal shape. Producer (`build_own_checkpoint`) and verifier are on the same circuit, so an honest peer's checkpoint verifies. |
| **H-7** | SBT scope path must verify signature, not trust DB rows | **Addressed** | `api::middleware::auth` skips unsigned rows, checks the issuer is trusted, recomputes `commit_id`, and BJJ-EdDSA-verifies every credential before granting scopes. |
| **H-8** | Unsigned authority SBT at bootstrap | **Addressed** | `bootstrap::ensure_system_sbt` mints the bootstrap authority SBT *self-signed* (BJJ-EdDSA over the recomputed `commit_id`), populating the `issued_sig_*` / issuer-pubkey columns — no unsigned row can grant admin. |
| **H-10** | Federation admin routes need `AuthenticatedKey` + admin scope | **Addressed** | `federation::api` admin handlers (peer add/remove/trust, identity rotate) take the `AuthenticatedKey` extractor and call `require_admin` (admin scope) before any work; the Tor-exposed `tor_router` is a separate router that cannot reach the admin paths. |
| **H-11 / M-5** | Null `groth16_proof` silently stored as `proof_verified=false` | **Addressed** | `verify::verify_and_store` hard-rejects null-proof checkpoints; `checkpoint::build_own_checkpoint` now emits a real Groth16 `document_existence` proof attesting that the latest record's `original_root` is at `snapshot_index` in a Poseidon Merkle tree of size `snapshot_size` rooted at `snapshot_root` (= the checkpoint's `ledger_root`). Operator prerequisites: (a) `setup_circuits.sh` has been run so the `document_existence` artifacts (`.wasm` / `.r1cs` / `.ark.zkey`) are staged, and (b) at least one ingest record exists with all `snapshot_*` columns populated (pre-migration-0029 rows are invisible until backfilled — same semantics as the `/zk_bundle` endpoint). Each gossip tick incurs ~5-15s of CPU for the prove (run in `spawn_blocking` so the tokio reactor stays responsive). |
| **H-12 / F-3** | Equivocation default-on without operator opt-in | **Addressed** | `OLYMPUS_FEDERATION_AUTO_BLOCK` defaults to false; auto-block requires explicit opt-in plus a verified signature plus a detected equivocation. |

If you see a finding in the audit document that is **not** listed here, treat
it as outstanding and consult the audit's recommended order of operations
before relying on federation in production.

> **Tuning.** `OLYMPUS_FEDERATION_SYNC_INTERVAL` (seconds, floored at 10,
> default 300) sets the gossip cadence. `OLYMPUS_FEDERATION_AUTO_BLOCK=1`
> opts into auto-blocking equivocators (see §5).

## 2. Hidden-service identity

The HS keypair is persisted by arti under
`{app_data_dir}/tor/state/hs_service/`. The `.onion` address is
deterministic across restarts as long as that directory survives.

**Back this up.** Losing the directory wipes the address and every peer
that pinned it can't reach the node until they re-add it.

| Platform | App data dir |
|---|---|
| Linux | `~/.local/share/com.olympus.olympus/tor/` |
| macOS | `~/Library/Application Support/com.olympus.olympus/tor/` |
| Windows | `%APPDATA%/com.olympus.olympus/tor/` |

Recommended backup cadence: weekly, plus once immediately after the
first successful bootstrap (when the `.onion` address is logged at
startup). A bare `tar -czf hs-keys-$(date +%F).tgz tor/` is sufficient;
restore by extracting back over the same path before starting the
desktop.

## 3. Rotating the hidden-service identity

When you want to mint a fresh `.onion` (compromise suspected,
re-organization, hostname leak), use
**`POST /federation/identity/rotate`** (`admin` scope).

```bash
curl -X POST -H "X-API-Key: $OLYMPUS_ADMIN_KEY" \
     http://127.0.0.1:$PORT/federation/identity/rotate
```

Response:

```json
{
  "wiped_entries": 3,
  "next_step": "Restart the Olympus desktop process to bring up a fresh hidden service…"
}
```

The route only wipes the HS key material — it does **not** restart the
process, because arti caches the keypair in memory for the lifetime of
the running hidden service. After the call:

1. Stop the Olympus desktop process.
2. Restart it. The new `.onion` address is logged at startup
   (`federation: hidden service live at <new>.onion`).
3. Notify peers via your usual side channel and have them call
   `POST /federation/peers` with the new address. (Their previously
   stored entry will silently fail to reach you until updated.)

If the arti directory layout changes in a future release and the
automatic wipe stops finding the keys, the manual fallback is:

```bash
# 1. Stop the desktop process.
# 2. Locate the HS state dir.
ls "$APP_DATA_DIR"/tor/state/      # look for "hs_service" or a v3-onion-named subdir
# 3. Remove it.
rm -rf "$APP_DATA_DIR"/tor/state/hs_service
# 4. Restart the desktop.
```

## 4. Peer health monitoring

Each gossip round, `gossip::sync_round` pulls each trusted peer's
latest checkpoint. The outcome is recorded in `peer_nodes`:

- **Success** → `last_seen_at` set to NOW(), `last_pull_error_*` cleared.
- **Failure** → `last_pull_error_at` set to NOW(),
  `last_pull_error_msg` set to a short reason (truncated at 512 chars).

A peer with `last_pull_error_at > last_seen_at` is currently failing.
Query directly:

```sql
SELECT name, onion_address,
       last_seen_at,
       last_pull_error_at,
       last_pull_error_msg
  FROM peer_nodes
 WHERE trust_status = 'trusted'
   AND (last_pull_error_at IS NOT NULL AND
        (last_seen_at IS NULL OR last_pull_error_at > last_seen_at))
 ORDER BY last_pull_error_at DESC;
```

Or via the admin API: `GET /federation/peers` returns the same fields
on every row.

## 5. Equivocation auto-block

Auto-blocking peers that publish conflicting checkpoint roots at the
same timestamp is **opt-in**. Set `OLYMPUS_FEDERATION_AUTO_BLOCK=1` to
enable. The default is off so a peer-pubkey leak can't be weaponised
to silently block legitimate federation members (audit H-12 / F-3).

Equivocation events are persisted on the `peer_checkpoints` row
(`equivocation_detected = TRUE`) regardless of the auto-block flag, so
operators can review and act manually via
`PUT /federation/peers/{id}/trust` with `{"trust_status": "blocked"}`.

## 6. Wire format

`PeerCheckpoint` carries an explicit `wire_version` (currently `1`).
The verify path rejects any value that doesn't match. When the wire
format changes in a future release, bump
`PEER_CHECKPOINT_WIRE_VERSION` in `federation/mod.rs` and ensure peers
upgrade in lockstep (a partial-upgrade federation will see all
cross-version pulls fail with a clear "wire_version X not supported"
error rather than silently misparsing).

---

## 7. M-of-N quorum credentials

A credential can require an **M-of-N federation quorum** instead of a single
authority signature. Each of the `N` pinned signers (this node's BJJ authority
key + its trusted peers, from `peer_nodes`) signs the same domain-separated
message derived from the credential's `commit_id`; the credential is valid only
when `M` distinct signatures verify. Verification is fully offline against the
pinned signer set — no node contact, no chain.

See the dedicated doc for the design, threat model, and the optional
privacy-preserving ZK attestation:
[`docs/federation-quorum-credentials.md`](federation-quorum-credentials.md).

**Operator quick reference:**

- Build with `--features federation` (peer co-signing needs the Tor transport)
  and set `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` to the default `M` (or pass
  `quorum_threshold` per request).
- Issue a quorum credential:
  ```bash
  curl -XPOST localhost:$PORT/credentials -H "x-api-key: $ADMIN" \
    -d '{"holder_key":"bjj:...","credential_type":"press_credential",
         "quorum":true,"quorum_threshold":2}'
  ```
  The issuing node signs locally, then collects co-signatures from trusted
  peers over Tor (`POST /federation/cosign`) until the threshold is met. If it
  can't reach `M`, issuance fails closed with `409 Conflict`.
- The pinned signer set and threshold are stored on the credential row; the
  per-signer signatures live in `credential_quorum_signatures`. `POST
  /credentials/{id}/verify` re-checks the quorum and reports
  `{threshold, total_signers, valid_signatures, satisfied}`.
- The ZK quorum proof (proving "≥ M of N signed" without revealing *which*
  peers signed) is **next-phase**: the `federation_quorum` circuit is authored
  and wired but its trusted-setup ceremony has not run, so proofs are only
  produced in builds compiled with `--features quorum-circuit` once a real vkey
  is staged. The explicit signature set is the authoritative mechanism either
  way.
