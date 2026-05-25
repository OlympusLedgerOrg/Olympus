# Federation runbook

_Audience: operators running an Olympus node that participates in a
multi-node federation over Tor hidden services._

This document covers the operational side of `src-tauri/src/federation/`.
For the protocol design, see the module-level docs in
`src-tauri/src/federation/mod.rs`. For the security audit findings that
motivated each procedure below, see
[`docs/audits/2026-05-25-zk-anchoring-federation.md`](audits/2026-05-25-zk-anchoring-federation.md).

---

## 1. Status in v0.9

Federation is **feature-gated** (`--features federation`) and currently
**inert in the default ship**: the routes compile so the code stays
honest, but `tor::start_hidden_service` and `gossip::spawn` are not
wired into `main.rs`. A future release will add the wiring; until then,
"running federation" means building from source with the feature flag
and patching `main.rs` to spawn the tasks.

The persistence + admin surfaces (peer management, identity rotation,
gossip-error tracking) are all live regardless, so when wiring lands
operators inherit a fully-instrumented federation rather than one that
needs day-1 incident-response patches.

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
