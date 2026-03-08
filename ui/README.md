# Olympus Debug Console UI

Minimal FastAPI + Jinja2 developer console for integrity inspection.

## Run

```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export OLYMPUS_DEBUG_UI=true
export OPENSTATES_API_KEY='your-openstates-api-key'  # required for live voting lookups
make dev
```

- API: http://127.0.0.1:8000
- UI: http://127.0.0.1:8080

> **Note:** `OLYMPUS_DEBUG_UI=true` is required to enable the debug console.
> Without it, all UI routes return HTTP 404. This prevents accidental exposure
> in production.

## UX spec (wireframe text)

Top-to-bottom layout:

1. **Header bar**: title + API base URL.
2. **Failure banners**: red alert blocks for DB missing/503, invalid signature, chain broken.
3. **Commit / verify / redaction panels**: dual-anchor demo workflow for document commitments and proofs.
4. **Representative voting record tracker**: OpenStates-backed lookup for recent legislator votes.
5. **Bill text simplifier pipeline**: pasted legislation → deterministic plain-English summary + visible prompt chain.
6. **Geofence boundary visualizer**: district GeoJSON + constituent points → overlap counts + inline SVG map.
7. **Proof explorer panel**: shard/record form + JSON output pane.
8. **Shard list table**: shard id, latest seq, latest root, signature validity.
9. **Per-shard panels**: latest header payload and ledger tail for linkage inspection.

This is a read-only debug view intended for engineers validating invariants.

Theme notes:
- Uses CSS custom properties (`:root`) for a consistent "cryptographic" palette.
- Automatically adapts to dark mode via `prefers-color-scheme`.
