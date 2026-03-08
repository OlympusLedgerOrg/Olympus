# Olympus Debug Console UI

Minimal FastAPI + Jinja2 developer console for integrity inspection.

## Run

```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export OLYMPUS_DEBUG_UI=true
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
3. **Proof explorer panel**: shard/record form + JSON output pane.
4. **Shard list table**: shard id, latest seq, latest root, signature validity.
5. **Per-shard panels**: latest header payload and ledger tail for linkage inspection.

This is a read-only debug view intended for engineers validating invariants.

Theme notes:
- Uses CSS custom properties (`:root`) for a consistent "cryptographic" palette.
- Automatically adapts to dark mode via `prefers-color-scheme`.
