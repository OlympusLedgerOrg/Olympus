# Olympus Debug Console UI

Minimal FastAPI + Jinja2 developer console for integrity inspection.

## Run

```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
make dev
```

- API: http://127.0.0.1:8000
- UI: http://127.0.0.1:8080

## UX spec (wireframe text)

Top-to-bottom layout:

1. **Header bar**: title + API base URL.
2. **Failure banners**: red alert blocks for DB missing/503, invalid signature, chain broken.
3. **Proof explorer panel**: shard/record form + JSON output pane.
4. **Shard list table**: shard id, latest seq, latest root, signature validity.
5. **Per-shard panels**: latest header payload and ledger tail for linkage inspection.

This is a read-only debug view intended for engineers validating invariants.
