# Test coverage

Olympus measures coverage across the Rust workspace and the React frontend on every PR via [.github/workflows/coverage.yml](../.github/workflows/coverage.yml). The current state is **measurement-only** — coverage results are reported in the PR's check summary but do not block merges.

A follow-up PR will introduce `coverage-baseline.toml` and a ratchet gate so per-module coverage can only go up.

## Targets

The eventual goal is **≥85% line coverage per module**:

- `src-tauri/` (excluding the `prover` feature path; see [Known limitations](#known-limitations))
- `crates/olympus-crypto`
- `crates/light-poseidon` (vendored — best-effort)
- `app/public-ui/`

Excluded by design:
- `verifiers/rust/` — has its own conformance test suite that doubles as coverage.
- `pg-embed-local/` — vendored fork, not our code.
- `fuzz/` — fuzz targets, not unit tests.

## Run locally

### Rust

Install [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) once:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

Then from the repo root:

```bash
# Full workspace (default features = prover enabled, matches CI).
cargo llvm-cov --workspace --summary-only

# HTML report (open target/llvm-cov/html/index.html in a browser).
cargo llvm-cov --workspace --html

# Just one crate.
cargo llvm-cov -p olympus-crypto --summary-only
```

### Frontend

```bash
pnpm --filter app/public-ui coverage
# Open app/public-ui/coverage/index.html for the detailed view.
```

The vitest config is in [app/public-ui/vitest.config.ts](../app/public-ui/vitest.config.ts).

## Known limitations

- Frontend tests do not yet exist — coverage will be ~0% until tests land in PR C+.

## Writing tests

- Rust unit tests live alongside source as `#[cfg(test)] mod tests { ... }`. Integration tests go in `src-tauri/tests/` or the equivalent in each crate.
- Frontend tests use [vitest](https://vitest.dev/). Convention: `src/**/__tests__/<thing>.test.ts` or `src/**/<thing>.test.tsx`. Component tests should use `@testing-library/react` (not yet added — add to devDependencies when needed).
