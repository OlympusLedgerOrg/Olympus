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
# Full workspace, no-default-features (matches CI).
cargo llvm-cov --workspace --no-default-features --summary-only

# HTML report (open target/llvm-cov/html/index.html in a browser).
cargo llvm-cov --workspace --no-default-features --html

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

- The Rust coverage job runs with `--no-default-features`, which disables the `prover` feature. This avoids the cranelift `__rust_probestack` link error documented in [.github/workflows/ci.yml](../.github/workflows/ci.yml). **Code reachable only through the prover path (e.g. `src-tauri/src/zk/prove.rs`) is not measured.** Once the linker issue is resolved (or we move the prover behind a runtime check), the `--no-default-features` flag can be dropped.
- Frontend tests do not yet exist — coverage will be ~0% until tests land in PR C+.

## Writing tests

- Rust unit tests live alongside source as `#[cfg(test)] mod tests { ... }`. Integration tests go in `src-tauri/tests/` or the equivalent in each crate.
- Frontend tests use [vitest](https://vitest.dev/). Convention: `src/**/__tests__/<thing>.test.ts` or `src/**/<thing>.test.tsx`. Component tests should use `@testing-library/react` (not yet added — add to devDependencies when needed).
