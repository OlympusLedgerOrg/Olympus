# Supply-chain vetting

Olympus uses `cargo-vet` as an additive review trail for the runtime Rust
workspace. The initial baseline is intentionally exemption-based: it records the
current dependency graph so future dependency changes have a concrete review
queue instead of starting from zero.

Run locally from the repository root:

```bash
cargo vet --locked
```

The first gate covers the root Cargo workspace only. The workspace-excluded
verifier and fuzz graphs (`verifiers/rust/`, `fuzz/`, and
`verifiers/rust/fuzz/`) stay on the existing cargo-audit/cargo-deny gates for
now and should be added to cargo-vet in a follow-up once the runtime graph is
boring.
