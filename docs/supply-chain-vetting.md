# Supply-chain vetting

Olympus uses `cargo-vet` as an additive review trail for the runtime Rust
workspace. The initial baseline is intentionally exemption-based: it records the
current dependency graph so future dependency changes have a concrete review
queue instead of starting from zero.

The checks divide responsibility deliberately:

- `cargo-audit` tracks known vulnerability advisories.
- `cargo-deny` enforces license and source policy.
- `cargo-vet` records human audit provenance and prevents silent trust
  expansion.

Run locally from the repository root:

```bash
cargo vet --locked
```

The first gate covers the root Cargo workspace only. The workspace-excluded
verifier and fuzz graphs (`verifiers/rust/`, `fuzz/`, and
`verifiers/rust/fuzz/`) stay on the existing cargo-audit/cargo-deny gates for
now and should be added to cargo-vet in a follow-up once the runtime graph is
boring.

Dependency review should call out elevated-risk classes explicitly:

- Crypto primitives, proof systems, and signature implementations.
- Parsers, canonicalizers, archive handlers, ZIP/PDF/OOXML code, and codecs.
- Network-facing clients/servers, TLS, Tor/federation, and HTTP middleware.
- Crates with `unsafe`, native/FFI bindings, build scripts, or proc macros.
- Vendored or patched crates, which also need provenance drift checks.
