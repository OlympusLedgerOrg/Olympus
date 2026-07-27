# Supply-chain exemption rationale

`cargo vet fmt` canonicalizes `config.toml` and does not preserve comments.
This companion ledger records the rationale for exemptions that intentionally
remain unaudited.

| Crate | Version | Rationale |
|---|---:|---|
| `ntapi` | 0.4.3 | Audit deferred for this unsafe Windows FFI/Franken-C pin. It remains trusted without a source audit because the GitHub Advisory Database reported no advisories when rechecked on 2026-07-26. |
| `objc2-io-kit` | 0.3.2 | Audit deferred for this unsafe Apple I/O Kit FFI pin. It remains trusted without a source audit because the GitHub Advisory Database reported no advisories when rechecked on 2026-07-26. |
| `sysinfo` | 0.37.2 | Audit deferred for this unsafe cross-platform FFI/Franken-C pin. It remains trusted without a source audit because the GitHub Advisory Database reported no advisories when rechecked on 2026-07-26. |
