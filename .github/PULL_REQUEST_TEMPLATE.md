## Summary

<!-- What does this PR change, and why? Link the issue if one exists. -->

## Checklist

- [ ] `cargo nextest run --workspace`, `cargo test --doc --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` pass locally (or via the `.githooks/pre-push` hook)
- [ ] Frontend changes: `pnpm exec tsc --noEmit` + `pnpm exec eslint .` pass in `app/public-ui`

**If this PR touches cryptographic code** (leaf/node hashing, SMT, Poseidon, canonicalization, signatures):

- [ ] Domain constants come from `crates/olympus-crypto` — not redefined locally
- [ ] Any leaf/SMT hash layout change updates `olympus-crypto`, both verifiers (`verifiers/rust`, `verifiers/javascript`), the `smt_leaves` schema, **and** regenerates the SSMF golden vectors (`cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt`) in this same PR

**If this PR touches circuits, vkeys, or ceremony artifacts:**

- [ ] Regenerated the signed ceremony manifest in the same commit (never hand-edit `proofs/keys/manifests/*.json` — re-run `setup_circuits.sh`)
- [ ] `bash proofs/circomspect.sh` passes (or the baseline diff is reviewed and updated intentionally)

**If this PR adds or bumps dependencies:**

- [ ] No GPL in the runtime graph (`cargo deny check bans licenses sources`); Baby Jubjub / Poseidon stay on the vendored permissive crates
