# Groth16 Setup Provenance

Generated: 2026-06-30T00:02:53Z

PTAU_SOURCE: https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
PTAU_FILE: powersOfTau28_hez_final_20.ptau
PTAU_B2: 89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b

Verification key fingerprints (SHA-256):
- document_existence_vkey.json: 2ad906b6256ccc60706a5bafb9c3d5fd0d027c0e47f9ebe9765eb83de61fb5ae
- non_existence_vkey.json: e3fc9d41fed2cb4307b495969b7d94ed4c9ebfbebe9b7299bbbfa80f8dd92010
- unified_canonicalization_inclusion_root_sign_vkey.json: d26d3d3077e317272391fad9c1e5177b33d62fe684af59a5fcc5d2dfdaa883b1
- federation_quorum_vkey.json: 1e8b18a3c9376417ff49f1ba616cfb258bcb8f2af3cf8f77b73c1dbdee79cdf0

## `federation_quorum` — superseded by a circuit change (2026-08-14)

`federation_quorum.circom` gained three soundness constraints after this run
(audit OLY-M5 / OLY-L12 / threshold range), so the R1CS changed:
59,081 → 59,282 non-linear and 5,636 → 5,693 linear constraints. **The
fingerprint above, and every artifact hash in
`proofs/keys/manifests/federation_quorum_manifest.json`, therefore describe a
circuit that no longer exists in the tree.**

Nothing breaks today and no regeneration was performed, deliberately: the
committed vkey is a placeholder (gitignored — see `.gitignore`), so
`build.rs::verify_manifest_vkey_blake3` skips its assertion for this circuit,
and the runtime `.ark.zkey` hash check only fires when a real zkey is loaded,
which cannot happen before the ceremony. Regenerating a *dev* manifest would
only replace one set of hashes nobody can verify with another.

**Whoever runs the production Phase-2 ceremony for `federation_quorum` must run
it against the post-fix circuit**, and the manifest and vkey fingerprint here
must be regenerated in that same commit.
