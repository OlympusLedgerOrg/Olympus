# Groth16 Setup Provenance

Generated: 2026-06-08T23:57:10Z

PTAU_SOURCE: https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
PTAU_FILE: powersOfTau28_hez_final_20.ptau
PTAU_B2: 89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b

Verification key fingerprints (SHA-256):

Production circuits — vkey JSONs committed under `verification_keys/`:
- document_existence_vkey.json: d45f85e9b5605cdb378e1c36ae04d0aa59f0fbe779e4d14fee720895999c480b
- redaction_validity_vkey.json: bc4658832d9303353bcf86095dd64cd496c088068caa7c75e4f623a7ad045734
- non_existence_vkey.json: c0a48d507331ab463cfb868f1fc3f78332ddd71806ee6e37211627722d266ad5

Next-phase circuits — placeholder, ceremony pending, circuit feature-gated OFF
(no vkey JSON on disk yet; these fingerprints are reserved for the artifacts the
trusted setup will produce, and intentionally do not correspond to a committed file):
- unified_canonicalization_inclusion_root_sign_vkey.json: 1dc92c92bbe4fe00349061a966cd78491dd60bbdb5080f2ccf4092f5098f3b38 (requires PTAU power 20 trusted setup; gitignored until then)
- federation_quorum_vkey.json: c874c43b287d4bc01b528170cac91c8b41fb7396ad3144a74eaa7c207037f500 (behind the `quorum-circuit` cargo feature)
