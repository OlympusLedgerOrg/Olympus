//! Round-trip test for the `unified_canonicalization_inclusion_root_sign` circuit.
//!
//! Round 4: fixture construction added; `#[ignore]` removed.
//! The test gracefully returns (no failure) when circuit artifacts are absent —
//! run `bash proofs/setup_circuits.sh` to materialise them.  When the artifacts
//! are present the full prove → verify round-trip executes.
//!
//! ## Witness ↔ circuit alignment (audit C-1 / C-2)
//!
//! The `unified_canonicalization_inclusion_root_sign.circom` circuit
//! declares **4 public signals**: `[canonicalHash, merkleRoot, ledgerRoot,
//! treeSize]`. `UnifiedWitness::public_signals()` returns those four;
//! `UnifiedWitness::circom_inputs()` pushes only the signals the circuit
//! actually declares.
//!
//! The witness struct still carries `checkpoint_timestamp`,
//! `authority_pubkey`, `authority_pubkey_hash`, and `signature` as
//! off-circuit context — they're used by `UnifiedWitness::sign_checkpoint`
//! and by `federation::verify::verify_checkpoint_signature` to produce
//! and verify the Baby Jubjub EdDSA-Poseidon checkpoint signature
//! **off-circuit**. There is no in-circuit `EdDSAPoseidonVerifier`,
//! despite the `_root_sign` suffix in the circuit file name; see the
//! circuit's own docstring at lines 41–46 for the authoritative statement.
//!
//! ## Fixture design
//!
//! All three consistency constraints mirror the circom components exactly:
//!
//! **Component 1 — canonicalization** (domain-3 chain, maxSections = 8):
//! ```text
//! acc = sectionCount
//! for i in 0..8:
//!     acc = DomainPoseidon(3)(acc, sectionLengths[i])
//!     acc = DomainPoseidon(3)(acc, sectionHashes[i])
//! canonicalHash == acc
//! ```
//!
//! **Component 2 — Merkle inclusion** (depth 20, domain-1 `DomainPoseidonNode`):
//! ```text
//! leaf = canonicalHash  placed at index 0 (all merkleIndices = 0)
//! siblings = precomputed zero-subtree hashes zeros[0..20]
//! merkleRoot = compute_merkle_root(canonicalHash, zeros[0..20], [0;20], domain=1)
//! leafIndex  = Σ merkleIndices[k] * 2^k  =  0
//! ```
//!
//! **Component 3 — ledger SMT** (depth 256, same domain-1 node hash):
//! ```text
//! leaf = merkleRoot  placed at index 0 (all ledgerPathIndices = 0)
//! siblings = zeros[0..256]
//! ledgerRoot = compute_merkle_root(merkleRoot, zeros[0..256], [0;256], domain=1)
//! ```

use std::path::PathBuf;

use ark_bn254::Fr;
use olympus_tauri_lib::zk::poseidon::{compute_merkle_root, domain_node, PoseidonError};
use olympus_tauri_lib::zk::prove::prove_unified;
use olympus_tauri_lib::zk::verify::CircuitVerifier;
use olympus_tauri_lib::zk::witness::unified::{MAX_SECTIONS, MERKLE_DEPTH, SMT_DEPTH};
use olympus_tauri_lib::zk::witness::{BabyJubJubPubKey, UnifiedWitness};

// ---------------------------------------------------------------------------
// Artifact resolution
// ---------------------------------------------------------------------------

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

fn artifacts() -> Option<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let build = build_dir();
    let stem = "unified_canonicalization_inclusion_root_sign";
    let wasm = build.join(format!("{stem}_js")).join(format!("{stem}.wasm"));
    let r1cs = build.join(format!("{stem}.r1cs"));
    let ark_zkey = build.join(format!("{stem}_final.ark.zkey"));
    let vkey = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("keys")
        .join("verification_keys")
        .join(format!("{stem}_vkey.json"));
    if wasm.is_file() && r1cs.is_file() && ark_zkey.is_file() && vkey.is_file() {
        Some((wasm, r1cs, ark_zkey, vkey))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Fixture helpers (mirror protocol/poseidon_tree.py + ssmf.py in Rust)
// ---------------------------------------------------------------------------

/// Precompute the "empty subtree" hash at each depth using domain-1 Poseidon.
///
/// `zeros[0]` = Fr(0) (empty leaf sentinel).
/// `zeros[i]` = root of an all-zero subtree of height `i`, i.e.
///              `DomainPoseidon(1)(zeros[i-1], zeros[i-1])`.
///
/// These are the siblings used in the sparse Merkle path for a leaf at index 0.
fn precompute_zero_hashes(max_depth: usize) -> Vec<Fr> {
    let mut zeros = Vec::with_capacity(max_depth + 1);
    zeros.push(Fr::from(0u64));
    for i in 0..max_depth {
        let next = domain_node(1, zeros[i], zeros[i])
            .expect("precompute_zero_hashes: domain_node is infallible for valid Fr");
        zeros.push(next);
    }
    zeros
}

/// Compute `canonicalHash` matching circom component 1.
///
/// Chain: acc = section_count, then for each slot:
///   acc = DomainPoseidon(3)(acc, section_lengths[i])
///   acc = DomainPoseidon(3)(acc, section_hashes[i])
///
/// Exactly mirrors the `structuredHashes` signal array in the circuit.
/// Both `section_lengths` and `section_hashes` must have length `MAX_SECTIONS`.
fn compute_canonical_hash(
    section_count: u64,
    section_lengths: &[u64; MAX_SECTIONS],
    section_hashes: &[Fr; MAX_SECTIONS],
) -> Result<Fr, PoseidonError> {
    let mut acc = Fr::from(section_count);
    for i in 0..MAX_SECTIONS {
        acc = domain_node(3, acc, Fr::from(section_lengths[i]))?;
        acc = domain_node(3, acc, section_hashes[i])?;
    }
    Ok(acc)
}

/// Build a sparse Merkle path placing `leaf` at index 0.
///
/// All `depth` siblings are zero-subtree hashes from `zeros`.  The path indices
/// are all 0 (leaf is always the left child at every level), so the integer
/// reconstruction `Σ indices[k] * 2^k` gives `leafIndex = 0`.
///
/// Returns `(root, path_elements, path_indices)`.
fn sparse_path_at_index_zero(
    leaf: Fr,
    zeros: &[Fr],
    depth: usize,
) -> (Fr, Vec<Fr>, Vec<u8>) {
    let path_elements: Vec<Fr> = (0..depth).map(|i| zeros[i]).collect();
    let path_indices = vec![0u8; depth];
    let root = compute_merkle_root(leaf, &path_elements, &path_indices, 1)
        .expect("sparse_path_at_index_zero: compute_merkle_root");
    (root, path_elements, path_indices)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn prove_and_verify_unified_roundtrip() {
    let Some((wasm, r1cs, ark_zkey, vkey_path)) = artifacts() else {
        eprintln!("[skip] unified artifacts missing — run `bash proofs/setup_circuits.sh` first");
        return;
    };

    let verifier = CircuitVerifier::from_file(&vkey_path)
        .expect("vkey JSON should parse once the file exists");

    // --- Section data (representative small fixture) ---
    // sectionCount = 2; two real sections, six zero-padded slots.
    let section_count: u64 = 2;
    let section_lengths: [u64; MAX_SECTIONS] = [42, 87, 0, 0, 0, 0, 0, 0];
    // section_hashes are BLAKE3-of-section reduced into Fr.  For the fixture
    // we use small deterministic field elements (the circuit constrains the
    // chain output, not the individual hash values).
    let section_hashes: [Fr; MAX_SECTIONS] = [
        Fr::from(0xBEEF_0001_u64),
        Fr::from(0xBEEF_0002_u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ];
    // documentSections are private inputs the circuit receives but does not
    // further constrain against sectionHashes (the hash is pre-supplied).
    let document_sections: Vec<Fr> = (0..MAX_SECTIONS as u64)
        .map(|i| Fr::from(i * 0x1000))
        .collect();

    // --- Component 1: canonicalHash ---
    let canonical_hash = compute_canonical_hash(section_count, &section_lengths, &section_hashes)
        .expect("compute_canonical_hash");

    // Precompute zero subtree hashes once; reuse for both depths.
    let zeros = precompute_zero_hashes(SMT_DEPTH);

    // --- Component 2: Poseidon Merkle inclusion (depth 20) ---
    // canonical_hash is the leaf at index 0.
    let (merkle_root, merkle_path, merkle_indices) =
        sparse_path_at_index_zero(canonical_hash, &zeros, MERKLE_DEPTH);
    let leaf_index: u64 = 0; // matches Σ merkle_indices[k]*2^k = 0
    let tree_size: u64 = 1;  // satisfies leafIndex (0) < treeSize (1)

    // --- Component 3: ledger SMT commitment (depth 256) ---
    // merkle_root is the leaf at index 0 in the 256-depth sparse tree.
    let (ledger_root, ledger_path_elements, ledger_path_indices) =
        sparse_path_at_index_zero(merkle_root, &zeros, SMT_DEPTH);

    // --- Baby Jubjub authority keypair + checkpoint signature ---
    // The witness still carries `checkpoint_timestamp`, the pubkey, and
    // `signature` because `sign_checkpoint` + federation's off-circuit
    // verifier use them. They are NOT pushed to ark-circom anymore —
    // `circom_inputs()` only emits the signals the circuit declares
    // (audit C-1).
    let priv_key = [0x42_u8; 32];
    let checkpoint_timestamp = 1_700_000_000_u64;
    let pubkey = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey derive");
    let signature = UnifiedWitness::sign_checkpoint(&priv_key, ledger_root, checkpoint_timestamp)
        .expect("sign_checkpoint");

    // --- Build and validate the witness struct ---
    let witness = UnifiedWitness::new(
        canonical_hash,
        merkle_root,
        ledger_root,
        tree_size,
        checkpoint_timestamp,
        pubkey,
        document_sections,
        section_count,
        section_lengths.to_vec(),
        section_hashes.to_vec(),
        merkle_path,
        merkle_indices,
        leaf_index,
        ledger_path_elements,
        ledger_path_indices,
        signature,
    )
    .expect("UnifiedWitness::new: fixture should satisfy all structural checks");

    // authorityPubKeyHash consistency. The circuit itself does NOT bind
    // authority identity (audit C-1 — no in-circuit EdDSAPoseidonVerifier;
    // authorityPubKeyHash is not a circuit signal). This assertion is a
    // fixture sanity check that the witness's stored hash matches
    // Poseidon(Ax, Ay) — the off-circuit federation verifier
    // (`federation::verify::verify_checkpoint_signature`) is what actually
    // ties a signature back to the authority pubkey.
    assert_eq!(
        witness.authority_pubkey_hash,
        pubkey.authority_hash().expect("authority_hash"),
        "authority_pubkey_hash must match Poseidon(Ax, Ay)"
    );

    // --- Prove + verify ---
    // `circom_inputs()` now emits only signals the circuit declares
    // (audit C-1); the prove path is no longer relying on ark-circom
    // silently discarding "unknown signal" pushes.
    let (proof, public_inputs) =
        prove_unified(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_unified");

    let ok = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify_proof");
    assert!(ok, "Groth16 verification failed for unified circuit");
}
