// Pure-Rust in-process prover / verifier stack (Phase 4B — no Node required).
// The Phase 4A Node.js sidecar (`bridge.rs`) was retired: it was never wired
// into any live HTTP handler or Tauri command and retained a `Command::new(
// node_bin)` shell-exec surface for no benefit. Audit finding F-9.
pub mod chunk;
pub mod field_validation;
pub mod manifest;
pub mod pedersen;
pub mod poseidon;
pub mod proof;
pub mod prove;
pub mod snapshot;
pub mod verify;
pub mod vkey;
pub mod witness;
pub mod zkey;

use std::path::{Path, PathBuf};

/// The five supported ZK proof circuits.
///
/// `wasm_path` / `r1cs_path` / `ark_zkey_path` are used by the in-process
/// Rust prover.  `zkey_path` / `vkey_path` are used by the Node bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Circuit {
    DocumentExistence,
    NonExistence,
    RedactionValidity,
    UnifiedCanonicalizationInclusionRootSign,
    /// Federation M-of-N quorum proof — see `proofs/circuits/federation_quorum.circom`.
    FederationQuorum,
}

impl Circuit {
    /// Circuit name as used in file-name conventions.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DocumentExistence => "document_existence",
            Self::NonExistence => "non_existence",
            Self::RedactionValidity => "redaction_validity",
            Self::UnifiedCanonicalizationInclusionRootSign => {
                "unified_canonicalization_inclusion_root_sign"
            }
            Self::FederationQuorum => "federation_quorum",
        }
    }

    /// WASM witness-generator file (used by both bridge and in-process prover).
    pub fn wasm_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.wasm", self.name()))
    }

    /// R1CS constraint file (used by in-process prover via ark-circom).
    pub fn r1cs_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.r1cs", self.name()))
    }

    /// snarkjs `.zkey` proving key (used by Node bridge).
    pub fn zkey_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.zkey", self.name()))
    }

    /// arkworks-serialized proving key (used by in-process prover).
    pub fn ark_zkey_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.ark.zkey", self.name()))
    }

    /// Groth16 verification key JSON (used by both bridge and in-process verifier).
    pub fn vkey_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir
            .join("verification_keys")
            .join(format!("{}_vkey.json", self.name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn circuit_paths_document_existence() {
        let base = Path::new("/proofs/keys");
        let c = Circuit::DocumentExistence;
        assert_eq!(c.wasm_path(base), Path::new("/proofs/keys/document_existence.wasm"));
        assert_eq!(c.r1cs_path(base), Path::new("/proofs/keys/document_existence.r1cs"));
        assert_eq!(c.ark_zkey_path(base), Path::new("/proofs/keys/document_existence.ark.zkey"));
        assert_eq!(
            c.vkey_path(base),
            Path::new("/proofs/keys/verification_keys/document_existence_vkey.json")
        );
    }

    #[test]
    fn circuit_paths_unified() {
        let base = Path::new("/keys");
        let c = Circuit::UnifiedCanonicalizationInclusionRootSign;
        assert!(c
            .wasm_path(base)
            .to_string_lossy()
            .contains("unified_canonicalization_inclusion_root_sign"));
    }

    #[test]
    fn all_circuits_have_distinct_names() {
        let circuits = [
            Circuit::DocumentExistence,
            Circuit::NonExistence,
            Circuit::RedactionValidity,
            Circuit::UnifiedCanonicalizationInclusionRootSign,
            Circuit::FederationQuorum,
        ];
        let names: Vec<&str> = circuits.iter().map(|c| c.name()).collect();
        let deduped: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), deduped.len(), "circuit names must be unique");
    }
}
