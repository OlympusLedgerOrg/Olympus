pub mod bridge;
pub use bridge::{Proof, ProveResult, ZkBridge, ZkBridgeError};

use std::path::{Path, PathBuf};

/// The four supported ZK proof circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Circuit {
    DocumentExistence,
    NonExistence,
    RedactionValidity,
    UnifiedCanonicalizationInclusionRootSign,
}

impl Circuit {
    /// Absolute path to the circuit WASM witness-generator file.
    pub fn wasm_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.wasm", self.name()))
    }

    /// Absolute path to the Groth16 proving key (.zkey).
    pub fn zkey_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir.join(format!("{}.zkey", self.name()))
    }

    /// Absolute path to the Groth16 verification key JSON.
    pub fn vkey_path(&self, keys_dir: &Path) -> PathBuf {
        keys_dir
            .join("verification_keys")
            .join(format!("{}_vkey.json", self.name()))
    }

    fn name(&self) -> &'static str {
        match self {
            Self::DocumentExistence => "document_existence",
            Self::NonExistence => "non_existence",
            Self::RedactionValidity => "redaction_validity",
            Self::UnifiedCanonicalizationInclusionRootSign => {
                "unified_canonicalization_inclusion_root_sign"
            }
        }
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
        assert_eq!(c.zkey_path(base), Path::new("/proofs/keys/document_existence.zkey"));
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
        ];
        let names: Vec<&str> = circuits.iter().map(|c| c.name()).collect();
        let deduped: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), deduped.len(), "circuit names must be unique");
    }
}
