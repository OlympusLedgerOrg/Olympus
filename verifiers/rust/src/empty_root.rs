//! Audit H-2 / red-team **OLY-H3**: off-chain enforcement of the
//! `document_existence` / unified circuits' `treeSize == 0` empty-root
//! invariant.
//!
//! Both circuits disable their in-circuit `leafIndex < treeSize` bounds check
//! when `treeSize == 0` (`proofs/circuits/document_existence.circom`). The
//! circuit docstring delegates the missing check to off-chain verifiers: they
//! MUST reject a `treeSize == 0` proof unless `root` equals the known
//! empty-tree root. The desktop server enforces this
//! (`olympus_desktop::zk::verify::enforce_empty_tree_invariant`) and so does
//! the canonicalization path in this crate — but the `verify` CLI, which
//! `docs/court-evidence.md` tells a court to trust *instead of* the Olympus
//! runtime, did not. A prover could build a private tree, take an honest proof
//! for `[arbitrary_root, leafIndex, treeSize=0]`, and have the court tool
//! accept an inclusion claim the server rejects.
//!
//! This module is the single owner of the empty-root computation for the whole
//! verifier crate; `canonicalization.rs` consumes it rather than keeping its
//! own copy, so the two paths cannot drift apart.

use ark_bn254::Fr;
use ark_ff::Zero;
use light_poseidon::{Poseidon, PoseidonHasher};

/// Internal-node domain tag — audit L-4 NODE=2 split. Must equal
/// `olympus_crypto::poseidon::DOMAIN_NODE` and the `2` the redaction fold uses
/// (`redaction.rs::variable_depth_fold`).
pub const MERKLE_NODE_DOMAIN: u64 = 2;

/// Merkle depth of the `document_existence` / unified circuits
/// (`MerkleTreeInclusionProof(20)`).
pub const DOCUMENT_MERKLE_DEPTH: usize = 20;

/// Why an empty-tree check could not be completed or did not hold.
#[derive(Debug, PartialEq, Eq)]
pub enum EmptyRootError {
    /// `treeSize == 0` but `root` is not the empty-tree root — the OLY-H3
    /// forgery shape.
    EmptyTreeMismatch,
    /// The public-signal vector is too short for the circuit's known layout.
    /// Fail-closed: never silently skip the check.
    MissingSignal {
        circuit: &'static str,
        index: usize,
        len: usize,
    },
    /// Poseidon failed to hash (cannot occur for fixed arity 2 in practice).
    Poseidon(String),
}

impl std::fmt::Display for EmptyRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTreeMismatch => write!(
                f,
                "treeSize=0 requires root == the depth-{DOCUMENT_MERKLE_DEPTH} empty-tree root \
                 (audit H-2 / OLY-H3): refusing an inclusion proof against a non-empty root"
            ),
            Self::MissingSignal {
                circuit,
                index,
                len,
            } => write!(
                f,
                "circuit `{circuit}` needs public signal {index} for the treeSize=0 check but \
                 only {len} signals were supplied"
            ),
            Self::Poseidon(error) => write!(f, "Poseidon error: {error}"),
        }
    }
}

impl std::error::Error for EmptyRootError {}

fn poseidon2(a: Fr, b: Fr) -> Result<Fr, EmptyRootError> {
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|error| EmptyRootError::Poseidon(error.to_string()))?;
    hasher
        .hash(&[a, b])
        .map_err(|error| EmptyRootError::Poseidon(error.to_string()))
}

/// `DomainPoseidonNode(d, l, r) = Poseidon(Poseidon(d, l), r)`.
fn domain_node(domain: u64, left: Fr, right: Fr) -> Result<Fr, EmptyRootError> {
    let inner = poseidon2(Fr::from(domain), left)?;
    poseidon2(inner, right)
}

/// Empty-tree root for a fully-empty Poseidon SMT of the given `depth`
/// (empty-leaf sentinel `Fr(0)`, internal-node domain [`MERKLE_NODE_DOMAIN`]).
pub fn empty_tree_root(depth: usize) -> Result<Fr, EmptyRootError> {
    let mut root = Fr::zero();
    for _ in 0..depth {
        root = domain_node(MERKLE_NODE_DOMAIN, root, root)?;
    }
    Ok(root)
}

/// The depth-20 empty-tree root for `document_existence` / unified.
pub fn empty_document_merkle_root() -> Result<Fr, EmptyRootError> {
    empty_tree_root(DOCUMENT_MERKLE_DEPTH)
}

/// Public-signal `(root_idx, tree_size_idx)` for circuits that expose
/// `treeSize`, or `None` for circuits with no `treeSize` signal.
///
/// MUST stay in lockstep with the desktop call sites in
/// `olympus_desktop::api::zk`: `document_existence` exposes
/// `[root, leafIndex, treeSize]`; the unified R1CS binds the bounds check to
/// its `merkleRoot` in `[canonicalHash, merkleRoot, ledgerRoot, treeSize,
/// ledgerKeyHash]`.
pub fn treesize_layout(circuit: &str) -> Option<(usize, usize)> {
    match circuit {
        "document_existence" => Some((0, 2)),
        // The live narrower statement and its retired historical identifier
        // share one R1CS and therefore one signal layout.
        "unified_section_commitment_inclusion_root"
        | "unified_canonicalization_inclusion_root_sign" => Some((1, 3)),
        // `non_existence` exposes no treeSize signal — nothing to enforce.
        _ => None,
    }
}

/// Reject `treeSize == 0` unless the circuit's root signal equals the
/// empty-tree root. A no-op for circuits without a `treeSize` signal; an error
/// (never a silent skip) if a circuit that *does* have one supplied too few
/// signals.
pub fn enforce_empty_tree_invariant(circuit: &str, signals: &[Fr]) -> Result<(), EmptyRootError> {
    let Some((root_idx, tree_size_idx)) = treesize_layout(circuit) else {
        return Ok(());
    };
    let missing = |index: usize| EmptyRootError::MissingSignal {
        circuit: if circuit == "document_existence" {
            "document_existence"
        } else {
            "unified"
        },
        index,
        len: signals.len(),
    };
    let tree_size = signals
        .get(tree_size_idx)
        .ok_or_else(|| missing(tree_size_idx))?;
    if !tree_size.is_zero() {
        return Ok(());
    }
    let root = signals.get(root_idx).ok_or_else(|| missing(root_idx))?;
    if *root != empty_document_merkle_root()? {
        return Err(EmptyRootError::EmptyTreeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The depth-20 empty root is a cross-language pinned value: the same
    /// constant the JavaScript verifier and the desktop server compute.
    #[test]
    fn pinned_h2_empty_root_matches_javascript_vector() {
        assert_eq!(
            empty_document_merkle_root().unwrap().to_string(),
            "15844545496281054012514088872996878997832991608828444956951187238677813598466"
        );
    }

    #[test]
    fn document_existence_rejects_empty_tree_witness_against_arbitrary_root() {
        // [root, leafIndex, treeSize] — the OLY-H3 forgery: an honest proof
        // over a privately built tree, replayed with treeSize=0.
        let forged = [Fr::from(7u64), Fr::from(3u64), Fr::from(0u64)];
        assert_eq!(
            enforce_empty_tree_invariant("document_existence", &forged),
            Err(EmptyRootError::EmptyTreeMismatch)
        );
    }

    #[test]
    fn document_existence_accepts_empty_tree_witness_against_empty_root() {
        let empty = empty_document_merkle_root().unwrap();
        let honest = [empty, Fr::from(0u64), Fr::from(0u64)];
        assert!(enforce_empty_tree_invariant("document_existence", &honest).is_ok());
    }

    #[test]
    fn document_existence_accepts_nonempty_tree_with_any_root() {
        // treeSize > 0 keeps the in-circuit bounds check, so the root is
        // unconstrained by this invariant.
        let populated = [Fr::from(7u64), Fr::from(3u64), Fr::from(9u64)];
        assert!(enforce_empty_tree_invariant("document_existence", &populated).is_ok());
    }

    #[test]
    fn unified_layout_checks_merkle_root_at_signal_one() {
        let empty = empty_document_merkle_root().unwrap();
        let accepted = [
            Fr::from(1u64),
            empty,
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(3u64),
        ];
        assert!(enforce_empty_tree_invariant(
            "unified_section_commitment_inclusion_root",
            &accepted
        )
        .is_ok());

        let mut rejected = accepted;
        rejected[1] = Fr::from(1u64);
        assert_eq!(
            enforce_empty_tree_invariant("unified_section_commitment_inclusion_root", &rejected),
            Err(EmptyRootError::EmptyTreeMismatch)
        );
    }

    #[test]
    fn circuits_without_treesize_are_a_noop() {
        assert!(enforce_empty_tree_invariant("non_existence", &[Fr::from(1u64)]).is_ok());
    }

    /// Fail-closed: a truncated signal vector must error, never skip silently.
    #[test]
    fn truncated_signals_error_rather_than_skip() {
        assert!(matches!(
            enforce_empty_tree_invariant("document_existence", &[Fr::from(1u64)]),
            Err(EmptyRootError::MissingSignal {
                index: 2,
                len: 1,
                ..
            })
        ));
    }
}
