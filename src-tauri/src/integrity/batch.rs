use std::path::Path;

/// Outcome of a batch integrity check.
///
/// Invariant: `valid + invalid + unverified == total`. The `unverified` bucket
/// exists so that a check which was skipped or is not yet implemented is never
/// misreported as `invalid` (audit finding 4) — "could not be checked" is a
/// distinct state from "checked and failed", and conflating them tells a caller
/// every document is bad when in fact none were examined.
pub struct BatchIntegrityResult {
    pub total: usize,
    pub valid: usize,
    pub invalid: usize,
    pub unverified: usize,
}

/// Verify integrity of a batch of document files.
///
/// NOT YET IMPLEMENTED: real SMT inclusion-proof verification is pending
/// (Phase 2 — wire to `olympus-crypto`). Until then every path is reported as
/// `unverified` (never `invalid`), so no caller mistakes "unimplemented" for
/// "all documents failed verification".
pub fn verify_batch(paths: &[&Path]) -> BatchIntegrityResult {
    BatchIntegrityResult {
        total: paths.len(),
        valid: 0,
        invalid: 0,
        unverified: paths.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_batch_has_no_entries() {
        let result = verify_batch(&[]);
        assert_eq!(result.total, 0);
        assert_eq!(result.valid, 0);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.unverified, 0);
    }

    #[test]
    fn unimplemented_check_reports_unverified_not_invalid() {
        let paths: Vec<std::path::PathBuf> = ["a.json", "b.json"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect();
        let path_refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
        let result = verify_batch(&path_refs);
        assert_eq!(result.total, 2);
        // The regression this guards: the stub must NOT mark anything invalid.
        assert_eq!(result.invalid, 0);
        assert_eq!(result.unverified, 2);
        assert_eq!(
            result.valid + result.invalid + result.unverified,
            result.total
        );
    }
}
