use std::path::Path;

pub enum IntegrityStatus {
    Valid,
    Invalid { reason: String },
}

/// Verify the integrity of a single document file.
/// Phase 2: wire to olympus-crypto for BLAKE3/SMT proof verification.
pub fn verify_single(path: &Path) -> IntegrityStatus {
    if !path.exists() {
        return IntegrityStatus::Invalid {
            reason: format!("file not found: {}", path.display()),
        };
    }
    // Conservative until Phase 2 wires real SMT inclusion proof verification.
    IntegrityStatus::Invalid {
        reason: "integrity verification not yet implemented".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_path_returns_invalid() {
        let status = verify_single(Path::new("nonexistent.json"));
        assert!(matches!(status, IntegrityStatus::Invalid { .. }));
    }
}
