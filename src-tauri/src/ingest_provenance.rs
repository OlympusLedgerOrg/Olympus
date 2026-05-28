//! Ingest parser provenance (ADR-0003 / ADR-0004).
//!
//! The leaf hash binds three provenance fields — `parser_id`,
//! `canonical_parser_version`, and `model_hash` — so the ledger records which
//! parser (and which model artifact) produced each committed value. This
//! module resolves those fields from environment once at startup; the ingest
//! path stamps every leaf it commits into the parser-bound SMT with the
//! resolved triple.
//!
//! All three fields MUST be non-empty: the canonical `olympus_crypto::leaf_hash`
//! domain and the SMT write path both require it, so a blank value could never
//! reproduce a verifiable leaf. Blank/whitespace env values fall back to the
//! defaults rather than being accepted.

/// Default parser identity when none is configured. Matches the ADR-0003
/// fallback-parser convention (`"<name>@<version>"`).
pub const DEFAULT_PARSER_ID: &str = "fallback@1.0.0";
/// Default canonical parser version (ADR-0003).
pub const DEFAULT_CANONICAL_PARSER_VERSION: &str = "v1";
/// Default model hash sentinel when no model artifact is declared (ADR-0004).
pub const DEFAULT_MODEL_HASH: &str = "none";

/// Resolved, always-non-empty provenance triple stamped onto committed leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestProvenance {
    pub parser_id: String,
    pub canonical_parser_version: String,
    pub model_hash: String,
}

impl Default for IngestProvenance {
    fn default() -> Self {
        Self {
            parser_id: DEFAULT_PARSER_ID.to_string(),
            canonical_parser_version: DEFAULT_CANONICAL_PARSER_VERSION.to_string(),
            model_hash: DEFAULT_MODEL_HASH.to_string(),
        }
    }
}

impl IngestProvenance {
    /// Resolve provenance from the environment:
    /// - `OLYMPUS_INGEST_PARSER_ID` (default `fallback@1.0.0`)
    /// - `INGEST_PARSER_CANONICAL_VERSION` (default `v1`) — the variable named
    ///   in ADR-0003.
    /// - `OLYMPUS_INGEST_MODEL_HASH` (default `none`) — ADR-0004.
    ///
    /// A missing, empty, or whitespace-only value falls back to the default.
    pub fn from_env() -> Self {
        Self {
            parser_id: resolve("OLYMPUS_INGEST_PARSER_ID", DEFAULT_PARSER_ID),
            canonical_parser_version: resolve(
                "INGEST_PARSER_CANONICAL_VERSION",
                DEFAULT_CANONICAL_PARSER_VERSION,
            ),
            model_hash: resolve("OLYMPUS_INGEST_MODEL_HASH", DEFAULT_MODEL_HASH),
        }
    }
}

/// Read `var`, trim it, and return it if non-empty; otherwise `default`.
fn resolve(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_nonempty() {
        let p = IngestProvenance::default();
        assert!(!p.parser_id.is_empty());
        assert!(!p.canonical_parser_version.is_empty());
        assert!(!p.model_hash.is_empty());
        assert_eq!(p.parser_id, DEFAULT_PARSER_ID);
        assert_eq!(p.canonical_parser_version, DEFAULT_CANONICAL_PARSER_VERSION);
        assert_eq!(p.model_hash, DEFAULT_MODEL_HASH);
    }

    #[test]
    fn resolve_trims_and_falls_back() {
        // Use a process-unique var name to avoid cross-test env races.
        let var = "OLYMPUS_TEST_PROV_RESOLVE";
        std::env::remove_var(var);
        assert_eq!(resolve(var, "d"), "d", "missing → default");

        std::env::set_var(var, "   ");
        assert_eq!(resolve(var, "d"), "d", "whitespace-only → default");

        std::env::set_var(var, "  docling@2.3.1  ");
        assert_eq!(resolve(var, "d"), "docling@2.3.1", "trimmed value wins");

        std::env::remove_var(var);
    }
}
