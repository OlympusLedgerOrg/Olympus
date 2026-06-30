//! Canonical parsing for process environment mode.
//!
//! `OLYMPUS_ENV` controls production-only fail-closed gates. Treat an
//! explicitly malformed value as production rather than silently weakening
//! startup, artifact, CORS, or verifier policy.

fn normalized_olympus_env() -> Option<String> {
    std::env::var("OLYMPUS_ENV")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
}

/// True when the process must enforce production-only gates.
///
/// Unset keeps the historical local-dev default. Explicit empty, `prod`, and
/// unknown values fail closed to production behavior.
pub(crate) fn is_production() -> bool {
    match normalized_olympus_env().as_deref() {
        None => false,
        Some("production" | "prod") => true,
        Some("development" | "dev" | "test") => false,
        Some("") => true,
        Some(other) => {
            tracing::warn!(
                "unrecognised OLYMPUS_ENV={other:?}; treating as production for fail-closed gates"
            );
            true
        }
    }
}

/// True only for an explicit development mode.
pub(crate) fn is_development() -> bool {
    matches!(
        normalized_olympus_env().as_deref(),
        Some("development" | "dev")
    )
}

#[cfg(test)]
mod tests {
    use super::{is_development, is_production};

    fn with_env(value: Option<&str>, f: impl FnOnce()) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().expect("env test lock poisoned");
        let old = std::env::var("OLYMPUS_ENV").ok();
        match value {
            Some(v) => std::env::set_var("OLYMPUS_ENV", v),
            None => std::env::remove_var("OLYMPUS_ENV"),
        }
        f();
        match old {
            Some(v) => std::env::set_var("OLYMPUS_ENV", v),
            None => std::env::remove_var("OLYMPUS_ENV"),
        }
    }

    #[test]
    fn unset_env_is_non_production_for_local_dev() {
        with_env(None, || {
            assert!(!is_production());
            assert!(!is_development());
        });
    }

    #[test]
    fn trims_and_accepts_prod_alias() {
        with_env(Some(" production "), || assert!(is_production()));
        with_env(Some("prod"), || assert!(is_production()));
    }

    #[test]
    fn explicit_development_is_development() {
        with_env(Some(" development "), || {
            assert!(!is_production());
            assert!(is_development());
        });
    }

    #[test]
    fn unknown_or_empty_env_fails_closed() {
        with_env(Some(""), || assert!(is_production()));
        with_env(Some("staging"), || assert!(is_production()));
    }
}
