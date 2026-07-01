//! Canonical parsing for process environment mode.
//!
//! `OLYMPUS_ENV` controls production-only fail-closed gates. Treat an
//! explicitly malformed value as production rather than silently weakening
//! startup, artifact, CORS, or verifier policy.

#[derive(Debug, Clone, PartialEq, Eq)]
enum OlympusEnv {
    Unset,
    Invalid,
    Value(String),
}

fn normalize_olympus_env(raw: Result<String, std::env::VarError>) -> OlympusEnv {
    match raw {
        Ok(v) => OlympusEnv::Value(v.trim().to_ascii_lowercase()),
        Err(std::env::VarError::NotPresent) => OlympusEnv::Unset,
        Err(std::env::VarError::NotUnicode(_)) => OlympusEnv::Invalid,
    }
}

fn normalized_olympus_env() -> OlympusEnv {
    normalize_olympus_env(std::env::var("OLYMPUS_ENV"))
}

/// True when the process must enforce production-only gates.
///
/// Unset, explicit empty, `prod`, and unknown values fail closed to production
/// behavior. Local development must set `OLYMPUS_ENV=development`.
pub(crate) fn is_production() -> bool {
    match normalized_olympus_env() {
        OlympusEnv::Unset => true,
        OlympusEnv::Invalid => {
            tracing::warn!(
                "OLYMPUS_ENV is not valid Unicode; treating as production for fail-closed gates"
            );
            true
        }
        OlympusEnv::Value(v) if matches!(v.as_str(), "production" | "prod") => true,
        OlympusEnv::Value(v) if matches!(v.as_str(), "development" | "dev" | "test") => false,
        OlympusEnv::Value(v) if v.is_empty() => true,
        OlympusEnv::Value(other) => {
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
        normalized_olympus_env(),
        OlympusEnv::Value(v) if matches!(v.as_str(), "development" | "dev")
    )
}

#[cfg(test)]
mod tests {
    use super::{is_development, is_production, normalize_olympus_env, OlympusEnv};

    struct EnvRestore {
        old: Option<String>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.old.take() {
                Some(v) => std::env::set_var("OLYMPUS_ENV", v),
                None => std::env::remove_var("OLYMPUS_ENV"),
            }
        }
    }

    fn with_env(value: Option<&str>, f: impl FnOnce()) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().expect("env test lock poisoned");
        let old = std::env::var("OLYMPUS_ENV").ok();
        let _restore = EnvRestore { old };
        match value {
            Some(v) => std::env::set_var("OLYMPUS_ENV", v),
            None => std::env::remove_var("OLYMPUS_ENV"),
        }
        f();
    }

    #[test]
    fn unset_env_fails_closed_to_production() {
        with_env(None, || {
            assert!(is_production());
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

    #[test]
    fn non_unicode_env_fails_closed() {
        let raw = Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "not-valid-for-olympus",
        )));
        assert_eq!(normalize_olympus_env(raw), OlympusEnv::Invalid);
    }
}
