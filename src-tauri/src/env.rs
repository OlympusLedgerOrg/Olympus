//! Canonical parsing for process environment mode.
//!
//! `OLYMPUS_ENV` controls production-only fail-closed gates. Treat an
//! explicitly malformed value as production rather than silently weakening
//! startup, artifact, CORS, or verifier policy.
//!
//! The one exception is the build-time [`ReleaseChannel`]: a `preview` build
//! resolves an *absent or unparseable* `OLYMPUS_ENV` to development instead of
//! production. See [`ReleaseChannel::default_is_production`] for why, and note
//! that an **explicit** `OLYMPUS_ENV=production` is production on every
//! channel — that property is what keeps a preview binary from being usable as
//! a production node, and it is asserted by
//! `preview_channel_keeps_explicit_production_production` below.

/// Which release channel this binary was built for, stamped by `build.rs` from
/// `OLYMPUS_RELEASE_CHANNEL` (docs/plans/preview-release-channel.md §D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseChannel {
    /// Every ordinary build, every CI job, and every `v*` production tag.
    Stable,
    /// Publicly downloadable preview builds, produced from a single-contributor
    /// development ceremony by `.github/workflows/tauri-preview.yml`.
    Preview,
}

impl ReleaseChannel {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ReleaseChannel::Stable => "stable",
            ReleaseChannel::Preview => "preview",
        }
    }

    /// What an absent, empty, non-Unicode, or unrecognised `OLYMPUS_ENV`
    /// resolves to on this channel.
    ///
    /// `Stable` keeps the historical fail-closed answer: no environment means
    /// production, so a misconfigured deployment refuses to start rather than
    /// quietly running with development gates disabled.
    ///
    /// `Preview` inverts **only this default**. A preview installer is
    /// downloaded and double-clicked by people who will never set an
    /// environment variable, and under the stable default that process
    /// `exit(2)`s in the Tauri setup hook before Axum binds — no window, no
    /// error surface. There is also nothing for a preview build to fail closed
    /// *about*: it is built from an `olympus-dev-*` ceremony, so an operator
    /// who does set `OLYMPUS_ENV=production` on one still gets `exit(2)` from
    /// the A-4 gate in `startup.rs`.
    ///
    /// Note what this deliberately does **not** do: it does not make
    /// [`is_development`] true. A preview build with no environment is neither
    /// production nor development, so the production hard-gates are lifted
    /// (the app starts) while the development conveniences stay off — no Vite
    /// dev CORS origins, no recovery-token echo, no dev signing-key bootstrap
    /// path. Those are opt-in via an explicit `OLYMPUS_ENV=development`.
    const fn default_is_production(self) -> bool {
        match self {
            ReleaseChannel::Stable => true,
            ReleaseChannel::Preview => false,
        }
    }
}

/// Build-time channel name. `build.rs` validates it is exactly `stable` or
/// `preview` before stamping, so the fallback arm in [`release_channel`] is
/// unreachable in practice — it exists so that any future drift resolves
/// toward the fail-closed channel rather than away from it.
pub(crate) const RELEASE_CHANNEL_NAME: &str = env!("OLYMPUS_RELEASE_CHANNEL");

/// Which preview this binary is (e.g. `preview-v0.10.0-rc.1`), or empty on
/// `stable` and on unlabelled preview builds from `workflow_dispatch`.
pub(crate) const PREVIEW_TAG: &str = env!("OLYMPUS_PREVIEW_TAG");

pub(crate) fn release_channel() -> ReleaseChannel {
    match RELEASE_CHANNEL_NAME {
        "preview" => ReleaseChannel::Preview,
        _ => ReleaseChannel::Stable,
    }
}

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
/// Unset, explicit empty, and unknown values resolve to the channel's default
/// ([`ReleaseChannel::default_is_production`]) — production on `stable`,
/// development on `preview`. `production` and `prod` are production on every
/// channel. Local development must set `OLYMPUS_ENV=development`.
pub(crate) fn is_production() -> bool {
    is_production_on(release_channel(), normalized_olympus_env())
}

/// [`is_production`] with the channel and parsed environment injected, so both
/// channels are exercisable from a single ordinary `cargo test` run rather than
/// only from a binary rebuilt with `OLYMPUS_RELEASE_CHANNEL=preview`.
fn is_production_on(channel: ReleaseChannel, env: OlympusEnv) -> bool {
    match env {
        OlympusEnv::Unset => channel.default_is_production(),
        OlympusEnv::Invalid => {
            tracing::warn!(
                "OLYMPUS_ENV is not valid Unicode; resolving to the {} channel default \
                 (production={})",
                channel.as_str(),
                channel.default_is_production()
            );
            channel.default_is_production()
        }
        OlympusEnv::Value(ref v) if matches!(v.as_str(), "production" | "prod") => true,
        OlympusEnv::Value(ref v) if matches!(v.as_str(), "development" | "dev" | "test") => false,
        OlympusEnv::Value(ref v) if v.is_empty() => channel.default_is_production(),
        OlympusEnv::Value(other) => {
            tracing::warn!(
                "unrecognised OLYMPUS_ENV={other:?}; resolving to the {} channel default \
                 (production={})",
                channel.as_str(),
                channel.default_is_production()
            );
            channel.default_is_production()
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
pub(crate) struct OlympusEnvTestGuard {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    old: Option<String>,
}

#[cfg(test)]
impl Drop for OlympusEnvTestGuard {
    fn drop(&mut self) {
        match self.old.take() {
            Some(v) => std::env::set_var("OLYMPUS_ENV", v),
            None => std::env::remove_var("OLYMPUS_ENV"),
        }
    }
}

#[cfg(test)]
static OLYMPUS_ENV_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) async fn with_olympus_env(value: Option<&str>) -> OlympusEnvTestGuard {
    let guard = OLYMPUS_ENV_TEST_LOCK.lock().await;
    let old = std::env::var("OLYMPUS_ENV").ok();
    match value {
        Some(v) => std::env::set_var("OLYMPUS_ENV", v),
        None => std::env::remove_var("OLYMPUS_ENV"),
    }
    OlympusEnvTestGuard { _guard: guard, old }
}

#[cfg(test)]
mod tests {
    use super::{
        is_development, is_production, is_production_on, normalize_olympus_env, release_channel,
        with_olympus_env, OlympusEnv, ReleaseChannel, PREVIEW_TAG, RELEASE_CHANNEL_NAME,
    };

    async fn with_env(value: Option<&str>, f: impl FnOnce()) {
        let _env = with_olympus_env(value).await;
        f();
    }

    #[tokio::test]
    async fn unset_env_fails_closed_to_production() {
        with_env(None, || {
            assert!(is_production());
            assert!(!is_development());
        })
        .await;
    }

    #[tokio::test]
    async fn trims_and_accepts_prod_alias() {
        with_env(Some(" production "), || assert!(is_production())).await;
        with_env(Some("prod"), || assert!(is_production())).await;
    }

    #[tokio::test]
    async fn explicit_development_is_development() {
        with_env(Some(" development "), || {
            assert!(!is_production());
            assert!(is_development());
        })
        .await;
    }

    #[tokio::test]
    async fn unknown_or_empty_env_fails_closed() {
        with_env(Some(""), || assert!(is_production())).await;
        with_env(Some("staging"), || assert!(is_production())).await;
    }

    #[test]
    fn non_unicode_env_fails_closed() {
        let raw = Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "not-valid-for-olympus",
        )));
        assert_eq!(normalize_olympus_env(raw), OlympusEnv::Invalid);
    }

    // ── Release channel (docs/plans/preview-release-channel.md §9) ──────────

    /// T3: the channel stamp defaults to `stable`, so an ordinary developer
    /// build and every `v*` tag build keep the historical fail-closed default.
    /// If this fails, `OLYMPUS_RELEASE_CHANNEL` leaked into a build that should
    /// not have it — which would silently disable the production secret gates.
    #[test]
    fn release_channel_defaults_to_stable() {
        assert_eq!(
            RELEASE_CHANNEL_NAME, "stable",
            "this build was stamped with OLYMPUS_RELEASE_CHANNEL={RELEASE_CHANNEL_NAME:?}; \
             only .github/workflows/tauri-preview.yml may set it"
        );
        assert_eq!(release_channel(), ReleaseChannel::Stable);
        assert!(
            PREVIEW_TAG.is_empty(),
            "a stable build must carry no preview tag, got {PREVIEW_TAG:?}"
        );
    }

    /// T2 / hard constraint: an **explicit** `OLYMPUS_ENV=production` is
    /// production on the preview channel too. This is what makes shipping
    /// preview installers safe — such a binary carries an `olympus-dev-*`
    /// ceremony, so reaching production mode means reaching the A-4 gate in
    /// `startup.rs::apply_extra_prod_gates` and exiting 2. Deleting the
    /// preview arm's production handling would break this test.
    #[test]
    fn preview_channel_keeps_explicit_production_production() {
        for value in ["production", "prod"] {
            assert!(
                is_production_on(ReleaseChannel::Preview, OlympusEnv::Value(value.to_owned())),
                "OLYMPUS_ENV={value} must stay production on the preview channel"
            );
        }
    }

    /// The whole point of the channel: with no environment at all, a preview
    /// build starts instead of exiting 2 at the four-secret gate.
    #[test]
    fn preview_channel_defaults_to_development() {
        assert!(!is_production_on(
            ReleaseChannel::Preview,
            OlympusEnv::Unset
        ));
        assert!(!is_production_on(
            ReleaseChannel::Preview,
            OlympusEnv::Value(String::new())
        ));
        assert!(!is_production_on(
            ReleaseChannel::Preview,
            OlympusEnv::Invalid
        ));
        assert!(!is_production_on(
            ReleaseChannel::Preview,
            OlympusEnv::Value("staging".to_owned())
        ));
    }

    /// The stable channel's defaults are untouched by the channel refactor —
    /// asserted against `is_production_on` directly so this holds regardless of
    /// how the running test binary happened to be stamped.
    #[test]
    fn stable_channel_defaults_are_unchanged() {
        for env in [
            OlympusEnv::Unset,
            OlympusEnv::Invalid,
            OlympusEnv::Value(String::new()),
            OlympusEnv::Value("staging".to_owned()),
            OlympusEnv::Value("production".to_owned()),
            OlympusEnv::Value("prod".to_owned()),
        ] {
            assert!(
                is_production_on(ReleaseChannel::Stable, env.clone()),
                "stable must treat {env:?} as production"
            );
        }
        for env in [
            OlympusEnv::Value("development".to_owned()),
            OlympusEnv::Value("dev".to_owned()),
            OlympusEnv::Value("test".to_owned()),
        ] {
            assert!(
                !is_production_on(ReleaseChannel::Stable, env.clone()),
                "stable must treat {env:?} as development"
            );
        }
    }

    /// A preview build with no environment must be neither production nor
    /// development: production hard-gates lift so the app starts, development
    /// conveniences (Vite dev CORS origins in `server/mod.rs`, the
    /// recovery-token echo in `api/user_auth/recovery.rs`) stay off.
    #[tokio::test]
    async fn unset_env_is_not_development_on_any_channel() {
        with_env(None, || {
            assert!(!is_development());
        })
        .await;
        assert!(!is_production_on(
            ReleaseChannel::Preview,
            OlympusEnv::Unset
        ));
    }
}
