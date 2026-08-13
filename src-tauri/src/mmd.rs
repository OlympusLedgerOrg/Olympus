// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Maximum Merge Delay (MMD) policy (ADR-0021).
//!
//! CT-style operational hardening promises that a submitted record appears
//! in a published, signed checkpoint within a bounded time. This module
//! resolves that bound from the environment once at startup; the delay
//! computation itself lives in `api::monitor::mmd` (it needs a DB pool to
//! find the first covering checkpoint, so it isn't a pure function of this
//! config alone).

/// Default MMD: 24 hours. Chosen to comfortably exceed the anchoring cron's
/// own default interval (`OLYMPUS_ANCHOR_INTERVAL_SECS`, 1 hour —
/// `anchoring::mod::AnchoringConfig`) by a wide margin, so an operator running
/// with default settings does not see spurious breaches from ordinary
/// checkpoint-cadence jitter. Operators who tighten the checkpoint interval
/// should tighten this to match.
pub const DEFAULT_MMD_SECONDS: i64 = 86_400;

/// Floor on a configured MMD. Matches the anchoring cron's own
/// `MIN_INTERVAL_SECS` floor (`anchoring::cron`) — an MMD shorter than the
/// fastest possible checkpoint cadence could never be met even by an
/// operator running checkpoints as often as physically allowed, making every
/// record a permanent, unactionable "breach."
pub const MIN_MMD_SECONDS: i64 = 60;

/// Resolved MMD policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmdPolicy {
    pub mmd_seconds: i64,
}

impl Default for MmdPolicy {
    fn default() -> Self {
        Self {
            mmd_seconds: DEFAULT_MMD_SECONDS,
        }
    }
}

impl MmdPolicy {
    /// Resolve from `OLYMPUS_MMD_SECONDS`. A missing, non-numeric, or
    /// below-floor value falls back to [`DEFAULT_MMD_SECONDS`] — a
    /// misconfigured MMD must never silently become "no policy" (e.g. `0` or
    /// negative), which would make every record an instant breach or, worse,
    /// disable the breach signal a submitter relies on.
    pub fn from_env() -> Self {
        Self {
            mmd_seconds: Self::parse(std::env::var("OLYMPUS_MMD_SECONDS").ok().as_deref()),
        }
    }

    /// Pure parsing logic behind [`Self::from_env`], taking the raw value
    /// directly so it's unit-testable without mutating the process
    /// environment — mirrors `ingest_provenance::resolve`'s reasoning for
    /// the same shape of test.
    fn parse(raw: Option<&str>) -> i64 {
        raw.and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|&n| n >= MIN_MMD_SECONDS)
            .unwrap_or(DEFAULT_MMD_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_meets_its_own_floor() {
        assert!(MmdPolicy::default().mmd_seconds >= MIN_MMD_SECONDS);
    }

    #[test]
    fn parse_falls_back_on_missing_nonnumeric_or_below_floor() {
        assert_eq!(MmdPolicy::parse(None), DEFAULT_MMD_SECONDS);
        assert_eq!(MmdPolicy::parse(Some("not-a-number")), DEFAULT_MMD_SECONDS);
        assert_eq!(MmdPolicy::parse(Some("0")), DEFAULT_MMD_SECONDS);
        assert_eq!(MmdPolicy::parse(Some("-100")), DEFAULT_MMD_SECONDS);
    }

    #[test]
    fn parse_accepts_a_valid_value() {
        assert_eq!(MmdPolicy::parse(Some("7200")), 7200);
        assert_eq!(
            MmdPolicy::parse(Some("  7200  ")),
            7200,
            "trimmed value wins"
        );
    }

    #[test]
    fn from_env_reads_the_documented_var_name() {
        // The only thing `parse`'s tests can't cover: that `from_env` reads
        // `OLYMPUS_MMD_SECONDS` specifically. Saves and restores whatever
        // value the process started with (rather than unconditionally
        // clearing it) so this test can't leak a changed policy into any
        // other test in this binary that constructs `AppState`.
        struct RestoreEnv(Option<std::ffi::OsString>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("OLYMPUS_MMD_SECONDS", v),
                    None => std::env::remove_var("OLYMPUS_MMD_SECONDS"),
                }
            }
        }
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let _restore = RestoreEnv(std::env::var_os("OLYMPUS_MMD_SECONDS"));

        std::env::set_var("OLYMPUS_MMD_SECONDS", "7200");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, 7200);
    }
}
