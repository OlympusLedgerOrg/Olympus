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
        let mmd_seconds = std::env::var("OLYMPUS_MMD_SECONDS")
            .ok()
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|&n| n >= MIN_MMD_SECONDS)
            .unwrap_or(DEFAULT_MMD_SECONDS);
        Self { mmd_seconds }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test in this module that mutates
    /// `OLYMPUS_MMD_SECONDS` — a process-global — since `cargo test` runs
    /// test functions concurrently on separate threads by default.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_meets_its_own_floor() {
        assert!(MmdPolicy::default().mmd_seconds >= MIN_MMD_SECONDS);
    }

    #[test]
    fn from_env_falls_back_on_missing_nonnumeric_or_below_floor() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::remove_var("OLYMPUS_MMD_SECONDS");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, DEFAULT_MMD_SECONDS);

        std::env::set_var("OLYMPUS_MMD_SECONDS", "not-a-number");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, DEFAULT_MMD_SECONDS);

        std::env::set_var("OLYMPUS_MMD_SECONDS", "0");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, DEFAULT_MMD_SECONDS);

        std::env::set_var("OLYMPUS_MMD_SECONDS", "-100");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, DEFAULT_MMD_SECONDS);

        std::env::remove_var("OLYMPUS_MMD_SECONDS");
    }

    #[test]
    fn from_env_accepts_a_valid_override() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("OLYMPUS_MMD_SECONDS", "7200");
        assert_eq!(MmdPolicy::from_env().mmd_seconds, 7200);
        std::env::remove_var("OLYMPUS_MMD_SECONDS");
    }
}
