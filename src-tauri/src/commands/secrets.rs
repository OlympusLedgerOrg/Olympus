// SPDX-License-Identifier: Apache-2.0

use tauri::Manager;

/// One-shot store for secrets freshly minted by bootstrap. Read once via
/// the `take_initial_secrets` Tauri command; subsequent reads return
/// `None`.
///
/// Each `String` field is wrapped in `zeroize::Zeroizing<String>`, so when
/// the outer struct drops (after Tauri's serde layer has finished borrowing
/// the fields for IPC serialization) the backing heap region is overwritten
/// with zeros instead of just being `dealloc`'d. This is one-of-N copies —
/// serde's internal buffer, the IPC pipe, and the webview's V8 string heap
/// are not zeroed and remain readable until reclaimed — but this is the
/// only copy we still control on the Rust side, so we scrub it.
/// (Audit finding F-4. An earlier version of this doc comment claimed
/// `String`'s Drop "zeroed" the bytes; it does not, it only deallocates.)
pub(crate) struct InitialSecretsState {
    pub(crate) inner: std::sync::Mutex<Option<InitialSecretsSerde>>,
}

// No `#[derive(Clone)]`: `Zeroizing<String>::clone()` would still scrub the
// clone on Drop, but every extra copy widens the window where the secret is
// live in memory. The only consumer is `take_initial_secrets`, which *moves*
// the value out of the Mutex via `Option::take`, so Clone is unused.
// CodeRabbit nit on PR #1055.
pub(crate) struct InitialSecretsSerde {
    /// `oly_…` raw admin API key (only present when freshly created).
    pub(crate) system_api_key: Option<zeroize::Zeroizing<String>>,
    /// 64-char hex BJJ authority private key (only when freshly created).
    pub(crate) bjj_authority_key_hex: Option<zeroize::Zeroizing<String>>,
}

// Manual `Serialize` so the Zeroizing<String> wrapper is transparent to
// the IPC layer (just emits the inner string), while Drop on the wrapper
// still zeros the heap region afterward. Field names mirror the previous
// derive(Serialize) output verbatim for frontend compatibility.
impl serde::Serialize for InitialSecretsSerde {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("InitialSecretsSerde", 2)?;
        s.serialize_field(
            "system_api_key",
            &self.system_api_key.as_ref().map(|z| z.as_str()),
        )?;
        s.serialize_field(
            "bjj_authority_key_hex",
            &self.bjj_authority_key_hex.as_ref().map(|z| z.as_str()),
        )?;
        s.end()
    }
}

/// Returns the one-shot secrets bundle to the frontend, then clears the
/// in-memory copy. Returns `None` if either: bootstrap had nothing fresh
/// to surface, or this command was already called this process lifetime.
#[tauri::command]
pub(crate) fn take_initial_secrets(
    state: tauri::State<'_, InitialSecretsState>,
) -> Option<InitialSecretsSerde> {
    state.inner.lock().ok().and_then(|mut guard| guard.take())
}

/// In-app startup error surface. Replaces stderr-only failures
/// (placeholder ZK artifacts under `OLYMPUS_ENV=production`, missing
/// proofs_dir, BJJ key required but absent, …) with a GUI screen so
/// the user knows why the app refuses to function.
#[derive(Clone, Default, serde::Serialize)]
pub(crate) struct StartupError {
    pub(crate) code: String,
    pub(crate) message: String,
    /// Optional docs URL the user can read for context.
    pub(crate) doc_url: Option<String>,
}

pub(crate) struct StartupErrorState {
    pub(crate) inner: std::sync::Mutex<Option<StartupError>>,
}

#[tauri::command]
pub(crate) fn get_startup_error(
    state: tauri::State<'_, StartupErrorState>,
) -> Option<StartupError> {
    state.inner.lock().ok().and_then(|g| g.clone())
}

/// Code used for the "startup is taking too long" screen.
///
/// Named because it is the one startup error that can be retracted: unlike a
/// config error, it describes a condition that may resolve on its own.
pub(crate) const STARTUP_TIMEOUT_CODE: &str = "STARTUP_TIMEOUT";

/// Record a startup error, leaving any error already present untouched.
///
/// First writer wins: an error raised earlier is closer to the root cause, and
/// a later, vaguer one would bury it. Split from [`publish_startup_error`] so
/// the policy is testable without standing up a Tauri app.
fn record_startup_error(slot: &mut Option<StartupError>, error: StartupError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

/// Retract a [`STARTUP_TIMEOUT_CODE`] entry, leaving every other code in place.
///
/// Scoped to that one code on purpose: it is the only claim a successful start
/// disproves. `STARTUP_FAILED` describes a dead server thread and a
/// config-level code describes a misconfiguration — neither becomes false
/// because the port later arrived, so neither may be cleared here.
///
/// It also runs *before* recording `STARTUP_FAILED` on the
/// timeout-then-disconnect path, where the first-writer-wins rule in
/// [`record_startup_error`] would otherwise keep the stale "still waiting"
/// message instead of the terminal one.
///
/// (`main` also builds a `PROD_NO_PROOFS_DIR` error before the wait. That arm
/// is currently unreachable — production `exit(2)`s on a missing artifacts
/// directory long before the state is registered — so it is retained as a
/// guard, not as a live case.)
fn retract_startup_timeout(slot: &mut Option<StartupError>) {
    if slot
        .as_ref()
        .is_some_and(|e| e.code == STARTUP_TIMEOUT_CODE)
    {
        *slot = None;
    }
}

/// Publish a startup error to the GUI surface. See [`record_startup_error`].
pub(crate) fn publish_startup_error(app: &tauri::AppHandle, error: StartupError) {
    eprintln!(
        "[olympus-desktop] startup error {}: {}",
        error.code, error.message
    );
    if let Some(state) = app.try_state::<StartupErrorState>() {
        if let Ok(mut guard) = state.inner.lock() {
            record_startup_error(&mut guard, error);
        }
    }
}

/// Clear the "startup is taking too long" screen once the server does start.
/// See [`retract_startup_timeout`].
pub(crate) fn clear_startup_timeout(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<StartupErrorState>() {
        if let Ok(mut guard) = state.inner.lock() {
            retract_startup_timeout(&mut guard);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup_error(code: &str) -> StartupError {
        StartupError {
            code: code.to_owned(),
            message: format!("{code} happened"),
            doc_url: None,
        }
    }

    #[test]
    fn the_first_startup_error_survives_a_later_one() {
        // A late, vaguer error must not bury the root cause.
        let mut slot = None;
        record_startup_error(&mut slot, startup_error("PROD_NO_PROOFS_DIR"));
        record_startup_error(&mut slot, startup_error(STARTUP_TIMEOUT_CODE));
        assert_eq!(
            slot.as_ref().expect("an error was recorded").code,
            "PROD_NO_PROOFS_DIR"
        );
    }

    #[test]
    fn a_late_start_retracts_only_the_timeout_screen() {
        // Retraction is scoped to the one code that describes a condition which
        // can resolve on its own. Prove both directions — clearing every code
        // would hide an error the successful start did nothing to disprove.
        let mut timed_out = Some(startup_error(STARTUP_TIMEOUT_CODE));
        retract_startup_timeout(&mut timed_out);
        assert!(timed_out.is_none(), "the timeout screen must be retracted");

        let mut misconfigured = Some(startup_error("PROD_NO_PROOFS_DIR"));
        retract_startup_timeout(&mut misconfigured);
        assert_eq!(
            misconfigured.as_ref().map(|e| e.code.as_str()),
            Some("PROD_NO_PROOFS_DIR"),
            "a config error stays true whether or not the server came up"
        );

        // And an empty slot is left empty rather than panicking.
        let mut healthy = None;
        retract_startup_timeout(&mut healthy);
        assert!(healthy.is_none());
    }

    #[test]
    fn a_dead_server_thread_replaces_the_timeout_screen() {
        // The timeout-then-disconnect path: the wait overran, then the channel
        // closed without a port. First-writer-wins alone would keep the
        // STARTUP_TIMEOUT message — "still waiting, will recover on its own" —
        // about a thread that is dead and will never report. The waiter
        // therefore retracts before recording the terminal error.
        let mut slot = None;
        record_startup_error(&mut slot, startup_error(STARTUP_TIMEOUT_CODE));
        retract_startup_timeout(&mut slot);
        record_startup_error(&mut slot, startup_error("STARTUP_FAILED"));

        assert_eq!(
            slot.as_ref().map(|e| e.code.as_str()),
            Some("STARTUP_FAILED"),
            "the terminal error must replace the stale 'still waiting' one"
        );

        // Without the retraction the stale message would survive — this is the
        // regression the ordering exists to prevent.
        let mut unretracted = None;
        record_startup_error(&mut unretracted, startup_error(STARTUP_TIMEOUT_CODE));
        record_startup_error(&mut unretracted, startup_error("STARTUP_FAILED"));
        assert_eq!(
            unretracted.as_ref().map(|e| e.code.as_str()),
            Some(STARTUP_TIMEOUT_CODE),
            "first-writer-wins is what makes the retraction load-bearing"
        );
    }
}
