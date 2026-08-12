// SPDX-License-Identifier: Apache-2.0

use crate::db;

/// The local Axum server's port, or [`ApiState::NOT_READY`] before it binds.
///
/// Atomic rather than a plain `u16` because the setup hook no longer blocks
/// indefinitely on the server thread: a slow embedded-Postgres bring-up can
/// outrun the hook's budget, in which case the hook completes with the port
/// still unset (the GUI shows a startup-error screen) and a waiter thread
/// stores the real port if the server does come up afterwards. Commands must
/// therefore read it through [`ApiState::port`] on every call rather than
/// caching it.
pub(crate) struct ApiState {
    port: std::sync::atomic::AtomicU16,
}

impl ApiState {
    /// Sentinel for "the server has not reported a port yet". Port 0 is never
    /// a real bound port here — the server always binds an explicit port and
    /// reports the resolved value.
    pub(crate) const NOT_READY: u16 = 0;

    pub(crate) fn new(port: u16) -> Self {
        Self {
            port: std::sync::atomic::AtomicU16::new(port),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn set_port(&self, port: u16) {
        self.port.store(port, std::sync::atomic::Ordering::Release);
    }

    /// Read the port, refusing to build a request URL before the server binds.
    ///
    /// Without this, a command racing a slow startup would POST to
    /// `127.0.0.1:0` and surface an opaque connection error instead of the
    /// actual reason the app is not ready.
    ///
    /// `pub(crate)`, not private: `commands::files` calls this from `commit_file`,
    /// `describe_by_path`, and `redact_by_path`, which now live in a sibling module.
    pub(crate) fn ready_port(&self) -> Result<u16, String> {
        match self.port() {
            Self::NOT_READY => Err("the local Olympus server has not finished starting yet; \
                 wait for startup to complete and try again"
                .to_owned()),
            port => Ok(port),
        }
    }
}

#[tauri::command]
pub(crate) fn get_api_port(state: tauri::State<ApiState>) -> u16 {
    state.port()
}

/// Database startup failure detail, surfaced by `DbErrorGate` in the UI.
///
/// Behind a mutex for the same reason [`ApiState`] is atomic: the waiter
/// thread may publish it after the setup hook has already returned.
pub(crate) struct DbErrorState {
    pub(crate) error: std::sync::Mutex<Option<String>>,
}

#[tauri::command]
pub(crate) fn get_db_error(state: tauri::State<DbErrorState>) -> Option<String> {
    state.error.lock().ok().and_then(|guard| guard.clone())
}

/// Holds the embedded PG instance so it can be stopped cleanly on exit.
/// Wrapped in Mutex so the on-exit handler can take ownership.
pub(crate) struct EmbeddedDbState {
    pub(crate) inner: std::sync::Mutex<Option<db::EmbeddedDb>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_state_refuses_to_build_a_url_until_the_server_reports_a_port() {
        // The setup hook now completes before the port is known, so every
        // command can run against an unpopulated ApiState. Prove the guard is
        // the *sentinel* that decides, not a constant: the same state refuses
        // before the store and answers after it.
        let state = ApiState::new(ApiState::NOT_READY);
        let err = state
            .ready_port()
            .expect_err("NOT_READY must not yield a port");
        assert!(
            err.contains("has not finished starting"),
            "the error must name the actual reason, not a connection failure: {err}"
        );

        state.set_port(3737);
        assert_eq!(state.ready_port().expect("port after publish"), 3737);
        assert_eq!(state.port(), 3737);
    }
}
