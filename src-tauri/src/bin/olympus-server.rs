// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Headless Olympus server — the embedded Axum HTTP server + pg_embed
//! Postgres, booted **without** the Tauri desktop window.
//!
//! ## Why this exists
//!
//! Two consumers, one server:
//!   * The **audit / E2E harness** (`docker/Dockerfile.audit` +
//!     `docker/compose.audit.yml`) needs to stand up the full API surface in a
//!     Linux container so every endpoint can be exercised over HTTP. It cannot
//!     open a GTK/webkit window.
//!   * The **buddy / multi-host deployment model** runs one machine as an interim
//!     API server reached over an SSH tunnel — again, no GUI.
//!
//! This is **not** a new architecture or a second proving backend: it reuses the
//! exact same [`olympus_tauri_lib::server::start`] + [`bootstrap::run`] path the
//! desktop app uses. The only inputs that the desktop derives from Tauri — the
//! app-data directory and the ZK proofs directory — are taken from env here
//! (`OLYMPUS_DATA_DIR`, `OLYMPUS_PROOFS_DIR`).
//!
//! ## Kept in sync with `main.rs`
//!
//! The bootstrap sequence below mirrors the `tauri::Builder::setup` closure in
//! `src/main.rs` (DB → `bootstrap::run` → `AppState` assembly with the
//! `resolve_*` helpers → anchor crons → federation bootstrap → `server::start`).
//! If that closure changes, update this binary too.
//!
//! ## Deliberate divergences from `main.rs`
//!
//!   * **No Tauri managed state / window / file-drop** — those are GUI-only.
//!   * **No startup ceremony-manifest gate.** `main.rs::verify_ceremony_manifests`
//!     lives in the bin-only `startup` module and is not exported by the lib.
//!     The runtime check in `zk::zkey::load_proving_key_with_manifest` (the
//!     re-hash-before-deserialize gate) still fires on the first `/zk/prove`, so
//!     a tampered `.ark.zkey` is still rejected. Because this gate is missing,
//!     `main()` refuses to start at all under `OLYMPUS_ENV=production` (before
//!     any database connection is opened) rather than silently running without
//!     it. Run this binary in dev/test mode (`OLYMPUS_ENV` unset or `dev`).
//!     Production deployments should keep using the desktop binary (or this
//!     gate must be lifted into the lib first).

use std::path::PathBuf;

use olympus_tauri_lib::{anchoring, api, bootstrap, db, server, state};

#[tokio::main]
async fn main() {
    // Mirror main.rs: tracing → stderr, honour RUST_LOG, default to
    // info + our crate at debug so handler/background-task warnings surface.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,olympus_desktop=debug")
            }),
        )
        .with_writer(std::io::stderr)
        .try_init();

    // ── Refuse OLYMPUS_ENV=production before touching the database ───────────
    // This binary deliberately skips `main.rs::verify_ceremony_manifests` and
    // the desktop's placeholder/manifest OLYMPUS_ENV=production exit(2) gate
    // (see the module doc above) — running it in production would silently
    // accept tampered or placeholder ZK artifacts. Mirror the desktop's
    // established refusal behavior rather than enforcing the gate here.
    if let Ok(v) = std::env::var("OLYMPUS_ENV") {
        if matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "production" | "prod"
        ) {
            eprintln!(
                "[olympus-server] FATAL: OLYMPUS_ENV=production is refused by this headless \
                 binary — it does not enforce the ceremony-manifest / placeholder-artifact \
                 startup gate the olympus-desktop binary does. Use olympus-desktop for \
                 production deployments."
            );
            std::process::exit(2);
        }
    }

    // ── App-data dir (embedded PG cluster + federation Tor state live here) ──
    // Desktop uses Tauri's `app_data_dir()`; headless takes it from env so the
    // container can mount a persistent volume. Default to a cwd-relative dir so
    // a bare `./olympus-server` still works for local smoke tests.
    let data_dir: PathBuf = std::env::var_os("OLYMPUS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("olympus-data")
        });
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!(
            "[olympus-server] FATAL: cannot create data dir {}: {e}",
            data_dir.display()
        );
        std::process::exit(2);
    }
    eprintln!("[olympus-server] data dir: {}", data_dir.display());

    // ── ZK artifacts dir ────────────────────────────────────────────────────
    // Desktop resolves a 4-candidate chain; headless takes the single
    // OLYMPUS_PROOFS_DIR (candidate #1 in that chain). None → /zk/* return 503.
    let proofs_dir: Option<PathBuf> = std::env::var_os("OLYMPUS_PROOFS_DIR").map(PathBuf::from);
    match &proofs_dir {
        Some(p) => eprintln!("[olympus-server] ZK artifacts dir: {}", p.display()),
        None => eprintln!(
            "[olympus-server] ZK artifacts dir: NOT SET (set OLYMPUS_PROOFS_DIR to enable /zk/*)"
        ),
    }

    // ── Database: external (DATABASE_URL) or embedded pg_embed ───────────────
    let (pool, db_error, mut embedded) = if let Ok(url) = std::env::var("DATABASE_URL") {
        let p = db::connect_external(&url).await;
        let err = p.is_none().then(|| {
            "Could not connect to external database; check DATABASE_URL and that it is running."
                .to_string()
        });
        (p, err, None)
    } else {
        match db::init_embedded(&data_dir).await {
            Ok(e) => {
                let pool = e.pool.clone();
                (Some(pool), None, Some(e))
            }
            Err(e) => {
                let msg = format!("Embedded PostgreSQL failed to start: {e}");
                eprintln!("[olympus-server] FATAL: {msg}");
                std::process::exit(2);
            }
        }
    };
    if let Some(ref e) = db_error {
        // No DB means almost every route 503s — treat as fatal for a server.
        eprintln!("[olympus-server] FATAL: {e}");
        std::process::exit(2);
    }

    // ── Bootstrap: system user, API key, BJJ authority, SBT ──────────────────
    let bjj_result = match pool.as_ref() {
        Some(p) => bootstrap::run(p).await,
        None => None,
    };

    let mut app_state = state::AppState::new_with_error(pool, db_error);
    if let Some(br) = bjj_result {
        app_state.bjj_authority_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(
            br.bjj_authority_key,
        )));
        app_state.bjj_authority_pubkey = Some(br.bjj_authority_pubkey);
        app_state.ingest_signing_key =
            state::resolve_ingest_signing_key(state::secret_bytes(&app_state.bjj_authority_key));
        // Historical redaction/ingest issuer keys (docs/key-rotation.md):
        // mirrors main.rs — record the current Ed25519 verifying key so
        // GET /redaction/issuer-key can serve prior keys too. Non-fatal.
        if let (Some(pool), Some(signing_key)) = (
            app_state.pool.as_ref(),
            state::secret_bytes(&app_state.ingest_signing_key),
        ) {
            let pubkey_hex = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(signing_key)
                    .verifying_key()
                    .to_bytes(),
            );
            if let Err(e) = bootstrap::ensure_ingest_signing_key(pool, &pubkey_hex).await {
                tracing::warn!("bootstrap: ingest signing key registry: {e}");
            }
        }
        app_state.redaction_blind_secret = state::resolve_redaction_blind_secret(
            state::secret_bytes(&app_state.bjj_authority_key),
        );
        // Blind-secret rotation registry (migration 0059, docs/key-rotation.md):
        // mirrors main.rs. Gated on the same literal `OLYMPUS_ENV=production`/
        // `prod` this binary already refuses to start under (see the exit(2)
        // guard above) — NOT `env::is_production`'s fail-closed-on-unset
        // semantics (that helper is crate-private anyway), because unset here
        // always means "this is the dev/audit-harness binary", never a real
        // production deployment. Since literal production is refused before
        // this point, this check is always false in practice; kept for parity
        // with main.rs if that refusal is ever relaxed.
        let is_production = std::env::var("OLYMPUS_ENV").is_ok_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "production" | "prod"
            )
        });
        if is_production {
            if let (Some(pool), Some(secret)) = (
                app_state.pool.as_ref(),
                state::secret_bytes(&app_state.redaction_blind_secret),
            ) {
                let fingerprint = state::fingerprint_redaction_blind_secret(secret);
                match bootstrap::ensure_redaction_blind_secret_fingerprint(pool, &fingerprint).await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        app_state.redaction_blind_secret = None;
                    }
                    Err(e) => {
                        tracing::warn!("bootstrap: redaction blind secret registry: {e}");
                    }
                }
            }
        }
        app_state.bjj_trusted_issuers =
            api::trusted_issuers::load_trusted_issuers(app_state.bjj_authority_pubkey.as_ref());

        // One-shot bootstrap secrets: the desktop forwards these to the UI via
        // an IPC command. Headless has no UI, so log a one-line pointer (never
        // the secret itself) — the operator already supplied or can re-derive
        // the system key from the persisted BJJ authority.
        if !br.freshly_generated.is_empty() {
            eprintln!(
                "[olympus-server] bootstrap minted fresh secrets on this DB \
                 (system API key + BJJ authority). Derive the API key from the \
                 persisted BJJ key via derive_api_key_from_bjj if you need it."
            );
        }
    } else {
        eprintln!("[olympus-server] WARNING: bootstrap did not run (no DB pool); auth will 503.");
    }
    app_state.proofs_dir = proofs_dir;

    // ── Anchor crons (mirror main.rs) ────────────────────────────────────────
    // The anchor cron is the canonical own_checkpoint producer (red-team
    // CR-5/CR-7); outbound submission to OLYMPUS_ANCHOR_* is gated per-tick on
    // any_enabled(), so a build with no anchor URLs makes no network calls.
    let _anchor_cron = app_state.pool.as_ref().map(|pool| {
        anchoring::cron::spawn(
            pool.clone(),
            app_state.anchoring.clone(),
            app_state.anchor_http.clone(),
            state::secret_bytes(&app_state.bjj_authority_key).copied(),
            app_state.bjj_authority_pubkey,
            app_state.proofs_dir.clone(),
        )
    });
    let _ots_upgrade_cron = app_state.pool.as_ref().map(|pool| {
        anchoring::upgrade_cron::spawn(
            pool.clone(),
            app_state.anchor_http.clone(),
            !app_state.anchoring.ots_calendars.is_empty(),
            app_state.anchoring.ots_bitcoin_headers_path.clone(),
        )
    });

    // ADR-0036: keep the signed-request replay cache bounded. Mirrors main.rs —
    // the reaper deletes expired rows via ix_signed_request_nonces_expires_at
    // and leaves live nonce reservations intact.
    let _signed_request_nonce_reaper = app_state.pool.as_ref().map(|pool| {
        api::middleware::signed_request::spawn_signed_request_nonce_reaper(pool.clone())
    });

    // ── Federation (feature-gated, runtime-gated on OLYMPUS_FEDERATION_ENABLED) ─
    // Mirror main.rs: populate the config the Tor-exposed handlers read, capture
    // the handles the Tor + gossip tasks need, then bootstrap Tor off the
    // critical path AFTER the server reports its port.
    #[cfg(feature = "federation")]
    let federation_bootstrap = {
        use olympus_tauri_lib::federation;
        let fed_cfg = federation::FederationConfig::default();
        if fed_cfg.enabled {
            let state_dir = data_dir.join("tor");
            app_state.federation_config = Some(fed_cfg.clone());
            app_state.federation_state_dir = Some(state_dir.clone());
            let fed_proofs_dir = app_state.proofs_dir.clone();
            let tor_handle_cell = app_state.tor_handle.clone();
            match (
                app_state.pool.clone(),
                state::secret_bytes(&app_state.bjj_authority_key).copied(),
                app_state.bjj_authority_pubkey,
            ) {
                (Some(pool), Some(bjj_key), Some(bjj_pubkey)) => {
                    let tor_state = app_state.clone();
                    Some((
                        pool,
                        fed_cfg,
                        bjj_key,
                        bjj_pubkey,
                        state_dir,
                        fed_proofs_dir,
                        tor_handle_cell,
                        tor_state,
                    ))
                }
                _ => {
                    tracing::warn!(
                        "federation: OLYMPUS_FEDERATION_ENABLED set but BJJ key or DB unavailable; \
                         hidden service + gossip not started"
                    );
                    None
                }
            }
        } else {
            tracing::info!(
                "federation: compiled in but OLYMPUS_FEDERATION_ENABLED not set; not started"
            );
            None
        }
    };

    // ── Start the Axum server ────────────────────────────────────────────────
    let addr = match server::start(app_state).await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("[olympus-server] FATAL: Axum server failed to bind: {e}");
            if let Some(e) = embedded.as_mut() {
                if let Err(stop_err) = e.pg.stop_db().await {
                    eprintln!(
                        "[olympus-server] WARNING: embedded postgres did not stop cleanly: {stop_err}"
                    );
                }
            }
            std::process::exit(2);
        }
    };
    // Single machine-greppable readiness line for the container/health probe.
    eprintln!("[olympus-server] listening on http://{addr}");
    println!("OLYMPUS_SERVER_LISTENING http://{addr}");

    // ── Tor hidden service + gossip, off the critical path ───────────────────
    #[cfg(feature = "federation")]
    if let Some((
        pool,
        fed_cfg,
        bjj_key,
        bjj_pubkey,
        state_dir,
        fed_proofs_dir,
        tor_handle_cell,
        tor_state,
    )) = federation_bootstrap
    {
        use olympus_tauri_lib::federation;
        tokio::spawn(async move {
            let tor_local_port = match server::start_tor_listener(tor_state).await {
                Ok(addr) => addr.port(),
                Err(e) => {
                    tracing::error!("federation: failed to bind Tor-facing listener: {e}");
                    return;
                }
            };
            tracing::info!("federation: bootstrapping Tor hidden service (may take 30-60s)");
            match federation::tor::start_hidden_service(state_dir, tor_local_port).await {
                Ok(handle) => {
                    tracing::info!(
                        "federation: hidden service live at {}; starting gossip",
                        handle.onion_address
                    );
                    let handle = std::sync::Arc::new(handle);
                    let _ = tor_handle_cell.set(handle.clone());
                    let _gossip = federation::gossip::spawn(
                        pool,
                        fed_cfg,
                        bjj_key,
                        bjj_pubkey,
                        handle,
                        fed_proofs_dir,
                    );
                }
                Err(e) => {
                    tracing::error!("federation: Tor bootstrap failed; gossip not started: {e}")
                }
            }
        });
    }

    // ── Run until a shutdown signal, then stop embedded PG cleanly ───────────
    wait_for_shutdown().await;
    eprintln!("[olympus-server] shutdown signal received; stopping…");
    if let Some(e) = embedded.as_mut() {
        match e.pg.stop_db().await {
            Ok(()) => eprintln!("[olympus-server] embedded postgres stopped cleanly"),
            Err(stop_err) => eprintln!(
                "[olympus-server] WARNING: embedded postgres did not stop cleanly: {stop_err}"
            ),
        }
    }
}

/// Await SIGTERM (containers) or Ctrl-C (interactive). On non-unix, Ctrl-C only.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
