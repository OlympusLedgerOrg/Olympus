#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Match lib.rs: the bin re-includes the same module tree, so without this
// every item not reachable from `main` is reported as dead code.
#![allow(dead_code, unused_imports)]

mod anchoring;
mod api;
mod bootstrap;
mod db;
#[cfg(feature = "federation")]
mod federation;
mod ingest_provenance;
mod integrity;
mod quorum;
mod routes;
mod server;
mod smt;
mod state;
mod zk;

use tauri::Manager;

// Tauri IPC commands + managed-state types and the startup-artifact /
// ceremony-verification helpers were extracted from this file. Glob-imported
// so `main()` and `generate_handler!` reference them by bare name unchanged.
mod commands;
mod startup;
use commands::*;
use startup::*;
fn main() {
    // Initialise tracing → stderr so warn!/error! from request handlers and
    // background tasks (snapshot build, anchoring, etc.) are visible during
    // dev. Honour RUST_LOG; default to `info,olympus_desktop=debug` so our
    // own crate's warnings surface without drowning in third-party noise.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,olympus_desktop=debug")
            }),
        )
        .with_writer(std::io::stderr)
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

            // Best-effort cleanup if this process panics after PG starts.
            // The clean-exit path is handled by WindowEvent::Destroyed below;
            // this hook covers panics (e.g. setup-hook timeout) so the next
            // launch isn't blocked by an orphaned postgres.exe holding port 5433.
            {
                let cleanup_dir = app_data_dir.clone();
                let prev = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    db::reap_embedded_pg(&cleanup_dir);
                    prev(info);
                }));
            }

            let proofs_dir = resolve_proofs_dir(app.handle());
            let is_prod = std::env::var("OLYMPUS_ENV")
                .map(|v| v.eq_ignore_ascii_case("production"))
                .unwrap_or(false);
            if let Some(ref p) = proofs_dir {
                eprintln!("[olympus-desktop] ZK artifacts dir: {}", p.display());
                let placeholders = detect_placeholder_artifacts(p);
                if !placeholders.is_empty() {
                    eprintln!(
                        "[olympus-desktop] WARNING: {} placeholder ZK artifact(s) detected — \
                         /zk/prove will return 503 until `proofs/setup_circuits.sh` is run.",
                        placeholders.len()
                    );
                    for path in &placeholders {
                        eprintln!("[olympus-desktop]   placeholder: {}", path.display());
                    }
                    if is_prod {
                        eprintln!(
                            "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
                             with placeholder ZK artifacts. Re-build with real Groth16 keys."
                        );
                        std::process::exit(2);
                    }
                }
            } else {
                eprintln!(
                    "[olympus-desktop] ZK artifacts dir: NOT FOUND \
                     (set OLYMPUS_PROOFS_DIR to enable /zk/prove and /zk/verify)"
                );
                if is_prod {
                    eprintln!(
                        "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start without \
                         a populated ZK artifacts directory."
                    );
                    std::process::exit(2);
                }
            }

            let (tx, rx) = std::sync::mpsc::channel::<(
                u16,
                Option<String>,
                Option<db::EmbeddedDb>,
                Option<InitialSecretsSerde>,
            )>();
            let proofs_dir_for_thread = proofs_dir.clone();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(async move {
                        let (pool, db_error, embedded) = if let Ok(url) = std::env::var("DATABASE_URL") {
                            let p = db::connect_external(&url).await;
                            let err = if p.is_none() {
                                Some(format!(
                                    "Could not connect to external database.\n\
                                     URL: {url}\n\
                                     Check that the server is running and DATABASE_URL is correct."
                                ))
                            } else {
                                None
                            };
                            (p, err, None)
                        } else {
                            match db::init_embedded(&app_data_dir).await {
                                Ok(embedded) => {
                                    let pool = embedded.pool.clone();
                                    (Some(pool), None, Some(embedded))
                                }
                                Err(e) => {
                                    let msg = format!(
                                        "Embedded PostgreSQL failed to start.\n\
                                         Error: {}\n\
                                         Data dir: {}\n\
                                         Hint: check that port 5433 is free and disk has space.",
                                        e,
                                        app_data_dir.display()
                                    );
                                    eprintln!("[olympus-desktop] {msg}");
                                    (None, Some(msg), None)
                                }
                            }
                        };

                        // Bootstrap: ensure system user, API key, BJJ authority, and SBT exist.
                        let bjj_result = if let Some(ref p) = pool {
                            bootstrap::run(p).await
                        } else {
                            None
                        };

                        let mut app_state = state::AppState::new_with_error(pool, db_error.clone());
                        let mut initial_secrets: Option<InitialSecretsSerde> = None;
                        if let Some(br) = bjj_result {
                            app_state.bjj_authority_key = Some(br.bjj_authority_key);
                            app_state.bjj_authority_pubkey = Some(br.bjj_authority_pubkey);
                            // Audit M-3: resolve the full trusted-issuer set
                            // (primary bootstrap pubkey + any rotation entries
                            // in OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON) once at
                            // startup so the scope resolver doesn't re-parse
                            // per request.
                            app_state.bjj_trusted_issuers =
                                crate::api::trusted_issuers::load_trusted_issuers(
                                    app_state.bjj_authority_pubkey.as_ref(),
                                );
                            // Audit CEREMONY_INTEGRITY.md #3 + #4:
                            // verify each circuit's embedded ceremony
                            // manifest against the trusted-issuer set
                            // and the on-disk .ark.zkey. Under
                            // OLYMPUS_ENV=production, any non-placeholder
                            // failure is fatal — exit(2) before the
                            // server starts serving. In dev, surface a
                            // tracing::warn! so the operator can fix it
                            // (the runtime check in
                            // load_proving_key_with_manifest provides
                            // belt-and-suspenders at first prove call).
                            if let Some(ref proofs_path) = proofs_dir_for_thread {
                                let is_prod = std::env::var("OLYMPUS_ENV")
                                    .map(|v| v.eq_ignore_ascii_case("production"))
                                    .unwrap_or(false);
                                let checks = verify_ceremony_manifests(
                                    proofs_path,
                                    &app_state.bjj_trusted_issuers,
                                    is_prod,
                                    app_state.bjj_authority_pubkey.as_ref(),
                                );
                                let mut real_failures = 0usize;
                                for ManifestCheck { circuit, result } in &checks {
                                    match result {
                                        Ok(coord_x_dec) => {
                                            tracing::info!(
                                                "ceremony-integrity: {} manifest verified under coordinator x={}",
                                                circuit, coord_x_dec
                                            );
                                        }
                                        Err(reason) if reason.contains("placeholder") => {
                                            // detect_placeholder_artifacts above checks vkey JSON
                                            // but NOT manifest files — so a binary with real
                                            // .ark.zkey + placeholder manifest would otherwise
                                            // sail past the earlier gate. Treat as fatal in prod
                                            // so the runtime can't run without active manifest
                                            // verification.
                                            if is_prod {
                                                real_failures += 1;
                                                tracing::error!(
                                                    "ceremony-integrity: {} FAILED in production — {}",
                                                    circuit, reason
                                                );
                                            } else {
                                                tracing::warn!(
                                                    "ceremony-integrity: {} skipped — {}",
                                                    circuit, reason
                                                );
                                            }
                                        }
                                        Err(reason) => {
                                            real_failures += 1;
                                            tracing::error!(
                                                "ceremony-integrity: {} FAILED — {}",
                                                circuit, reason
                                            );
                                        }
                                    }
                                }
                                if real_failures > 0 && is_prod {
                                    eprintln!(
                                        "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
                                         with {real_failures} ceremony-manifest failure(s). See \
                                         tracing::error! above and proofs/CEREMONY_INTEGRITY.md for \
                                         the operator runbook."
                                    );
                                    std::process::exit(2);
                                }
                            }
                            if !br.freshly_generated.is_empty() {
                                // F-4: wrap each secret String in Zeroizing<String> at the
                                // earliest point we own the value, so the heap region is
                                // scrubbed on drop. The upstream `FreshlyGenerated` still
                                // holds plain Strings briefly; widening Zeroizing into
                                // bootstrap.rs is a separate larger change.
                                initial_secrets = Some(InitialSecretsSerde {
                                    system_api_key: br
                                        .freshly_generated
                                        .system_api_key
                                        .map(zeroize::Zeroizing::new),
                                    bjj_authority_key_hex: br
                                        .freshly_generated
                                        .bjj_authority_key_hex
                                        .map(zeroize::Zeroizing::new),
                                });
                            }
                        }
                        app_state.proofs_dir = proofs_dir_for_thread;

                        // Audit H-A1: spawn the periodic anchor cron BEFORE
                        // moving app_state into server::start. The cron clones
                        // only the fields it needs (pool, anchoring cfg, http
                        // client, BJJ key + pubkey, proofs_dir). It always runs
                        // as the canonical own_checkpoints producer (red-team
                        // CR-5/CR-7), but external submission to OLYMPUS_ANCHOR_*
                        // backends is gated per-tick on `any_enabled()`, so a
                        // build with no anchor URLs still makes no outbound
                        // network calls.
                        let _anchor_cron = app_state.pool.as_ref().map(|pool| {
                            crate::anchoring::cron::spawn(
                                pool.clone(),
                                app_state.anchoring.clone(),
                                app_state.anchor_http.clone(),
                                app_state.bjj_authority_key,
                                app_state.bjj_authority_pubkey,
                                // Red-team CR-5 / PR E: the cron is now
                                // the canonical own_checkpoint producer
                                // (runs `prove_existence` per tick) so
                                // it needs the proofs_dir alongside the
                                // BJJ key.
                                app_state.proofs_dir.clone(),
                            )
                        });

                        // Audit M-A3: spawn the OTS upgrade cron alongside the
                        // anchor cron. The anchor cron above creates pending
                        // OTS receipts; this one drives them through the
                        // upgrade pipeline (pending → upgraded) once the OTS
                        // calendars publish their Bitcoin attestations. No-op
                        // when no OTS calendars are configured.
                        let _ots_upgrade_cron = app_state.pool.as_ref().map(|pool| {
                            crate::anchoring::upgrade_cron::spawn(
                                pool.clone(),
                                app_state.anchor_http.clone(),
                                !app_state.anchoring.ots_calendars.is_empty(),
                            )
                        });

                        // Federation: populate the config the Tor-exposed route
                        // handlers read (so they don't 503) and capture the
                        // handles the Tor + gossip tasks need. The actual Tor
                        // bootstrap happens AFTER the server reports its port,
                        // because the hidden service proxies to that port and a
                        // bootstrap can take 30-60s — longer than the startup
                        // budget the Tauri thread waits on. Gated on the
                        // `federation` feature AND `OLYMPUS_FEDERATION_ENABLED`.
                        #[cfg(feature = "federation")]
                        let federation_bootstrap = {
                            let fed_cfg = crate::federation::FederationConfig::default();
                            if fed_cfg.enabled {
                                let state_dir = app_data_dir.join("tor");
                                app_state.federation_config = Some(fed_cfg.clone());
                                app_state.federation_state_dir = Some(state_dir.clone());
                                // Capture proofs_dir here BEFORE app_state
                                // is moved into server::start below — the
                                // gossip task needs it for prove_existence
                                // in build_own_checkpoint (H-11/M-5 closure).
                                let proofs_dir = app_state.proofs_dir.clone();
                                // Shared cell the bootstrap task publishes the
                                // Tor handle into, so the credentials handler
                                // can collect quorum co-signatures over Tor.
                                let tor_handle_cell = app_state.tor_handle.clone();
                                match (
                                    app_state.pool.clone(),
                                    app_state.bjj_authority_key,
                                    app_state.bjj_authority_pubkey,
                                ) {
                                    (Some(pool), Some(bjj_key), Some(bjj_pubkey)) => {
                                        // Clone AppState for the verify-only
                                        // Tor-facing listener BEFORE app_state
                                        // is moved into server::start below.
                                        let tor_state = app_state.clone();
                                        Some((pool, fed_cfg, bjj_key, bjj_pubkey, state_dir, proofs_dir, tor_handle_cell, tor_state))
                                    }
                                    _ => {
                                        tracing::warn!(
                                            "federation: OLYMPUS_FEDERATION_ENABLED set but the BJJ \
                                             authority key or database is unavailable; hidden service \
                                             and gossip not started"
                                        );
                                        None
                                    }
                                }
                            } else {
                                tracing::info!(
                                    "federation: compiled in but OLYMPUS_FEDERATION_ENABLED not set; \
                                     hidden service and gossip not started"
                                );
                                None
                            }
                        };

                        let addr = server::start(app_state)
                            .await
                            .expect("axum server failed to bind");
                        let local_port = addr.port();
                        tx.send((local_port, db_error, embedded, initial_secrets))
                            .expect("receiver dropped before port was sent");

                        // Bootstrap Tor + start gossip off the critical path so a
                        // slow Tor bootstrap can't stall app startup. The task
                        // owns the `Arc<TorHandle>` for its lifetime, keeping the
                        // hidden service alive.
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
                            tokio::spawn(async move {
                                // Bind the verify-only Tor-facing listener and
                                // point the hidden service at IT, not the full
                                // router's port. This keeps admin/auth/key/write
                                // and /zk/prove off the onion surface entirely.
                                let tor_local_port = match server::start_tor_listener(tor_state).await {
                                    Ok(addr) => addr.port(),
                                    Err(e) => {
                                        tracing::error!(
                                            "federation: failed to bind Tor-facing listener: {e}; \
                                             hidden service not started"
                                        );
                                        return;
                                    }
                                };
                                tracing::info!(
                                    "federation: bootstrapping Tor hidden service (may take 30-60s)"
                                );
                                match crate::federation::tor::start_hidden_service(
                                    state_dir, tor_local_port,
                                )
                                .await
                                {
                                    Ok(handle) => {
                                        tracing::info!(
                                            "federation: hidden service live at {}; starting gossip",
                                            handle.onion_address
                                        );
                                        let handle = std::sync::Arc::new(handle);
                                        // Publish the handle so issue-time quorum
                                        // co-sign collection can reach peers over
                                        // Tor. Ignore the error: set() only fails
                                        // if already set (a second bootstrap),
                                        // which keeps the first live handle.
                                        let _ = tor_handle_cell.set(handle.clone());
                                        let _gossip = crate::federation::gossip::spawn(
                                            pool,
                                            fed_cfg,
                                            bjj_key,
                                            bjj_pubkey,
                                            handle,
                                            // proofs_dir is needed for
                                            // build_own_checkpoint's
                                            // prove_existence call (H-11/M-5
                                            // producer-side closure). When
                                            // None, build_own_checkpoint
                                            // returns Err and the gossip
                                            // round skips emission.
                                            fed_proofs_dir.clone(),
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "federation: Tor bootstrap failed; gossip not started: {e}"
                                        );
                                    }
                                }
                            });
                        }

                        std::future::pending::<()>().await;
                    });
            });

            let (port, db_error, embedded, initial_secrets) = rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("axum server failed to report port within 30s: {e}"),
                ))?;

            app.manage(ApiState { port });
            app.manage(DbErrorState { error: db_error });
            app.manage(EmbeddedDbState {
                inner: std::sync::Mutex::new(embedded),
            });
            app.manage(InitialSecretsState {
                inner: std::sync::Mutex::new(initial_secrets),
            });

            // Surface fatal-style startup config errors to the GUI rather
            // than letting them die only on stderr. Currently populated by
            // the OLYMPUS_ENV=production placeholder check above; future
            // callers (db_error path, ZK artifact missing, etc.) can also
            // write here.
            let startup_error = if proofs_dir.is_none() && is_prod {
                Some(StartupError {
                    code: "PROD_NO_PROOFS_DIR".to_owned(),
                    message: "OLYMPUS_ENV=production but no usable ZK artifacts \
                              directory was found. Set OLYMPUS_PROOFS_DIR or run \
                              proofs/setup_circuits.sh to populate proofs/keys/."
                        .to_owned(),
                    doc_url: Some(
                        "https://github.com/OlympusLedgerOrg/Olympus/blob/main/proofs/README.md"
                            .to_owned(),
                    ),
                })
            } else {
                None
            };
            app.manage(StartupErrorState {
                inner: std::sync::Mutex::new(startup_error),
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // Stop embedded postgres when the last window closes.
                if let Some(db_state) = window.try_state::<EmbeddedDbState>() {
                    if let Ok(mut guard) = db_state.inner.lock() {
                        if let Some(mut embedded) = guard.take() {
                            // stop_db is async — run it on a throw-away runtime.
                            let rt = tokio::runtime::Runtime::new();
                            if let Ok(rt) = rt {
                                let _ = rt.block_on(embedded.pg.stop_db());
                                eprintln!("[olympus-desktop] embedded postgres stopped cleanly");
                            }
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_api_port,
            get_db_error,
            commit_file,
            take_initial_secrets,
            get_startup_error,
            open_file_dialog,
            verify_redaction_binding,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
