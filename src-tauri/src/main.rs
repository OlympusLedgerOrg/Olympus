#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Match lib.rs: the bin re-includes the same module tree, so without this
// every item not reachable from `main` is reported as dead code.
#![allow(dead_code, unused_imports)]

mod anchoring;
mod api;
mod bootstrap;
mod db;
mod integrity;
mod quorum;
mod routes;
mod server;
mod smt;
mod state;
mod zk;
#[cfg(feature = "federation")]
mod federation;

use tauri::Manager;

struct ApiState {
    port: u16,
}

#[tauri::command]
fn get_api_port(state: tauri::State<ApiState>) -> u16 {
    state.port
}

struct DbErrorState {
    error: Option<String>,
}

#[tauri::command]
fn get_db_error(state: tauri::State<DbErrorState>) -> Option<String> {
    state.error.clone()
}

/// Cap any single IPC-supplied `Vec<u8>` to match the Axum-side body limit
/// (128 MiB). The Tauri IPC channel itself has no built-in upper bound; a
/// compromised webview could otherwise allocate ~3× this in Rust heap via
/// serialize → IPC → Vec<u8> → reqwest multipart copies. Audit finding F-2.
const IPC_BYTES_LIMIT: usize = 128 * 1024 * 1024;

/// Proxy a file commit through Tauri IPC so the webview avoids cross-origin /
/// mixed-content restrictions.  The frontend sends the file bytes + metadata;
/// we POST them to the local Axum server from the native side.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn commit_file(
    api_state: tauri::State<'_, ApiState>,
    api_key: String,
    file_bytes: Vec<u8>,
    file_name: String,
    shard_id: String,
    record_id: String,
    version: u32,
    original_hash: Option<String>,
) -> Result<serde_json::Value, String> {
    // F-2: refuse oversize uploads at the IPC boundary, before any further
    // allocation (reqwest::multipart::Part::bytes would clone, etc.).
    if file_bytes.len() > IPC_BYTES_LIMIT {
        return Err(format!(
            "file exceeds {} byte IPC cap (got {}, audit F-2)",
            IPC_BYTES_LIMIT,
            file_bytes.len()
        ));
    }
    // M-IPC-1: cap the multipart filename at 256 bytes. The downstream Axum
    // ingest endpoint validates `shard_id`/`record_id` but never inspects the
    // multipart filename; refusing pathologically long values here keeps log
    // lines, error responses, and the multipart header itself bounded.
    if file_name.len() > 256 {
        return Err(format!(
            "file_name exceeds 256 byte IPC cap (got {}, audit M-IPC-1)",
            file_name.len()
        ));
    }
    let port = api_state.port;
    let url = format!("http://127.0.0.1:{port}/ingest/files");

    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(file_name)
        .mime_str("application/octet-stream")
        .map_err(|e| e.to_string())?;

    let mut form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("shard_id", shard_id)
        .text("record_id", record_id)
        .text("version", version.to_string());

    if let Some(oh) = original_hash {
        if !oh.is_empty() {
            form = form.text("original_hash", oh);
        }
    }

    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-API-Key", &api_key)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Response parse error: {e}"))?;

    if status >= 400 {
        let detail = body.get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(format!("HTTP {status}: {detail}"));
    }

    Ok(body)
}

/// Holds the embedded PG instance so it can be stopped cleanly on exit.
/// Wrapped in Mutex so the on-exit handler can take ownership.
struct EmbeddedDbState {
    inner: std::sync::Mutex<Option<db::EmbeddedDb>>,
}

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
struct InitialSecretsState {
    inner: std::sync::Mutex<Option<InitialSecretsSerde>>,
}

// No `#[derive(Clone)]`: `Zeroizing<String>::clone()` would still scrub the
// clone on Drop, but every extra copy widens the window where the secret is
// live in memory. The only consumer is `take_initial_secrets`, which *moves*
// the value out of the Mutex via `Option::take`, so Clone is unused.
// CodeRabbit nit on PR #1055.
struct InitialSecretsSerde {
    /// `oly_…` raw admin API key (only present when freshly created).
    system_api_key: Option<zeroize::Zeroizing<String>>,
    /// 64-char hex BJJ authority private key (only when freshly created).
    bjj_authority_key_hex: Option<zeroize::Zeroizing<String>>,
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
fn take_initial_secrets(
    state: tauri::State<'_, InitialSecretsState>,
) -> Option<InitialSecretsSerde> {
    state.inner.lock().ok().and_then(|mut guard| guard.take())
}

/// In-app startup error surface. Replaces stderr-only failures
/// (placeholder ZK artifacts under `OLYMPUS_ENV=production`, missing
/// proofs_dir, BJJ key required but absent, …) with a GUI screen so
/// the user knows why the app refuses to function.
#[derive(Clone, Default, serde::Serialize)]
struct StartupError {
    code: String,
    message: String,
    /// Optional docs URL the user can read for context.
    doc_url: Option<String>,
}

struct StartupErrorState {
    inner: std::sync::Mutex<Option<StartupError>>,
}

#[tauri::command]
fn get_startup_error(state: tauri::State<'_, StartupErrorState>) -> Option<StartupError> {
    state.inner.lock().ok().and_then(|g| g.clone())
}

#[derive(Clone, serde::Serialize)]
struct PickedFile {
    /// The basename, so the frontend can build a `File` with the original
    /// filename without re-parsing the path.
    name: String,
    /// Full path the user picked (informational; the bytes are already
    /// in `bytes`, so the frontend doesn't need to round-trip through FS).
    path: String,
    /// The raw file contents. Serde maps Vec<u8> → JSON array of numbers,
    /// which Tauri's invoke wraps efficiently for the webview side.
    bytes: Vec<u8>,
}

/// Native file picker + read. Tauri dialog plugin opens the GTK chooser
/// (which under WSLg can navigate to /mnt/c/Users/...) or the Win32
/// picker, and we slurp the bytes in Rust so the frontend doesn't need
/// an extra `@tauri-apps/plugin-fs` JS dep.
///
/// Returns `None` on user cancel. Returns an error on read failure
/// (e.g. permission denied, file vanished between pick and read).
#[tauri::command]
async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<PickedFile>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel::<Option<std::path::PathBuf>>();
    app.dialog()
        .file()
        .set_title("Select a file to commit to the ledger")
        .pick_file(move |path| {
            let _ = tx.send(path.and_then(|p| p.into_path().ok()));
        });
    let path = match rx.recv().ok().flatten() {
        Some(p) => p,
        None => return Ok(None),
    };

    // F-2: refuse oversize files BEFORE allocating a Vec<u8> for the entire
    // contents, and read through a SINGLE file handle so the size check and
    // the read can't be split by a concurrent grow/replace.
    //
    // Previous revision called `std::fs::metadata(&path)` then `std::fs::read(
    // &path)` — two independent path resolutions. Between them an attacker
    // could replace the file with a larger one and bypass the cap (CodeRabbit
    // review on PR #1055). Open once; stat via the file handle; cap the
    // actual read at IPC_BYTES_LIMIT + 1 via `Read::take` so even a sparse-
    // file lie about metadata length cannot blow past the limit at read time.
    use std::io::Read as _;
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    // Explicit regular-file guard: the dialog plugin restricts to files but
    // a malicious caller bypassing the picker (or a symlink whose target
    // changed) could hand us a directory, device, FIFO, or socket. Reject
    // those up front with a clear error rather than letting `read_to_end`
    // fail later with an opaque OS message. CodeRabbit nit.
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file",
            path.display()
        ));
    }
    if meta.len() > IPC_BYTES_LIMIT as u64 {
        return Err(format!(
            "file {} exceeds {} byte IPC cap ({} bytes on disk, audit F-2)",
            path.display(),
            IPC_BYTES_LIMIT,
            meta.len(),
        ));
    }
    let mut bytes = Vec::new();
    // `IPC_BYTES_LIMIT + 1`: the sentinel byte lets us *detect* a TOCTOU
    // grow past the limit (bytes.len() > IPC_BYTES_LIMIT below) while still
    // bounding the worst-case allocation. Without the +1, a file that
    // grows to exactly the limit + 1 byte would read to exactly the
    // limit, and we'd be unable to tell the difference from a clean
    // limit-sized read.
    (&file)
        .take(IPC_BYTES_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() > IPC_BYTES_LIMIT {
        return Err(format!(
            "file {} grew past {} byte IPC cap during read (TOCTOU, audit F-2)",
            path.display(),
            IPC_BYTES_LIMIT,
        ));
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("selected-file")
        .to_owned();
    Ok(Some(PickedFile {
        name,
        path: path.to_string_lossy().into_owned(),
        bytes,
    }))
}

/// Resolve where ZK circuit artifacts (.wasm/.r1cs/.ark.zkey/vkey JSON) live.
///
/// Order of precedence:
/// 1. `OLYMPUS_PROOFS_DIR` env var — operator override.
/// 2. Tauri resource dir + `proofs/keys` — production bundle path.
/// 3. Directory containing the running binary + `proofs/keys` — packaged
///    distributions that copy artifacts next to the executable.
/// 4. `proofs/keys` relative to the current working directory — `cargo tauri dev`
///    from the repo root.
///
/// A candidate is accepted only if its `verification_keys/` subdirectory exists;
/// otherwise it's a misconfigured shell with no real artifacts. Returns `None`
/// if no candidate qualifies — `/zk/*` routes then 503 with a clear message
/// pointing at `OLYMPUS_PROOFS_DIR`.
fn resolve_proofs_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    let candidates: Vec<std::path::PathBuf> = std::iter::empty()
        .chain(
            std::env::var_os("OLYMPUS_PROOFS_DIR").map(std::path::PathBuf::from),
        )
        .chain(
            app.path()
                .resource_dir()
                .ok()
                .map(|d| d.join("proofs").join("keys")),
        )
        .chain(
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .map(|d| d.join("proofs").join("keys")),
        )
        .chain(std::iter::once(std::path::PathBuf::from("proofs/keys")))
        .collect();

    candidates
        .into_iter()
        .find(|c| c.join("verification_keys").is_dir())
}

/// First 12 bytes of every committed placeholder artifact (`PLACEHOLDER\n` or
/// `{"placeholder` for JSON). Used to refuse to start a "production" build
/// against pre-setup artifact shells.
const PLACEHOLDER_PREFIX: &[u8] = b"PLACEHOLDER";
const JSON_PLACEHOLDER_PREFIX: &[u8] = b"{\"placeholder";

/// Scan a resolved proofs dir for placeholder (un-built) artifacts and return
/// the list of offending paths. Inspects only the first 16 bytes of each file.
fn detect_placeholder_artifacts(proofs_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    use std::io::Read;
    // `federation_quorum` is only required in builds compiled with the
    // `quorum-circuit` cargo feature (next-phase, ceremony-pending — same
    // posture as `unified-circuit`). Default builds ship without it and must
    // not refuse to start over its placeholder artifact.
    #[cfg(feature = "quorum-circuit")]
    let circuits: &[&str] = &[
        "document_existence",
        "non_existence",
        "redaction_validity",
        "unified_canonicalization_inclusion_root_sign",
        "federation_quorum",
    ];
    #[cfg(not(feature = "quorum-circuit"))]
    let circuits: &[&str] = &[
        "document_existence",
        "non_existence",
        "redaction_validity",
        "unified_canonicalization_inclusion_root_sign",
    ];
    let mut offenders = Vec::new();
    let mut head = [0u8; 16];
    let mut check = |p: std::path::PathBuf, prefix: &[u8]| {
        if let Ok(mut f) = std::fs::File::open(&p) {
            let n = f.read(&mut head).unwrap_or(0);
            if n >= prefix.len() && head[..prefix.len()] == *prefix {
                offenders.push(p);
            }
        }
    };
    for c in circuits {
        check(proofs_dir.join(format!("{c}.wasm")), PLACEHOLDER_PREFIX);
        check(proofs_dir.join(format!("{c}.r1cs")), PLACEHOLDER_PREFIX);
        check(proofs_dir.join(format!("{c}.ark.zkey")), PLACEHOLDER_PREFIX);
        check(
            proofs_dir
                .join("verification_keys")
                .join(format!("{c}_vkey.json")),
            JSON_PLACEHOLDER_PREFIX,
        );
    }
    offenders
}

fn main() {
    // Initialise tracing → stderr so warn!/error! from request handlers and
    // background tasks (snapshot build, anchoring, etc.) are visible during
    // dev. Honour RUST_LOG; default to `info,olympus_desktop=debug` so our
    // own crate's warnings surface without drowning in third-party noise.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,olympus_desktop=debug")),
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
                        // client, BJJ key + pubkey) and is a no-op when no
                        // OLYMPUS_ANCHOR_* URLs are configured, so the default
                        // build does no outbound network calls.
                        let _anchor_cron = app_state.pool.as_ref().map(|pool| {
                            crate::anchoring::cron::spawn(
                                pool.clone(),
                                app_state.anchoring.clone(),
                                app_state.anchor_http.clone(),
                                app_state.bjj_authority_key,
                                app_state.bjj_authority_pubkey.clone(),
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
                                    app_state.bjj_authority_pubkey.clone(),
                                ) {
                                    (Some(pool), Some(bjj_key), Some(bjj_pubkey)) => {
                                        Some((pool, fed_cfg, bjj_key, bjj_pubkey, state_dir, proofs_dir, tor_handle_cell))
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
                        )) = federation_bootstrap
                        {
                            tokio::spawn(async move {
                                tracing::info!(
                                    "federation: bootstrapping Tor hidden service (may take 30-60s)"
                                );
                                match crate::federation::tor::start_hidden_service(
                                    state_dir, local_port,
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
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
