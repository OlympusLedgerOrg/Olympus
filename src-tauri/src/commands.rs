//! Tauri IPC command handlers and their managed-state types.
//!
//! Extracted from `main.rs`. The state structs are `pub(crate)` (constructed by
//! `main`'s setup hook and read by `on_window_event`); the `#[tauri::command]`
//! handlers are `pub(crate)` so `tauri::generate_handler!` in `main` can wire
//! them. The IPC byte cap and the file-picker payload type stay private here.

use crate::db;
use tauri::Manager;

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
    fn ready_port(&self) -> Result<u16, String> {
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

/// Cap any single IPC-supplied `Vec<u8>` to match the Axum-side body limit
/// (128 MiB). The Tauri IPC channel itself has no built-in upper bound; a
/// compromised webview could otherwise allocate ~3× this in Rust heap via
/// serialize → IPC → Vec<u8> → reqwest multipart copies. Audit finding F-2.
const IPC_BYTES_LIMIT: usize = 128 * 1024 * 1024;

/// Cap for the display-only render read (ADR-0029 A.5-4, `read_file_for_render`).
///
/// Deliberately well below [`IPC_BYTES_LIMIT`]. Those 128 MiB bound what the app
/// will *commit or redact*, where refusing a file fails the operator's actual
/// task. This bounds what it copies into the webview purely so pdf.js can draw a
/// page, and refusing that costs only the drag-box affordance — the object
/// checklist still works on the same document. The asymmetry is the point: the
/// renderer holds this buffer *and* the canvas backing store at once, so the
/// cheap failure is the one worth having.
const RENDER_BYTES_LIMIT: usize = 64 * 1024 * 1024;

// Enforced at compile time rather than by a test: if the two caps ever converge,
// a file the app can still redact is one it also copies wholesale into the
// webview — the exact trade `RENDER_BYTES_LIMIT` exists to refuse. Making that
// unbuildable beats catching it in CI.
const _: () = assert!(
    RENDER_BYTES_LIMIT < IPC_BYTES_LIMIT,
    "the display-only render cap must stay strictly below the commit/redact IPC cap"
);

/// Proxy a file commit through Tauri IPC so the webview avoids cross-origin /
/// mixed-content restrictions.  The frontend sends the file bytes + metadata;
/// we POST them to the local Axum server from the native side.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_file(
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
    let port = api_state.ready_port()?;
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
        let detail = body
            .get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(format!("HTTP {status}: {detail}"));
    }

    Ok(body)
}

/// Holds the embedded PG instance so it can be stopped cleanly on exit.
/// Wrapped in Mutex so the on-exit handler can take ownership.
pub(crate) struct EmbeddedDbState {
    pub(crate) inner: std::sync::Mutex<Option<db::EmbeddedDb>>,
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

#[derive(Clone, serde::Serialize)]
pub(crate) struct PickedFile {
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

/// Lightweight file-picker that returns only the path and name — no bytes.
/// Use instead of `open_file_dialog` when the byte contents are not needed in
/// JS (e.g. the path-based redaction flow that reads the file in Rust).
#[derive(Clone, serde::Serialize)]
pub(crate) struct FileMeta {
    name: String,
    path: String,
}

#[tauri::command]
pub(crate) async fn pick_file_path(app: tauri::AppHandle) -> Result<Option<FileMeta>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<std::path::PathBuf>>();
    app.dialog()
        .file()
        .set_title("Select a document to redact")
        .pick_file(move |path| {
            let _ = tx.send(path.and_then(|p| p.into_path().ok()));
        });
    let path = match rx.await.ok().flatten() {
        Some(p) => p,
        None => return Ok(None),
    };
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("document")
        .to_owned();
    Ok(Some(FileMeta {
        name,
        path: path.to_string_lossy().into_owned(),
    }))
}

/// BLAKE3-hash a file on disk without loading the bytes into JS memory.
/// Returns the hex-encoded digest, identical to the server's `content_hash`.
/// Streams the file in 64 KiB blocks so it never allocates the full contents.
#[tauri::command]
pub(crate) async fn hash_file_for_manifest(path: String) -> Result<String, String> {
    use std::io::{BufReader, Read as _};
    let file = std::fs::File::open(&path).map_err(|e| format!("open {path}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("stat {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    if meta.len() > IPC_BYTES_LIMIT as u64 {
        return Err(format!(
            "file {path} exceeds {} byte cap ({} bytes on disk)",
            IPC_BYTES_LIMIT,
            meta.len(),
        ));
    }
    let mut hasher = blake3::Hasher::new();
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 65536];
    // Enforce the cap during the whole stream, not just at the initial stat:
    // a file that grows after the metadata check (TOCTOU) must not be hashed
    // unbounded. Mirrors the `.take(IPC_BYTES_LIMIT + 1)` guard in
    // `redact_by_path`.
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > IPC_BYTES_LIMIT as u64 {
            return Err(format!(
                "file {path} grew past {IPC_BYTES_LIMIT} byte cap during read (TOCTOU)"
            ));
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// Read a regular file into memory under `limit` bytes.
///
/// The cap is enforced twice on purpose: once against the `stat` size to reject
/// an oversize file before allocating anything, and again across the read itself
/// so a file that *grows* after the metadata check (TOCTOU) still cannot push
/// past the limit. `hash_file_for_manifest` applies the same discipline while
/// streaming, and it is the reason this is one helper rather than a copy per
/// caller.
///
/// `limit` is a parameter rather than always [`IPC_BYTES_LIMIT`] because the two
/// kinds of read answer different questions — see [`RENDER_BYTES_LIMIT`].
fn read_file_capped(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("stat {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    if meta.len() > limit as u64 {
        return Err(format!(
            "file {path} exceeds {} byte cap ({} bytes on disk)",
            limit,
            meta.len(),
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() > limit {
        return Err(format!(
            "file {path} grew past {limit} byte cap during read (TOCTOU)"
        ));
    }
    Ok(bytes)
}

/// Read a picked file's bytes for **display only** (ADR-0029 A.5-4, desktop path).
///
/// The desktop path deliberately keeps document bytes out of JS: `onFilePath`
/// hands Rust a path and gets back a hash, and `describe_by_path` /
/// `redact_by_path` do their own reads natively. That is a copy-and-memory
/// discipline rather than a trust boundary — the webview is the same trust
/// domain as the app — and it cost nothing while nothing in JS needed the bytes.
///
/// A.5-4 gave it a consumer. pdf.js draws the page the operator drags a box
/// over, and it runs in the webview. Rendering natively instead would mean a
/// second renderer *and* a second copy of the PDF-user-space → canvas
/// coordinate flip — the one piece of this feature that fails silently when it
/// is wrong, selecting the object mirrored about the page's horizontal axis. One
/// renderer, one flip, one set of tests is worth more than one avoided copy.
///
/// So this is the narrowest thing that unblocks it: raw bytes, capped at
/// [`RENDER_BYTES_LIMIT`], over binary IPC rather than serde's `Vec<u8>` →
/// JSON-array-of-numbers (roughly a 4× blowup on a multi-MB file).
///
/// Presentation-only, exactly like `describe_by_path`: the response never
/// touches a hiding leaf, manifest, or root, the box it enables only *proposes*
/// object ids, and the server re-validates every one against the committed
/// manifest before cutting anything (ADR-0029 §5). Callers treat a failure as
/// non-fatal — the object checklist works on the same document without it.
#[tauri::command]
pub(crate) async fn read_file_for_render(path: String) -> Result<tauri::ipc::Response, String> {
    let bytes = read_file_capped(&path, RENDER_BYTES_LIMIT)?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Path-based object description (ADR-0029 A.5-3): the `describe` counterpart of
/// [`redact_by_path`].
///
/// On the desktop path a picked file never enters JS memory — `onFilePath` hands
/// Rust a path and gets back a hash. That left the producer checklist with no
/// labels at all there, because `POST /redaction/describe` needs the document
/// bytes and the browser-only flow was the one that had them. This reads the
/// file, hashes and base64-encodes it in Rust, and calls the endpoint from the
/// native side, so the desktop path gets the same labels, previews, and
/// placements the browser path already had.
///
/// Presentation-only, exactly like the endpoint it proxies (ADR-0029 §A): the
/// response never touches a hiding leaf, manifest, or root, and callers treat a
/// failure as non-fatal — the plain id/size listing remains.
#[tauri::command]
pub(crate) async fn describe_by_path(
    api_state: tauri::State<'_, ApiState>,
    path: String,
    original_root: Option<String>,
    shard_id: Option<String>,
    api_key: Option<String>,
) -> Result<serde_json::Value, String> {
    use base64::Engine as _;

    let bytes = read_file_capped(&path, IPC_BYTES_LIMIT)?;
    // The endpoint requires `content_hash` to equal BLAKE3 of the uploaded bytes
    // — hash the same buffer we send, so the two cannot disagree.
    let content_hash = hex::encode(blake3::hash(&bytes).as_bytes());
    let original_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    drop(bytes); // free before the round-trip; the base64 copy is what we send

    let port = api_state.ready_port()?;
    let url = format!("http://127.0.0.1:{port}/redaction/describe");

    let mut req = reqwest::Client::new().post(&url);
    if let Some(key) = api_key.as_deref().filter(|k| !k.is_empty()) {
        req = req.header("X-API-Key", key);
    }
    let resp = req
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "original_base64": original_base64,
            "original_root": original_root,
            "shard_id": shard_id,
        }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    // Read the body as text first, then branch on status — parsing as success
    // JSON up front masks every server error (a non-2xx body has a `{detail}`
    // shape, or is empty on a request timeout). Same ordering as
    // `redact_by_path`, for the same reason.
    let status = resp.status().as_u16();
    let body_text = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;

    if status >= 400 {
        let detail = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_else(|| {
                let trimmed = body_text.trim();
                if trimmed.is_empty() {
                    "the server returned an empty response body.".to_string()
                } else {
                    trimmed.to_string()
                }
            });
        return Err(format!("HTTP {status}: {detail}"));
    }

    serde_json::from_str(&body_text).map_err(|e| format!("response parse error: {e}"))
}

/// Progress payload emitted by `redact_by_path` via its IPC channel.
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProgressEvent {
    pub percent: u8,
    pub label: &'static str,
}

/// Path-based redaction: reads the original document directly in Rust (no
/// JS base64 encoding), calls `/redaction/redact`, decodes the redacted bytes
/// in Rust, and saves them via a native save dialog. Emits real-percent
/// progress via `on_progress`. Returns only the bundle JSON (not the redacted
/// bytes) — the redacted artifact is already on disk at `savedPath`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn redact_by_path(
    app: tauri::AppHandle,
    api_state: tauri::State<'_, ApiState>,
    path: String,
    redacted_obj_ids: Vec<u32>,
    recipient_id: String,
    original_root: Option<String>,
    api_key: Option<String>,
    on_progress: tauri::ipc::Channel<ProgressEvent>,
) -> Result<serde_json::Value, String> {
    use base64::Engine as _;
    use std::io::Read as _;

    // 10% — read file from disk
    let _ = on_progress.send(ProgressEvent {
        percent: 10,
        label: "reading",
    });

    let bytes = read_file_capped(&path, IPC_BYTES_LIMIT)?;

    // 30% — base64-encode in Rust (never touches JS memory) and POST to Axum
    let _ = on_progress.send(ProgressEvent {
        percent: 30,
        label: "sending",
    });

    let original_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    drop(bytes); // free before the network round-trip

    let port = api_state.ready_port()?;
    let url = format!("http://127.0.0.1:{port}/redaction/redact");

    let mut req = reqwest::Client::new().post(&url);
    if let Some(key) = api_key.as_deref().filter(|k| !k.is_empty()) {
        req = req.header("X-API-Key", key);
    }
    let resp = req
        .json(&serde_json::json!({
            "original_base64": original_base64,
            "original_root": original_root,
            "redacted_obj_ids": redacted_obj_ids,
            "recipient_id": recipient_id,
        }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    // 70% — parse response
    let _ = on_progress.send(ProgressEvent {
        percent: 70,
        label: "processing",
    });

    // Read the body as text FIRST, then branch on status. Parsing it as the
    // success JSON before checking the status masks every server error: a
    // non-2xx body has a different shape (an `{detail}` error) or is EMPTY (a
    // server-side request-timeout returns `408` with no body), so `.json()`
    // failed with the opaque "response parse error: error decoding response body"
    // instead of surfacing the real status. Read text → branch → parse on success.
    let status = resp.status().as_u16();
    let body_text = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;

    if status >= 400 {
        // Prefer a JSON `detail`; fall back to the raw body, or a human hint when
        // the body is empty (the timeout case the frontend used to mis-report).
        let detail = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_else(|| {
                let trimmed = body_text.trim();
                if trimmed.is_empty() {
                    match status {
                        408 => "the server timed out processing this redaction \
                                (it exceeded the request limit). The document may be \
                                too large, or the server is overloaded."
                            .to_string(),
                        _ => "the server returned an empty response body.".to_string(),
                    }
                } else {
                    trimmed.to_string()
                }
            });
        return Err(format!("HTTP {status}: {detail}"));
    }

    let json_resp: serde_json::Value =
        serde_json::from_str(&body_text).map_err(|e| format!("response parse error: {e}"))?;

    // Decode the redacted artifact in Rust and open a native save dialog
    let redacted_b64 = json_resp
        .get("redactedBase64")
        .and_then(|v| v.as_str())
        .ok_or("missing redactedBase64 in response")?;
    let redacted_bytes = base64::engine::general_purpose::STANDARD
        .decode(redacted_b64)
        .map_err(|e| format!("decode redactedBase64: {e}"))?;

    // 85% — open native save dialog
    let _ = on_progress.send(ProgressEvent {
        percent: 85,
        label: "saving",
    });

    let original_stem = std::path::Path::new(&path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("document");
    let original_ext = std::path::Path::new(&path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let hint = format!("redacted-{original_stem}.{original_ext}");

    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<std::path::PathBuf>>();
    app.dialog()
        .file()
        .set_file_name(&hint)
        .set_title("Save redacted document")
        .save_file(move |path| {
            let _ = tx.send(path.and_then(|p| p.into_path().ok()));
        });

    let saved_path = match rx.await.ok().flatten() {
        Some(p) => {
            std::fs::write(&p, &redacted_bytes)
                .map_err(|e| format!("write {}: {e}", p.display()))?;
            Some(p.to_string_lossy().into_owned())
        }
        None => None, // user cancelled the save dialog
    };

    // 100% — done
    let _ = on_progress.send(ProgressEvent {
        percent: 100,
        label: "done",
    });

    let bundle = json_resp
        .get("bundle")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({ "bundle": bundle, "savedPath": saved_path }))
}

/// Open a native save dialog and write `content` (UTF-8 text) to the chosen
/// path. Returns the saved path, or `None` if the user cancelled.
#[tauri::command]
pub(crate) async fn save_text_to_disk(
    app: tauri::AppHandle,
    content: String,
    filename_hint: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<std::path::PathBuf>>();
    app.dialog()
        .file()
        .set_file_name(&filename_hint)
        .set_title("Save file")
        .save_file(move |path| {
            let _ = tx.send(path.and_then(|p| p.into_path().ok()));
        });
    match rx.await.ok().flatten() {
        Some(p) => {
            std::fs::write(&p, content.as_bytes())
                .map_err(|e| format!("write {}: {e}", p.display()))?;
            Ok(Some(p.to_string_lossy().into_owned()))
        }
        None => Ok(None),
    }
}

// ─── OS keychain ──────────────────────────────────────────────────────────────
// Thin wrappers over the `keyring` crate (Windows Credential Manager, macOS
// Keychain, Linux libsecret). Both the service and account are fixed in native
// code: the renderer must never choose an account within the service that also
// stores non-UI authority material.

const KEYCHAIN_SERVICE: &str = "olympus-desktop";
const API_KEYCHAIN_ACCOUNT: &str = "api_key";
const API_KEY_HEX_LEN: usize = 64;
const KEYCHAIN_UNAVAILABLE: &str = "the OS keychain is unavailable";

fn validate_keychain_api_key(value: &str) -> Result<(), String> {
    if value.len() == API_KEY_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("API key must be exactly 64 hexadecimal characters".to_owned())
    }
}

fn api_keychain_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, API_KEYCHAIN_ACCOUNT)
        .map_err(|_| KEYCHAIN_UNAVAILABLE.to_owned())
}

/// Read the API key from the one renderer-accessible OS-keychain account.
/// Returns `None` if no entry exists (not an error — callers use it for
/// "first launch" detection).
#[tauri::command]
pub(crate) fn keychain_get() -> Result<Option<String>, String> {
    let entry = api_keychain_entry()?;
    match entry.get_password() {
        Ok(value) => {
            validate_keychain_api_key(&value)?;
            Ok(Some(value))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(KEYCHAIN_UNAVAILABLE.to_owned()),
    }
}

/// Write a validated API key to the fixed OS-keychain account.
#[tauri::command]
pub(crate) fn keychain_set(value: String) -> Result<(), String> {
    validate_keychain_api_key(&value)?;
    let entry = api_keychain_entry()?;
    entry
        .set_password(&value)
        .map_err(|_| KEYCHAIN_UNAVAILABLE.to_owned())
}

/// Delete the fixed API-key account. Idempotent if the entry does not exist.
#[tauri::command]
pub(crate) fn keychain_delete() -> Result<(), String> {
    let entry = api_keychain_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(KEYCHAIN_UNAVAILABLE.to_owned()),
    }
}

/// Native file picker + read. Tauri dialog plugin opens the GTK chooser
/// (which under WSLg can navigate to /mnt/c/Users/...) or the Win32
/// picker, and we slurp the bytes in Rust so the frontend doesn't need
/// an extra `@tauri-apps/plugin-fs` JS dep.
///
/// Returns `None` on user cancel. Returns an error on read failure
/// (e.g. permission denied, file vanished between pick and read).
#[tauri::command]
pub(crate) async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<PickedFile>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<std::path::PathBuf>>();
    app.dialog()
        .file()
        .set_title("Select a file to commit to the ledger")
        .pick_file(move |path| {
            let _ = tx.send(path.and_then(|p| p.into_path().ok()));
        });
    let path = match rx.await.ok().flatten() {
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
    let file = std::fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    // Explicit regular-file guard: the dialog plugin restricts to files but
    // a malicious caller bypassing the picker (or a symlink whose target
    // changed) could hand us a directory, device, FIFO, or socket. Reject
    // those up front with a clear error rather than letting `read_to_end`
    // fail later with an opaque OS message. CodeRabbit nit.
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_keychain_account_is_fixed_and_separate_from_authority_material() {
        assert_eq!(API_KEYCHAIN_ACCOUNT, "api_key");
        assert_ne!(API_KEYCHAIN_ACCOUNT, crate::bootstrap::BJJ_KEYCHAIN_ACCOUNT);
    }

    #[test]
    fn keychain_api_key_validation_is_exact_and_bounded() {
        assert!(validate_keychain_api_key(&"ab".repeat(32)).is_ok());
        assert!(validate_keychain_api_key(&"AB".repeat(32)).is_ok());
        assert!(validate_keychain_api_key(&"a".repeat(63)).is_err());
        assert!(validate_keychain_api_key(&"a".repeat(65)).is_err());
        assert!(validate_keychain_api_key(&"g".repeat(64)).is_err());
        assert!(validate_keychain_api_key(&"a".repeat(1_000_000)).is_err());
    }

    #[test]
    fn read_file_capped_honours_the_caller_supplied_limit() {
        // The limit became a parameter so the display-only render read can be
        // bounded independently of the commit/redact read. Prove it is actually
        // the parameter that decides, not a constant that ignores it: the SAME
        // file passes under a generous limit and is refused under a tight one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("doc.bin");
        std::fs::write(&path, vec![0xABu8; 4096]).expect("write");
        let path = path.to_str().expect("utf-8 path");

        let ok = read_file_capped(path, 8192).expect("4096 bytes under an 8192 cap");
        assert_eq!(ok.len(), 4096);

        // Exactly at the limit is allowed — the cap is a maximum, not a strict
        // upper bound, and an off-by-one here would reject legitimate files.
        assert_eq!(
            read_file_capped(path, 4096)
                .expect("4096 bytes under a 4096 cap")
                .len(),
            4096
        );

        let err = read_file_capped(path, 4095).expect_err("4096 bytes over a 4095 cap");
        assert!(err.contains("exceeds"), "unexpected error: {err}");
        assert!(err.contains("4095"), "error should name the cap: {err}");
    }

    fn startup_error(code: &str) -> StartupError {
        StartupError {
            code: code.to_owned(),
            message: format!("{code} happened"),
            doc_url: None,
        }
    }

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

    #[test]
    fn read_file_capped_rejects_a_directory() {
        // A path that is not a regular file must fail with a clear message
        // rather than an opaque read error — same guard the picker relies on.
        //
        // Which message is platform-dependent, and asserting only the Unix one
        // made this fail on Windows. `read_file_capped` opens first and checks
        // `is_file()` second: on Unix, opening a directory succeeds and the
        // guard produces "is not a regular file"; on Windows, `File::open`
        // refuses a directory outright with ERROR_ACCESS_DENIED unless
        // FILE_FLAG_BACKUP_SEMANTICS is set, so the guard is never reached.
        // Both reject — the assertion names the reason each platform actually
        // rejects for, rather than weakening to a bare `is_err()`.
        let dir = tempfile::tempdir().expect("tempdir");
        let err = read_file_capped(dir.path().to_str().expect("utf-8 path"), 4096)
            .expect_err("a directory is not a regular file");

        // `(os error 5)` rather than "Access is denied": the numeric tail is
        // locale-independent, the message text is not.
        #[cfg(windows)]
        let (expected, why) = (
            "os error 5",
            "Windows refusing to open a directory (ERROR_ACCESS_DENIED)",
        );
        #[cfg(not(windows))]
        let (expected, why) = ("not a regular file", "the is_file() guard");

        assert!(
            err.contains(expected),
            "expected the rejection to come from {why}, got: {err}"
        );
    }
}
