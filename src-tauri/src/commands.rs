//! Tauri IPC command handlers and their managed-state types.
//!
//! Extracted from `main.rs`. The state structs are `pub(crate)` (constructed by
//! `main`'s setup hook and read by `on_window_event`); the `#[tauri::command]`
//! handlers are `pub(crate)` so `tauri::generate_handler!` in `main` can wire
//! them. The IPC byte cap and the file-picker payload type stay private here.

use crate::db;

pub(crate) struct ApiState {
    pub(crate) port: u16,
}

#[tauri::command]
pub(crate) fn get_api_port(state: tauri::State<ApiState>) -> u16 {
    state.port
}

pub(crate) struct DbErrorState {
    pub(crate) error: Option<String>,
}

#[tauri::command]
pub(crate) fn get_db_error(state: tauri::State<DbErrorState>) -> Option<String> {
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

    let file = std::fs::File::open(&path).map_err(|e| format!("open {path}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("stat {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    if meta.len() > IPC_BYTES_LIMIT as u64 {
        return Err(format!(
            "file {path} exceeds {} byte IPC cap ({} bytes on disk)",
            IPC_BYTES_LIMIT,
            meta.len(),
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(IPC_BYTES_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() > IPC_BYTES_LIMIT {
        return Err(format!(
            "file {path} grew past {IPC_BYTES_LIMIT} byte cap during read (TOCTOU)"
        ));
    }

    // 30% — base64-encode in Rust (never touches JS memory) and POST to Axum
    let _ = on_progress.send(ProgressEvent {
        percent: 30,
        label: "sending",
    });

    let original_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    drop(bytes); // free before the network round-trip

    let port = api_state.port;
    let url = format!("http://127.0.0.1:{port}/redaction/redact");

    let mut req = reqwest::Client::new().post(&url);
    if let Some(key) = api_key.as_deref().filter(|k| !k.is_empty()) {
        req = req.header("X-API-Key", key);
    }
    let resp = req
        .json(&serde_json::json!({
            "original_base64": original_base64,
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
// Keychain, Linux libsecret). The service name is fixed; the `key` parameter
// becomes the account name within that service.

const KEYCHAIN_SERVICE: &str = "olympus-desktop";

/// Reject IPC access to keychain accounts that hold non-UI secrets. The BJJ
/// authority private key (written by `bootstrap`) lives in this same keychain
/// service under `BJJ_KEYCHAIN_ACCOUNT`; handing it to the renderer would leak
/// the SBT / federation signing authority. Only operator-facing secrets (the
/// API key) are reachable from JS.
fn guard_keychain_key(key: &str) -> Result<(), String> {
    if key == crate::bootstrap::BJJ_KEYCHAIN_ACCOUNT {
        return Err(format!(
            "keychain key '{key}' is reserved and not accessible from the UI"
        ));
    }
    Ok(())
}

/// Read a value from the OS keychain. Returns `None` if no entry exists for
/// this key (not an error — callers use it for "first launch" detection).
#[tauri::command]
pub(crate) fn keychain_get(key: String) -> Result<Option<String>, String> {
    guard_keychain_key(&key)?;
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &key).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(val) => Ok(Some(val)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Write a value to the OS keychain, creating or updating the entry.
#[tauri::command]
pub(crate) fn keychain_set(key: String, value: String) -> Result<(), String> {
    guard_keychain_key(&key)?;
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &key).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())
}

/// Delete a keychain entry. Idempotent — no error if the entry does not exist.
#[tauri::command]
pub(crate) fn keychain_delete(key: String) -> Result<(), String> {
    guard_keychain_key(&key)?;
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &key).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
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
    fn keychain_guard_blocks_bjj_authority_key() {
        // The BJJ authority private key must never be reachable from the
        // renderer via the keychain IPC surface.
        assert!(guard_keychain_key(crate::bootstrap::BJJ_KEYCHAIN_ACCOUNT).is_err());
        assert!(guard_keychain_key("bjj_authority_key").is_err());
        // Operator-facing secrets stay reachable.
        assert!(guard_keychain_key("api_key").is_ok());
    }
}
