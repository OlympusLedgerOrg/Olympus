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

/// Re-derive the `redactedCommitment` public signal from a dropped file +
/// the bundle's `reveal_mask`, so the desktop auditor can prove the dropped
/// bytes are the ones the proof commits to (not just that the proof math
/// is internally consistent).
///
/// Reuses the same `chunk_tree_from_bytes` + `redaction_commitment` paths
/// the prover used — byte-identical guarantees by construction, no
/// JS-Poseidon parameter-matching risk.
///
/// Returns `true` iff `computed_commitment_dec == expected_commitment_dec`.
/// `expected_commitment_dec` is `publicSignals[2]` from the bundle.
#[tauri::command]
pub(crate) fn verify_redaction_binding(
    file_bytes: Vec<u8>,
    reveal_mask: Vec<u8>,
    expected_commitment_dec: String,
) -> Result<bool, String> {
    use ark_ff::{BigInteger, PrimeField};
    const EXPECTED_MASK_LEN: usize = crate::zk::witness::redaction::MAX_LEAVES;

    if file_bytes.len() > IPC_BYTES_LIMIT {
        return Err(format!(
            "file exceeds {IPC_BYTES_LIMIT} byte IPC cap (got {}, audit F-2)",
            file_bytes.len()
        ));
    }
    if reveal_mask.len() != EXPECTED_MASK_LEN {
        return Err(format!(
            "reveal_mask must have {EXPECTED_MASK_LEN} entries; got {}",
            reveal_mask.len()
        ));
    }
    for (i, &b) in reveal_mask.iter().enumerate() {
        if b > 1 {
            return Err(format!("reveal_mask[{i}] = {b} is not 0 or 1"));
        }
    }

    let tree = crate::zk::chunk::chunk_tree_from_bytes(&file_bytes).map_err(|e| e.to_string())?;

    let mask_bool: Vec<bool> = reveal_mask.iter().map(|&b| b == 1).collect();
    let revealed_count = mask_bool.iter().filter(|&&b| b).count() as u64;

    let commit =
        crate::zk::poseidon::redaction_commitment(revealed_count, &tree.leaves, &mask_bool)
            .map_err(|e| e.to_string())?;

    let bytes_be = commit.into_bigint().to_bytes_be();
    let computed_dec = num_bigint::BigUint::from_bytes_be(&bytes_be).to_string();
    Ok(computed_dec == expected_commitment_dec.trim())
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
