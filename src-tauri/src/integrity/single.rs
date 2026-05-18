use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use serde::Serialize;
use tauri::WebviewWindow;
use thiserror::Error;

const CHUNK_BYTES: usize = 1024 * 1024; // 1 MiB read chunks

#[derive(Debug, Error, Serialize)]
pub enum IntegrityError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Crypto failure: {0}")]
    CryptoFailure(String),
}

impl From<std::io::Error> for IntegrityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressPayload {
    path: String,
    bytes_processed: u64,
    total_bytes: u64,
}

/// Stream-hash a single file with BLAKE3 and emit progress events to the window.
/// Returns the lowercase hex digest on success.
pub fn verify_single_file_streaming(
    window: &WebviewWindow,
    path: PathBuf,
) -> Result<String, IntegrityError> {
    let path_str = path.to_string_lossy().into_owned();

    let file = File::open(&path)?;
    let total_bytes = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(CHUNK_BYTES, file);

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut bytes_processed: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        bytes_processed += n as u64;

        // Emit progress every chunk; ignore send errors (window may have closed).
        let _ = window.emit(
            "integrity://progress",
            ProgressPayload {
                path: path_str.clone(),
                bytes_processed,
                total_bytes,
            },
        );
    }

    Ok(hasher.finalize().to_hex().to_string())
}
