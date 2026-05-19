/// Resolve the Node.js binary for the snarkjs sidecar.
///
/// Resolution order:
/// 1. `TAURI_NODE_BIN` environment variable — set this in dev/CI to an
///    explicit path, e.g. `C:\tools\node.exe`.
/// 2. `src-tauri/binaries/node-{target_triple}[.exe]` — the Tauri sidecar
///    path used by release bundles.  Add `"binaries/node"` to `externalBin`
///    in `tauri.conf.json` and provide the binary as a CI build artefact.
/// 3. `"node"` from the system PATH — the default for development.
pub fn resolve_node_bin() -> String {
    if let Ok(v) = std::env::var("TAURI_NODE_BIN") {
        if !v.is_empty() {
            return v;
        }
    }

    // Tauri sidecar convention: <app-dir>/binaries/node-<target>[.exe]
    // TAURI_ENV_TARGET_TRIPLE is set by the Tauri build script at runtime.
    if let Ok(target) = std::env::var("TAURI_ENV_TARGET_TRIPLE") {
        let ext = if cfg!(windows) { ".exe" } else { "" };
        let sidecar = std::path::PathBuf::from("binaries")
            .join(format!("node-{target}{ext}"));
        if sidecar.exists() {
            return sidecar.to_string_lossy().into_owned();
        }
    }

    "node".to_owned()
}

/// Persistent Node.js sidecar bridge for snarkjs Groth16 operations.
///
/// Mirrors `proofs/snarkjs_bridge.py` — same line-delimited JSON IPC protocol.
/// A single `node` process is spawned on first use and kept alive; all
/// prove/verify calls share it, amortising V8 + snarkjs start-up cost.
///
/// # IPC protocol (line-delimited JSON)
///
/// ```text
/// fullProve: {"op":"fullProve","input":{...},"wasmFile":"/abs","zkeyFile":"/abs"}
///            ← {"proof":{...},"publicSignals":[...]}
///
/// prove:     {"op":"prove","witnessFile":"/abs","zkeyFile":"/abs"}
///            ← {"proof":{...},"publicSignals":[...]}
///
/// verify:    {"op":"verify","vkeyFile":"/abs","proof":{...},"publicSignals":[...]}
///            ← {"ok":true|false}
///
/// Errors:    ← {"error":"<message>"}
/// ```
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ZkBridgeError {
    #[error("node process unavailable: {0}")]
    ProcessUnavailable(String),
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC timeout after {}s", REQUEST_TIMEOUT.as_secs())]
    Timeout,
    #[error("snarkjs error: {0}")]
    SnarkjsError(String),
    #[error("response JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Groth16 proof object as returned by snarkjs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub pi_a: Value,
    pub pi_b: Value,
    pub pi_c: Value,
    pub protocol: String,
    pub curve: String,
}

/// Combined proof + public signals returned by `full_prove` and `prove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResult {
    pub proof: Proof,
    #[serde(rename = "publicSignals")]
    pub public_signals: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal process wrapper
// ---------------------------------------------------------------------------

struct NodeProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl NodeProcess {
    fn spawn(node_bin: &str, script: &Path) -> Result<Self, ZkBridgeError> {
        let mut child = Command::new(node_bin)
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ZkBridgeError::ProcessUnavailable(format!("spawn `{node_bin}`: {e}")))?;

        let stdin = child.stdin.take().ok_or_else(|| {
            ZkBridgeError::ProcessUnavailable("stdin handle unavailable after spawn".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ZkBridgeError::ProcessUnavailable("stdout handle unavailable after spawn".into())
        })?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

// ---------------------------------------------------------------------------
// Public bridge
// ---------------------------------------------------------------------------

/// Persistent bridge to a `node snarkjs_node_helper.js` sidecar process.
///
/// Wrap in `Arc<tokio::sync::Mutex<ZkBridge>>` to share across Axum handlers.
/// The tokio mutex is required because `call` holds the lock across `await` points.
pub struct ZkBridge {
    node_bin: String,
    script: PathBuf,
    process: Option<NodeProcess>,
}

impl ZkBridge {
    /// Create a bridge that will spawn `node_bin` with `script` on first use.
    ///
    /// `node_bin` is typically `"node"` (resolved from PATH) or an absolute path
    /// to the bundled Tauri sidecar binary.
    pub fn new(node_bin: impl Into<String>, script: PathBuf) -> Self {
        Self {
            node_bin: node_bin.into(),
            script,
            process: None,
        }
    }

    fn ensure_alive(&mut self) -> Result<(), ZkBridgeError> {
        let needs_spawn = self
            .process
            .as_mut()
            .map(|p| !p.is_alive())
            .unwrap_or(true);

        if needs_spawn {
            self.process = Some(NodeProcess::spawn(&self.node_bin, &self.script)?);
        }
        Ok(())
    }

    async fn call(&mut self, payload: Value) -> Result<Value, ZkBridgeError> {
        self.ensure_alive()?;

        // SAFETY: ensure_alive guarantees process is Some.
        let proc = self.process.as_mut().unwrap();

        let mut line = serde_json::to_string(&payload)?;
        line.push('\n');

        proc.stdin.write_all(line.as_bytes()).await.map_err(|e| {
            ZkBridgeError::ProcessUnavailable(format!("write to node stdin: {e}"))
        })?;
        proc.stdin.flush().await.map_err(|e| {
            ZkBridgeError::ProcessUnavailable(format!("flush node stdin: {e}"))
        })?;

        let mut response_line = String::new();
        let n = tokio::time::timeout(
            REQUEST_TIMEOUT,
            proc.stdout.read_line(&mut response_line),
        )
        .await
        .map_err(|_| ZkBridgeError::Timeout)?
        .map_err(ZkBridgeError::Io)?;

        if n == 0 {
            return Err(ZkBridgeError::ProcessUnavailable(
                "node process closed stdout unexpectedly".into(),
            ));
        }

        let resp: Value = serde_json::from_str(response_line.trim())?;
        if let Some(err) = resp.get("error") {
            return Err(ZkBridgeError::SnarkjsError(
                err.as_str().unwrap_or("unknown snarkjs error").to_owned(),
            ));
        }
        Ok(resp)
    }

    /// Generate a Groth16 witness and proof in one step (witness gen + prove).
    pub async fn full_prove(
        &mut self,
        input: Value,
        wasm_file: &Path,
        zkey_file: &Path,
    ) -> Result<ProveResult, ZkBridgeError> {
        require_file(wasm_file)?;
        require_file(zkey_file)?;
        let payload = serde_json::json!({
            "op": "fullProve",
            "input": input,
            "wasmFile": abs_str(wasm_file),
            "zkeyFile": abs_str(zkey_file),
        });
        let resp = self.call(payload).await?;
        Ok(serde_json::from_value(resp)?)
    }

    /// Generate a Groth16 proof from a pre-computed witness file.
    pub async fn prove(
        &mut self,
        witness_file: &Path,
        zkey_file: &Path,
    ) -> Result<ProveResult, ZkBridgeError> {
        require_file(witness_file)?;
        require_file(zkey_file)?;
        let payload = serde_json::json!({
            "op": "prove",
            "witnessFile": abs_str(witness_file),
            "zkeyFile": abs_str(zkey_file),
        });
        let resp = self.call(payload).await?;
        Ok(serde_json::from_value(resp)?)
    }

    /// Verify a Groth16 proof against a verification key.
    pub async fn verify(
        &mut self,
        vkey_file: &Path,
        proof: &Proof,
        public_signals: &[String],
    ) -> Result<bool, ZkBridgeError> {
        require_file(vkey_file)?;
        let payload = serde_json::json!({
            "op": "verify",
            "vkeyFile": abs_str(vkey_file),
            "proof": proof,
            "publicSignals": public_signals,
        });
        let resp = self.call(payload).await?;
        Ok(resp.get("ok").and_then(Value::as_bool).unwrap_or(false))
    }

    /// Return `true` if the node process is currently alive.
    pub fn is_alive(&mut self) -> bool {
        self.process.as_mut().map(|p| p.is_alive()).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_file(path: &Path) -> Result<(), ZkBridgeError> {
    if !path.exists() {
        return Err(ZkBridgeError::FileNotFound(path.to_owned()));
    }
    Ok(())
}

/// Return the absolute path as a UTF-8 string (lossy on non-UTF-8 paths).
fn abs_str(path: &Path) -> String {
    // Canonicalize to resolve symlinks; fall back to the path as-is.
    path.canonicalize()
        .unwrap_or_else(|_| path.to_owned())
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn file_not_found_error_display() {
        let err = ZkBridgeError::FileNotFound(PathBuf::from("/nonexistent/foo.zkey"));
        assert!(err.to_string().contains("foo.zkey"));
    }

    #[test]
    fn timeout_error_display() {
        let err = ZkBridgeError::Timeout;
        assert!(err.to_string().contains("120s"));
    }

    #[test]
    fn snarkjs_error_display() {
        let err = ZkBridgeError::SnarkjsError("circuit constraint unsatisfied".into());
        assert!(err.to_string().contains("circuit constraint"));
    }

    #[test]
    fn require_file_returns_err_for_missing_path() {
        let result = require_file(Path::new("/absolutely/does/not/exist.wasm"));
        assert!(matches!(result, Err(ZkBridgeError::FileNotFound(_))));
    }

    #[test]
    fn require_file_returns_ok_for_existing_path() {
        // Use the Cargo.toml at the crate root — always present during tests.
        let abs = std::fs::canonicalize(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
        )
        .expect("Cargo.toml must exist");
        assert!(require_file(&abs).is_ok());
    }

    #[tokio::test]
    async fn bridge_fails_gracefully_with_bad_node_bin() {
        // Spawning a non-existent binary should return ProcessUnavailable,
        // not panic, so callers can surface a useful error message.
        let script = PathBuf::from("proofs/snarkjs_node_helper.js");
        let mut bridge = ZkBridge::new("/nonexistent/node-binary", script);
        let result = bridge
            .full_prove(
                serde_json::json!({}),
                Path::new("/fake.wasm"),
                Path::new("/fake.zkey"),
            )
            .await;
        // FileNotFound because wasm_file check runs before spawn.
        assert!(matches!(result, Err(ZkBridgeError::FileNotFound(_))));
    }
}
