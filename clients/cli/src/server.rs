//! Network commands: commit a manifest to an Olympus node and pull record
//! proofs. Compiled only with `--features server` (pulls a blocking reqwest).
//!
//! These map onto the desktop node's existing HTTP surface:
//! * `commit` → `POST /ingest/files` (multipart) — the node hashes the manifest
//!   blob, commits it to the ledger, and returns a `proof_id` + `content_hash`.
//!   The manifest's own `manifest_root` (inside the blob) is thereby anchored.
//! * `fetch`  → `GET /ingest/records/hash/{hash}/verify` — pulls the node's
//!   snapshot proof for a committed blob by its BLAKE3 content hash.

use std::time::Duration;

use crate::args::Args;
use olympus_manifest::DatasetManifest;

fn base_url(a: &Args) -> Result<String, String> {
    Ok(a.req("server")?.trim_end_matches('/').to_string())
}

fn client() -> Result<reqwest::blocking::Client, String> {
    // Bounded timeouts so a stalled node can't hang a pipeline indefinitely.
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

/// `olympus commit --manifest <path> --server <url> [--shard <id>] [--api-key <k>]`
pub fn commit(a: &Args) -> Result<bool, String> {
    let manifest_path = a.req("manifest")?;
    let server = base_url(a)?;
    let shard = a.get_or("shard", "files").to_string();

    let bytes =
        std::fs::read(manifest_path).map_err(|e| format!("reading {manifest_path}: {e}"))?;
    // Parse so we can label the commit with the dataset id/version and confirm
    // the bytes are a real canonical manifest before shipping them.
    let manifest = DatasetManifest::from_json(&bytes).map_err(|e| e.to_string())?;
    let canonical = manifest.to_canonical_bytes().map_err(|e| e.to_string())?;
    let record_id = format!("{}:v{}", manifest.dataset_id, manifest.version);

    let part = reqwest::blocking::multipart::Part::bytes(canonical)
        .file_name(format!("{}.manifest.json", manifest.dataset_id))
        .mime_str("application/json")
        .map_err(|e| e.to_string())?;
    let form = reqwest::blocking::multipart::Form::new()
        .part("file", part)
        .text("shard_id", shard.clone())
        .text("record_id", record_id.clone());

    let mut req = client()?
        .post(format!("{server}/ingest/files"))
        .multipart(form);
    if let Some(key) = a.opt("api-key") {
        req = req.header("x-api-key", key);
    }
    let resp = req.send().map_err(|e| format!("POST /ingest/files: {e}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("node returned {status}: {body}"));
    }
    println!(
        "committed dataset '{}' v{} to {server}",
        manifest.dataset_id, manifest.version
    );
    println!("  shard:         {shard}");
    println!("  record_id:     {record_id}");
    println!("  manifest_root: {}", manifest.manifest_root);
    println!("  node response: {body}");
    Ok(true)
}

/// `olympus fetch --hash <content_hash> --server <url>`
pub fn fetch(a: &Args) -> Result<bool, String> {
    let server = base_url(a)?;
    let hash = a.req("hash")?;
    let resp = client()?
        .get(format!("{server}/ingest/records/hash/{hash}/verify"))
        .send()
        .map_err(|e| format!("GET proof: {e}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("node returned {status}: {body}"));
    }
    if let Some(out) = a.opt("out") {
        std::fs::write(out, &body).map_err(|e| format!("writing {out}: {e}"))?;
        eprintln!("ledger proof for {hash} -> {out}");
    } else {
        println!("{body}");
    }
    Ok(true)
}
