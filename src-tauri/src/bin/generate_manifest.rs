//! Generate a signed ceremony manifest for one ZK circuit.
//!
//! Run after `setup_circuits.sh` (or `phase2_ceremony.sh`) has produced
//! the `.r1cs`, `.wasm`, `.ark.zkey`, and `_vkey.json` for a circuit.
//! This binary computes blake3 over each artifact, builds a
//! contribution chain, signs the final running-chain-hash with the
//! contributor's BabyJubJub authority key, and writes a `manifest.json`.
//!
//! Companion to `proofs/CEREMONY_INTEGRITY.md`.
//!
//! Usage:
//!   generate_manifest \
//!     --circuit <name> \
//!     --keys-dir <path/to/proofs/keys> \
//!     --build-dir <path/to/proofs/build> \
//!     --ceremony-id <id> \
//!     --contributor-id <name> \
//!     --out <path/to/manifest.json>
//!
//! Required environment (one of):
//!   OLYMPUS_CEREMONY_COORDINATOR_KEY (32 bytes hex) — preferred
//!   OLYMPUS_BJJ_AUTHORITY_KEY        (fallback; dev-mode only)
//!
//! Exit codes:
//!   0 success
//!   1 argument / env error
//!   2 read error on an artifact
//!   3 sign / write error

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ark_bn254::Fr;
use ark_ff::PrimeField;

use olympus_tauri_lib::zk::manifest::{
    ArtifactMap, ArtifactRef, BjjPubkeyJson, BjjSignatureJson, CeremonyManifest, Contribution,
    CoordinatorRef, PtauRef,
};
use olympus_tauri_lib::zk::witness::baby_jubjub::{sign as bjj_sign, BabyJubJubPubKey};

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            eprintln!(
                "usage: generate_manifest --circuit <name> --keys-dir <path> \
                 --build-dir <path> --ceremony-id <id> --contributor-id <name> \
                 --out <path>"
            );
            return ExitCode::from(1);
        }
    };

    let priv_key = match resolve_signing_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let manifest = match build_manifest(&args, &priv_key) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // CEREMONY_INTEGRITY.md: manifest.json is JCS/RFC 8785 canonical so any
    // future tool that hashes the file bytes (distribution-time, mirroring,
    // external audit) gets a reproducible digest. `to_string_pretty` would
    // emit non-canonical whitespace + (potentially) non-canonical key order.
    let json_bytes = match serde_json::to_vec(&manifest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: serializing manifest JSON: {e}");
            return ExitCode::from(3);
        }
    };
    let canonical = match olympus_crypto::canonical::canonicalize_bytes(&json_bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: canonicalizing manifest JSON: {e}");
            return ExitCode::from(3);
        }
    };

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("error: creating {}: {e}", parent.display());
                return ExitCode::from(3);
            }
        }
    }
    if let Err(e) = fs::write(&args.out, &canonical) {
        eprintln!("error: writing {}: {e}", args.out.display());
        return ExitCode::from(3);
    }

    println!(
        "Wrote manifest: circuit={} contributor={} out={}",
        args.circuit,
        args.contributor_id,
        args.out.display()
    );
    ExitCode::from(0)
}

// ── CLI parsing ───────────────────────────────────────────────────────────

struct Args {
    circuit: String,
    keys_dir: PathBuf,
    build_dir: PathBuf,
    ceremony_id: String,
    contributor_id: String,
    out: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut circuit = None;
    let mut keys_dir = None;
    let mut build_dir = None;
    let mut ceremony_id = None;
    let mut contributor_id = None;
    let mut out = None;

    let mut i = 0;
    while i < raw.len() {
        let val = raw
            .get(i + 1)
            .cloned()
            .ok_or_else(|| format!("flag {} expects a value", raw[i]))?;
        match raw[i].as_str() {
            "--circuit" => circuit = Some(val),
            "--keys-dir" => keys_dir = Some(PathBuf::from(val)),
            "--build-dir" => build_dir = Some(PathBuf::from(val)),
            "--ceremony-id" => ceremony_id = Some(val),
            "--contributor-id" => contributor_id = Some(val),
            "--out" => out = Some(PathBuf::from(val)),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 2;
    }

    Ok(Args {
        circuit: circuit.ok_or("--circuit required")?,
        keys_dir: keys_dir.ok_or("--keys-dir required")?,
        build_dir: build_dir.ok_or("--build-dir required")?,
        ceremony_id: ceremony_id.ok_or("--ceremony-id required")?,
        contributor_id: contributor_id.ok_or("--contributor-id required")?,
        out: out.ok_or("--out required")?,
    })
}

fn resolve_signing_key() -> Result<[u8; 32], String> {
    let raw = std::env::var("OLYMPUS_CEREMONY_COORDINATOR_KEY")
        .or_else(|_| std::env::var("OLYMPUS_BJJ_AUTHORITY_KEY"))
        .map_err(|_| {
            "OLYMPUS_CEREMONY_COORDINATOR_KEY (or OLYMPUS_BJJ_AUTHORITY_KEY) must be set".to_owned()
        })?;
    let trimmed = raw.trim();
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| format!("signing key must be 64 hex chars: {e}"))?;
    Ok(out)
}

// ── Manifest assembly ─────────────────────────────────────────────────────

fn build_manifest(args: &Args, priv_key: &[u8; 32]) -> Result<CeremonyManifest, String> {
    let circuit = args.circuit.as_str();

    let vkey_path = args
        .keys_dir
        .join("verification_keys")
        .join(format!("{circuit}_vkey.json"));
    let ark_zkey_path = args.keys_dir.join(format!("{circuit}.ark.zkey"));
    let r1cs_path = args.build_dir.join(format!("{circuit}.r1cs"));
    let wasm_path = args
        .build_dir
        .join(format!("{circuit}_js"))
        .join(format!("{circuit}.wasm"));

    // Read each artifact. The vkey is a TEXT file (JSON) — strip CR
    // bytes so the blake3 we record is platform-stable. git stores text
    // with LF and Windows checkouts convert back to CRLF, which would
    // otherwise produce different digests on Windows vs Linux CI.
    // The .ark.zkey / .r1cs / .wasm are binary and git stores them
    // verbatim (no conversion) — no normalization needed.
    let vkey_bytes = normalize_text(&read_artifact(&vkey_path, "vkey")?);
    let ark_zkey_bytes = read_artifact(&ark_zkey_path, "ark_zkey")?;
    let r1cs_bytes = read_artifact(&r1cs_path, "r1cs")?;
    let wasm_bytes = read_artifact(&wasm_path, "wasm")?;

    let ptau = detect_ptau(&args.keys_dir)?;

    let pubkey =
        BabyJubJubPubKey::from_private(priv_key).map_err(|e| format!("BJJ pubkey derive: {e}"))?;
    let pubkey_json = BjjPubkeyJson {
        x: fr_to_decimal(&pubkey.x),
        y: fr_to_decimal(&pubkey.y),
    };

    // Use blake3(ark_zkey) as the contribution-identity proxy. For the
    // single-contributor dev path this binds the manifest to the
    // exact proving key the runtime will load; a multi-contributor
    // phase2_ceremony.sh path would append one Contribution per
    // intermediate `.zkey` and chain them.
    let contribution_hash = blake3::hash(&ark_zkey_bytes).to_hex().to_string();

    // Recompute running_chain_hash via the same recipe as
    // CeremonyManifest::verify_contribution_chain.
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:CEREMONY:CHAIN:V1");
    h.update(&[0u8; 32]);
    h.update(blake3::hash(&ark_zkey_bytes).as_bytes());
    let chain: [u8; 32] = *h.finalize().as_bytes();
    let chain_hex = hex::encode(chain);

    let msg = Fr::from_le_bytes_mod_order(&chain);
    let sig = bjj_sign(priv_key, msg).map_err(|e| format!("BJJ sign: {e}"))?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();

    Ok(CeremonyManifest {
        version: 1,
        ceremony_id: args.ceremony_id.clone(),
        circuit: circuit.to_owned(),
        created_unix: now_unix,
        ptau,
        artifacts: ArtifactMap {
            vkey: artifact_ref(&vkey_path, &vkey_bytes),
            ark_zkey: artifact_ref(&ark_zkey_path, &ark_zkey_bytes),
            r1cs: artifact_ref(&r1cs_path, &r1cs_bytes),
            wasm: artifact_ref(&wasm_path, &wasm_bytes),
        },
        contributions: vec![Contribution {
            index: 0,
            contributor_id: args.contributor_id.clone(),
            contribution_hash,
            running_chain_hash: chain_hex,
            timestamp_unix: now_unix,
            bjj_pubkey: pubkey_json.clone(),
        }],
        coordinator: CoordinatorRef {
            id: args.contributor_id.clone(),
            bjj_pubkey: pubkey_json,
            signature: BjjSignatureJson {
                r8x: fr_to_decimal(&sig.r8x),
                r8y: fr_to_decimal(&sig.r8y),
                s: fr_to_decimal(&sig.s),
            },
        },
    })
}

fn read_artifact(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let mut f =
        fs::File::open(path).map_err(|e| format!("opening {label} at {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| format!("reading {label}: {e}"))?;
    Ok(buf)
}

fn artifact_ref(path: &Path, bytes: &[u8]) -> ArtifactRef {
    ArtifactRef {
        name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned(),
        size: bytes.len() as u64,
        blake3: blake3::hash(bytes).to_hex().to_string(),
    }
}

/// Strip `\r` bytes so blake3 of a text file matches across platforms.
/// git stores text with LF; Windows checkouts convert to CRLF on the
/// working tree. Without this, the manifest blake3 computed on Windows
/// would differ from CI's Linux checkout for the same logical content.
/// Stripping `\r` is equivalent to converting `\r\n` -> `\n` because
/// JSON cannot contain a bare `\r` in any other context.
fn normalize_text(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().filter(|&b| b != b'\r').collect()
}

/// Detect the PTAU file in `keys_dir` and record its name, power, and
/// BLAKE2b-512 digest (audit F-3). The digest is computed over the actual
/// on-disk Phase-1 file so an external auditor can confirm — from the
/// manifest alone — which Powers-of-Tau transcript the ceremony consumed,
/// and cross-check it against the published Hermez announcement. (The
/// download-time pin in `setup_circuits.sh` is the trust anchor that the
/// file is the legitimate Hermez ptau; this field records what was used so
/// the manifest is self-describing.) The file is streamed, not buffered —
/// power-20 ptau is ~1.2 GB.
fn detect_ptau(keys_dir: &Path) -> Result<PtauRef, String> {
    let entries =
        fs::read_dir(keys_dir).map_err(|e| format!("reading {}: {e}", keys_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".ptau") {
            continue;
        }
        // power is the suffix before .ptau (e.g. `_final_20.ptau` -> 20).
        let power = name
            .rsplit('_')
            .find_map(|s| s.trim_end_matches(".ptau").parse::<u32>().ok())
            .unwrap_or(0);
        let blake2b =
            blake2b512_file(&path).map_err(|e| format!("hashing PTAU {}: {e}", path.display()))?;
        return Ok(PtauRef {
            file: name.to_owned(),
            power,
            blake2b,
        });
    }
    Err(format!(
        "no PTAU file (.ptau) found under {}; ceremony cannot proceed without Phase 1",
        keys_dir.display()
    ))
}

/// Stream a file through BLAKE2b-512 and return the lowercase hex digest.
/// Matches `b2sum` output, which is what the Hermez ceremony publishes and
/// what `setup_circuits.sh`'s `PTAU_CHECKSUMS` table pins.
fn blake2b512_file(path: &Path) -> Result<String, String> {
    use blake2::{Blake2b512, Digest};
    let mut f = fs::File::open(path).map_err(|e| format!("opening: {e}"))?;
    let mut hasher = Blake2b512::new();
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB chunks
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("reading: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

use olympus_tauri_lib::zk::proof::fr_to_decimal;
