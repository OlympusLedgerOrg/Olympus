// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Verify the internally signed structure and artifact hashes of one ceremony bundle.
//!
//! Coordinator identity is intentionally not established here; production startup
//! checks the signature against the operator's trusted-issuer configuration.

use std::path::{Path, PathBuf};

use olympus_tauri_lib::zk::manifest::{
    parse_trusted_contributors_json, ArtifactKind, CeremonyManifest, TRUSTED_CONTRIBUTORS_ENV,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("ceremony bundle verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut circuit = None;
    let mut keys_dir = None;
    let mut minimum_authenticated_contributors = 0usize;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--circuit" => circuit = Some(value),
            "--keys-dir" => keys_dir = Some(PathBuf::from(value)),
            "--minimum-authenticated-contributors" => {
                minimum_authenticated_contributors = value.parse().map_err(|_| {
                    "--minimum-authenticated-contributors must be a non-negative integer".to_owned()
                })?;
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }

    let circuit = circuit.ok_or("--circuit is required")?;
    let keys_dir = keys_dir.ok_or("--keys-dir is required")?;
    verify_bundle(&circuit, &keys_dir, minimum_authenticated_contributors)?;
    println!("verified ceremony structure and artifact hashes for {circuit}");
    Ok(())
}

fn verify_bundle(
    circuit: &str,
    keys_dir: &Path,
    minimum_authenticated_contributors: usize,
) -> Result<(), String> {
    let manifest_path = keys_dir
        .join("manifests")
        .join(format!("{circuit}_manifest.json"));
    let manifest_json = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("reading {}: {error}", manifest_path.display()))?;
    let manifest = CeremonyManifest::parse(&manifest_json).map_err(|error| error.to_string())?;
    manifest
        .require_circuit(circuit)
        .map_err(|error| error.to_string())?;

    // Recomputes every contribution link, validates all canonical fields, and
    // proves the signature matches the manifest's declared coordinator key.
    // Whether that key is trusted remains an independent deployment policy.
    manifest
        .verify_signature_against_declared_coordinator()
        .map_err(|error| error.to_string())?;

    if minimum_authenticated_contributors > 0 {
        let policy_json = std::env::var(TRUSTED_CONTRIBUTORS_ENV).map_err(|_| {
            format!(
                "{TRUSTED_CONTRIBUTORS_ENV} is required when enforcing an authenticated contributor threshold"
            )
        })?;
        let trusted =
            parse_trusted_contributors_json(&policy_json).map_err(|error| error.to_string())?;
        manifest
            .verify_authenticated_contributors(&trusted, minimum_authenticated_contributors)
            .map_err(|error| error.to_string())?;
    }

    let artifacts = [
        (
            ArtifactKind::Vkey,
            keys_dir
                .join("verification_keys")
                .join(format!("{circuit}_vkey.json")),
            manifest.artifacts.vkey.size,
        ),
        (
            ArtifactKind::ArkZkey,
            keys_dir.join(format!("{circuit}.ark.zkey")),
            manifest.artifacts.ark_zkey.size,
        ),
        (
            ArtifactKind::R1cs,
            keys_dir.join(format!("{circuit}.r1cs")),
            manifest.artifacts.r1cs.size,
        ),
        (
            ArtifactKind::Wasm,
            keys_dir.join(format!("{circuit}.wasm")),
            manifest.artifacts.wasm.size,
        ),
    ];

    for (kind, path, expected_size) in artifacts {
        let raw_bytes =
            std::fs::read(&path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        let normalized_vkey = if matches!(kind, ArtifactKind::Vkey) {
            Some(normalize_text(&raw_bytes))
        } else {
            None
        };
        let bytes = normalized_vkey.as_deref().unwrap_or(&raw_bytes);
        if bytes.len() as u64 != expected_size {
            return Err(format!(
                "{} size mismatch: manifest says {expected_size}, file has {}",
                path.display(),
                bytes.len()
            ));
        }
        manifest
            .check_artifact(kind, bytes)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Match generate_manifest/build.rs: JSON verification keys are logical text,
/// so their manifest size/hash is computed after CRLF-to-LF normalization.
fn normalize_text(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|&byte| byte != b'\r')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::normalize_text;

    #[test]
    fn vkey_crlf_normalization_matches_lf_checkout() {
        assert_eq!(
            normalize_text(b"{\r\n  \"key\": 1\r\n}\r\n"),
            b"{\n  \"key\": 1\n}\n"
        );
    }
}
