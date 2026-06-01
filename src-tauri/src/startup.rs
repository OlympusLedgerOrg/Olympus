//! Startup-time ZK-artifact resolution and ceremony-manifest verification.
//!
//! Extracted from `main.rs`: resolving where the circuit artifacts live,
//! detecting un-built placeholder stubs, and verifying each circuit's signed
//! ceremony manifest (audit CEREMONY_INTEGRITY.md #3/#4). Pure functions with
//! no Tauri managed state, so the placeholder/manifest logic is unit-testable.

use tauri::Manager;

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
pub(crate) fn resolve_proofs_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    let candidates: Vec<std::path::PathBuf> = std::iter::empty()
        .chain(std::env::var_os("OLYMPUS_PROOFS_DIR").map(std::path::PathBuf::from))
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
pub(crate) fn detect_placeholder_artifacts(proofs_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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

/// One result from the ceremony-manifest startup pass (audit
/// CEREMONY_INTEGRITY.md #3). Either the embedded manifest verified
/// against `trusted_issuers` and matched the on-disk `.ark.zkey`, or it
/// failed for a specific reason that's surfaced to the operator.
pub(crate) struct ManifestCheck {
    pub(crate) circuit: &'static str,
    pub(crate) result: Result<String, String>, // Ok(coordinator_id_for_logging) | Err(reason)
}

/// Audit CEREMONY_INTEGRITY.md #3 + #4: verify each circuit's embedded
/// ceremony manifest. For each circuit:
///   - skip if the embedded manifest is still a placeholder (fresh
///     checkout pre-setup; the placeholder gate above already handles
///     this case);
///   - parse, recompute the contribution chain, verify the coordinator
///     BJJ-EdDSA signature against `trusted_issuers`;
///   - re-read the `.ark.zkey` from `proofs_dir` and assert
///     `blake3(file_bytes)` matches the manifest.
pub(crate) fn verify_ceremony_manifests(
    proofs_dir: &std::path::Path,
    trusted_issuers: &[crate::api::trusted_issuers::TrustedIssuer],
) -> Vec<ManifestCheck> {
    use crate::zk::manifest::{ArtifactKind, CeremonyManifest};
    use crate::zk::verify as zk_verify;

    let circuits: &[(&'static str, &'static str)] = &[
        ("document_existence", zk_verify::EXISTENCE_MANIFEST_JSON),
        ("non_existence", zk_verify::NON_EXISTENCE_MANIFEST_JSON),
        ("redaction_validity", zk_verify::REDACTION_MANIFEST_JSON),
        (
            "unified_canonicalization_inclusion_root_sign",
            zk_verify::UNIFIED_MANIFEST_JSON,
        ),
        #[cfg(feature = "quorum-circuit")]
        (
            "federation_quorum",
            zk_verify::FEDERATION_QUORUM_MANIFEST_JSON,
        ),
    ];

    let mut out = Vec::with_capacity(circuits.len());
    for (circuit, manifest_json) in circuits {
        if CeremonyManifest::is_placeholder(manifest_json) {
            out.push(ManifestCheck {
                circuit,
                result: Err("manifest is still a placeholder (run setup_circuits.sh)".into()),
            });
            continue;
        }
        let result = (|| -> Result<String, String> {
            let manifest =
                CeremonyManifest::parse(manifest_json).map_err(|e| format!("parse: {e}"))?;
            manifest
                .require_circuit(circuit)
                .map_err(|e| format!("circuit binding: {e}"))?;
            let issuer = manifest
                .verify_coordinator_signature(trusted_issuers)
                .map_err(|e| format!("coordinator sig: {e}"))?;
            // Re-hash the on-disk .ark.zkey to confirm runtime + manifest agree.
            let ark_path = proofs_dir.join(format!("{circuit}.ark.zkey"));
            let bytes = std::fs::read(&ark_path)
                .map_err(|e| format!("reading {}: {e}", ark_path.display()))?;
            manifest
                .check_artifact(ArtifactKind::ArkZkey, &bytes)
                .map_err(|e| format!("ark_zkey blake3: {e}"))?;
            Ok(issuer.x_dec.clone())
        })();
        out.push(ManifestCheck { circuit, result });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detect_placeholder_artifacts_flags_only_stubs() {
        let base = std::env::temp_dir().join(format!(
            "oly_startup_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(base.join("verification_keys")).unwrap();

        // A placeholder .wasm stub (PLACEHOLDER magic) for one circuit …
        let stub = base.join("document_existence.wasm");
        std::fs::File::create(&stub)
            .unwrap()
            .write_all(b"PLACEHOLDER\n")
            .unwrap();
        // … and a placeholder vkey JSON ({"placeholder…).
        let vkey_stub = base
            .join("verification_keys")
            .join("document_existence_vkey.json");
        std::fs::File::create(&vkey_stub)
            .unwrap()
            .write_all(b"{\"placeholder\":true}")
            .unwrap();
        // A real (non-placeholder) artifact for another circuit must NOT flag.
        let real = base.join("non_existence.r1cs");
        std::fs::File::create(&real)
            .unwrap()
            .write_all(b"\0asm real circuit bytes")
            .unwrap();

        let offenders = detect_placeholder_artifacts(&base);
        assert!(offenders.contains(&stub), "placeholder .wasm must be flagged");
        assert!(
            offenders.contains(&vkey_stub),
            "placeholder vkey JSON must be flagged"
        );
        assert!(
            !offenders.contains(&real),
            "a real artifact must not be flagged"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
