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
/// 4. `proofs/keys` relative to the current working directory — resolves to
///    `<repo>/proofs/keys` when cwd is the repo root, but `cargo tauri dev`
///    actually launches the binary with cwd = `src-tauri/` (so it resolves to
///    `src-tauri/proofs/keys`), which is why candidate 5 points at
///    `<repo>/proofs/keys` in debug builds.
/// 5. **debug builds only** — `proofs/keys` relative to `CARGO_MANIFEST_DIR`'s
///    parent (i.e. `<repo>/proofs/keys`). `cargo tauri dev` launches the binary
///    with cwd = `src-tauri/`, so candidate 4 resolves to `src-tauri/proofs/keys`
///    and misses the real artifacts; this lets a checkout that has run
///    `setup_circuits.sh` resolve with no `OLYMPUS_PROOFS_DIR`. Gated to
///    `debug_assertions` so release / `cargo tauri build` binaries keep
///    candidates 1–4 exactly and never embed a build-machine path.
///
/// A candidate is accepted only if its `verification_keys/` subdirectory exists;
/// otherwise it's a misconfigured shell with no real artifacts. Returns `None`
/// if no candidate qualifies — `/zk/*` routes then 503 with a clear message
/// pointing at `OLYMPUS_PROOFS_DIR`.
pub(crate) fn resolve_proofs_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    // Candidate 5 (see doc comment): dev-only fallback derived from the
    // compile-time `src-tauri/` manifest dir so `cargo tauri dev` finds
    // artifacts without `OLYMPUS_PROOFS_DIR`. Compiled out of release builds.
    #[cfg(debug_assertions)]
    let dev_manifest_fallback: Option<std::path::PathBuf> =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|d| d.join("proofs").join("keys"));
    #[cfg(not(debug_assertions))]
    let dev_manifest_fallback: Option<std::path::PathBuf> = None;

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
        .chain(dev_manifest_fallback)
        .collect();

    first_populated_proofs_dir(candidates)
}

/// Pick the first candidate that looks like a populated artifacts directory —
/// i.e. its `verification_keys/` subdirectory exists. Split out from
/// [`resolve_proofs_dir`] so the selection rule is unit-testable without a
/// `tauri::AppHandle`.
fn first_populated_proofs_dir(
    candidates: impl IntoIterator<Item = std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
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
pub(crate) fn detect_placeholder_artifacts(
    proofs_dir: &std::path::Path,
) -> Vec<std::path::PathBuf> {
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
///
/// Red-team A-2 / A-3 / A-4: defences against accepting a self-attesting
/// or single-contributor ceremony manifest at runtime. These do NOT fix
/// the underlying single-contributor reality of the v0.9 committed
/// manifests (that needs a real multi-contributor Phase 2 ceremony,
/// tracked separately), but they prevent the runtime from blindly
/// trusting one going forward.
///
/// In **production** mode (`OLYMPUS_ENV=production`), any of these fires
/// as a hard failure (returned as `Err(...)` in the per-circuit
/// `ManifestCheck` so the caller increments `real_failures` and exits
/// 2). In **dev** mode, each fires as a `tracing::warn!` and the check
/// continues — so dev workflows that use the single-contributor
/// `setup_circuits.sh` path don't break.
const MIN_PROD_CONTRIBUTORS: usize = 3;

fn apply_extra_prod_gates(
    circuit: &str,
    manifest: &crate::zk::manifest::CeremonyManifest,
    is_prod: bool,
    bootstrap_pubkey: Option<&crate::zk::witness::baby_jubjub::BabyJubJubPubKey>,
) -> Result<(), String> {
    let mut hard_reasons: Vec<String> = Vec::new();

    // A-3 pre-flight (CodeRabbit follow-up): in production, A-3 is a
    // *hard* gate. The function below only fires the A-3 check inside
    // `if let Some(boot) = bootstrap_pubkey`, which means a prod caller
    // that simply omits the bootstrap key would silently skip the
    // self-attestation check. Refuse production startup when the key
    // is missing rather than letting that downgrade happen.
    if is_prod && bootstrap_pubkey.is_none() {
        hard_reasons.push(
            "runtime bootstrap BJJ pubkey is unavailable; audit A-3 self-attestation \
             check cannot be enforced — production builds require a bootstrap key so \
             coordinator-pubkey == bootstrap-pubkey can be detected"
                .to_owned(),
        );
    }

    // A-2: refuse single-contributor manifests in prod.
    if manifest.contributions.len() < MIN_PROD_CONTRIBUTORS {
        let msg = format!(
            "manifest has only {} contributor(s); audit A-2 requires >= {} for production \
             (single-contributor manifests are dev-only — run `phase2_ceremony.sh` with multiple parties)",
            manifest.contributions.len(),
            MIN_PROD_CONTRIBUTORS
        );
        if is_prod {
            hard_reasons.push(msg);
        } else {
            tracing::warn!(
                "ceremony-integrity: {} {} (dev mode — allowed, but production builds will refuse)",
                circuit,
                msg
            );
        }
    }

    // A-3: refuse manifests whose coordinator pubkey equals the runtime
    // bootstrap pubkey (self-attestation). Compares as decimal Fr
    // strings — the same shape the manifest itself stores.
    //
    // Fail-closed: enforcing A-3 REQUIRES a bootstrap pubkey to compare
    // against, so a missing one in production is itself a hard failure rather
    // than a silent skip of the gate. (The sole production caller in main.rs
    // always supplies it; this keeps the gate robust if a future caller
    // doesn't.)
    match bootstrap_pubkey {
        Some(boot) => {
            use ark_ff::{BigInteger, PrimeField};
            let boot_x =
                num_bigint::BigUint::from_bytes_be(&boot.x.into_bigint().to_bytes_be()).to_string();
            let boot_y =
                num_bigint::BigUint::from_bytes_be(&boot.y.into_bigint().to_bytes_be()).to_string();
            if manifest.coordinator.bjj_pubkey.x == boot_x
                && manifest.coordinator.bjj_pubkey.y == boot_y
            {
                let msg = "manifest coordinator pubkey == runtime bootstrap pubkey \
                    (audit A-3: trust circularity — the same key that ran the ceremony \
                    signs the attestation that itself ran it correctly; an independent \
                    offline/HSM-held coordinator key should be configured via \
                    OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON for production)"
                    .to_owned();
                if is_prod {
                    hard_reasons.push(msg);
                } else {
                    tracing::warn!(
                        "ceremony-integrity: {} {} (dev mode — allowed)",
                        circuit,
                        msg
                    );
                }
            }
        }
        None => {
            let msg = "no bootstrap pubkey available to enforce the audit A-3 \
                self-attestation gate — cannot confirm the ceremony coordinator is \
                independent of the runtime bootstrap key"
                .to_owned();
            if is_prod {
                hard_reasons.push(msg);
            } else {
                tracing::warn!(
                    "ceremony-integrity: {} {} (dev mode — allowed)",
                    circuit,
                    msg
                );
            }
        }
    }

    // A-4: refuse manifests whose ceremony_id is the dev-marker.
    if manifest.ceremony_id.starts_with("olympus-dev-") {
        let msg = format!(
            "manifest ceremony_id={:?} is dev-marker prefix `olympus-dev-` \
             (audit A-4: dev-mode setup_circuits.sh artifacts are not production-safe)",
            manifest.ceremony_id
        );
        if is_prod {
            hard_reasons.push(msg);
        } else {
            tracing::warn!(
                "ceremony-integrity: {} {} (dev mode — allowed)",
                circuit,
                msg
            );
        }
    }

    if hard_reasons.is_empty() {
        Ok(())
    } else {
        Err(hard_reasons.join("; "))
    }
}

pub(crate) fn verify_ceremony_manifests(
    proofs_dir: &std::path::Path,
    trusted_issuers: &[crate::api::trusted_issuers::TrustedIssuer],
    is_prod: bool,
    bootstrap_pubkey: Option<&crate::zk::witness::baby_jubjub::BabyJubJubPubKey>,
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
            // Red-team A-2/A-3/A-4: extra production-only gates before the
            // existing coordinator-sig + ark-zkey-blake3 checks. Dev mode
            // tracing::warn!s inside and returns Ok.
            apply_extra_prod_gates(circuit, &manifest, is_prod, bootstrap_pubkey)
                .map_err(|e| format!("prod-mode policy: {e}"))?;
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
        assert!(
            offenders.contains(&stub),
            "placeholder .wasm must be flagged"
        );
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

    #[test]
    fn first_populated_proofs_dir_selects_first_with_verification_keys() {
        let base = std::env::temp_dir().join(format!(
            "oly_resolve_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let missing = base.join("missing").join("keys");
        let populated = base.join("real").join("keys");
        std::fs::create_dir_all(populated.join("verification_keys")).unwrap();

        // Happy path: candidate 1 has no `verification_keys/`, so the populated
        // candidate 2 is chosen — exercises both the order and the subdir gate.
        let got = first_populated_proofs_dir([missing.clone(), populated.clone()]);
        assert_eq!(got.as_deref(), Some(populated.as_path()));

        // Error path: no candidate has a `verification_keys/` subdir → None.
        let none = first_populated_proofs_dir([missing.clone(), base.join("nope")]);
        assert_eq!(none, None);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Build a minimal `CeremonyManifest` for the apply_extra_prod_gates
    /// unit tests. The coordinator-sig + artifact-blake3 checks live in
    /// different code paths and are exercised by `manifest::tests`; here
    /// we only care about the new A-2/A-3/A-4 gates, so the manifest's
    /// signature and artifact hashes don't need to be valid.
    fn skeleton_manifest(
        ceremony_id: &str,
        n_contributions: usize,
        coord_pubkey: crate::zk::manifest::BjjPubkeyJson,
    ) -> crate::zk::manifest::CeremonyManifest {
        use crate::zk::manifest::{
            ArtifactMap, ArtifactRef, BjjSignatureJson, CeremonyManifest, Contribution,
            CoordinatorRef, PtauRef,
        };
        let zero_blake3 = "0".repeat(64);
        let zero_blake2b = "0".repeat(128);
        let dummy_artifact = ArtifactRef {
            name: "x".into(),
            size: 0,
            blake3: zero_blake3.clone(),
        };
        let contributions = (0..n_contributions)
            .map(|i| Contribution {
                index: i as u32,
                contributor_id: format!("c{i}"),
                contribution_hash: zero_blake3.clone(),
                running_chain_hash: zero_blake3.clone(),
                timestamp_unix: 0,
                bjj_pubkey: coord_pubkey.clone(),
            })
            .collect();
        CeremonyManifest {
            version: 1,
            ceremony_id: ceremony_id.into(),
            circuit: "document_existence".into(),
            created_unix: 0,
            ptau: PtauRef {
                file: "p.ptau".into(),
                power: 20,
                blake2b: zero_blake2b,
            },
            artifacts: ArtifactMap {
                vkey: dummy_artifact.clone(),
                ark_zkey: dummy_artifact.clone(),
                r1cs: dummy_artifact.clone(),
                wasm: dummy_artifact,
            },
            contributions,
            coordinator: CoordinatorRef {
                id: "coord".into(),
                bjj_pubkey: coord_pubkey,
                signature: BjjSignatureJson {
                    r8x: "0".into(),
                    r8y: "0".into(),
                    s: "0".into(),
                },
            },
        }
    }

    fn nonzero_pubkey() -> crate::zk::witness::baby_jubjub::BabyJubJubPubKey {
        // Any deterministic non-identity pubkey works.
        crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&[7u8; 32]).expect("pubkey")
    }

    /// A second distinct deterministic pubkey, used as the bootstrap
    /// key in tests that want A-3 (self-attestation) NOT to fire so the
    /// gate under test isolates A-2 / A-4 cleanly.
    fn second_nonzero_pubkey() -> crate::zk::witness::baby_jubjub::BabyJubJubPubKey {
        crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&[11u8; 32])
            .expect("pubkey")
    }

    fn pubkey_json_of(
        pk: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
    ) -> crate::zk::manifest::BjjPubkeyJson {
        use ark_ff::{BigInteger, PrimeField};
        let fr_dec = |f: &ark_bn254::Fr| {
            num_bigint::BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
        };
        crate::zk::manifest::BjjPubkeyJson {
            x: fr_dec(&pk.x),
            y: fr_dec(&pk.y),
        }
    }

    #[test]
    fn extra_prod_gates_dev_allows_single_contributor() {
        // Red-team A-2: in dev mode, single-contributor is allowed
        // (with a warning). Production refuses (separate test).
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", 1, pubkey_json_of(&pk));
        apply_extra_prod_gates("document_existence", &m, false, None)
            .expect("dev mode must allow single-contributor");
    }

    #[test]
    fn extra_prod_gates_prod_refuses_single_contributor() {
        // Red-team A-2: prod refuses < MIN_PROD_CONTRIBUTORS.
        // Pass a distinct bootstrap key so A-3's mandatory-key gate
        // (CodeRabbit follow-up) doesn't fire and the assertion below
        // isolates the A-2 gate cleanly.
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", 1, pubkey_json_of(&manifest_pk));
        let err = apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk))
            .expect_err("prod mode must refuse single-contributor");
        assert!(err.contains("A-2"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_prod_accepts_three_contributors() {
        // Boundary: exactly MIN_PROD_CONTRIBUTORS contributors clears A-2.
        // Pass a distinct bootstrap pubkey so A-3's mandatory-key gate
        // (CodeRabbit follow-up) and the self-attestation check both
        // clear — the boundary we want to exercise is A-2 only.
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let m = skeleton_manifest(
            "real-ceremony",
            MIN_PROD_CONTRIBUTORS,
            pubkey_json_of(&manifest_pk),
        );
        apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk))
            .expect("3+ contributors clears A-2");
    }

    #[test]
    fn extra_prod_gates_prod_refuses_self_attesting_coordinator() {
        // Red-team A-3: coordinator pubkey equals bootstrap pubkey.
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", MIN_PROD_CONTRIBUTORS, pubkey_json_of(&pk));
        let err = apply_extra_prod_gates("document_existence", &m, true, Some(&pk))
            .expect_err("self-attesting coordinator must reject in prod");
        assert!(err.contains("A-3"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_prod_accepts_distinct_coordinator() {
        let manifest_pk = nonzero_pubkey();
        let bootstrap_pk =
            crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&[11u8; 32])
                .expect("pubkey");
        let m = skeleton_manifest(
            "real-ceremony",
            MIN_PROD_CONTRIBUTORS,
            pubkey_json_of(&manifest_pk),
        );
        apply_extra_prod_gates("document_existence", &m, true, Some(&bootstrap_pk))
            .expect("distinct coordinator clears A-3");
    }

    #[test]
    fn extra_prod_gates_prod_requires_bootstrap_pubkey_for_a3() {
        // Fail-closed (review follow-up): prod must NOT silently skip A-3 when
        // no bootstrap pubkey is available to compare the coordinator against.
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", MIN_PROD_CONTRIBUTORS, pubkey_json_of(&pk));
        let err = apply_extra_prod_gates("document_existence", &m, true, None)
            .expect_err("prod must refuse when the bootstrap pubkey is absent");
        assert!(err.contains("A-3"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_dev_allows_missing_bootstrap_pubkey() {
        // Dev mode keeps working without a bootstrap pubkey (warn + continue).
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", MIN_PROD_CONTRIBUTORS, pubkey_json_of(&pk));
        apply_extra_prod_gates("document_existence", &m, false, None)
            .expect("dev mode must allow a missing bootstrap pubkey");
    }

    #[test]
    fn extra_prod_gates_prod_refuses_dev_ceremony_id() {
        // Red-team A-4: ceremony_id starts with "olympus-dev-".
        // Distinct bootstrap key isolates A-4 from the new A-3
        // mandatory-key gate.
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let m = skeleton_manifest(
            "olympus-dev-1748000000",
            MIN_PROD_CONTRIBUTORS,
            pubkey_json_of(&manifest_pk),
        );
        let err = apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk))
            .expect_err("dev-prefix ceremony_id must reject in prod");
        assert!(err.contains("A-4"), "error must cite finding: {err}");
    }
}
