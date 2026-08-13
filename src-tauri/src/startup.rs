//! Startup-time ZK-artifact resolution, ceremony-manifest verification, and
//! `main()`'s orchestration phases.
//!
//! Extracted from `main.rs`: resolving where the circuit artifacts live,
//! detecting un-built placeholder stubs, and verifying each circuit's signed
//! ceremony manifest (audit CEREMONY_INTEGRITY.md #3/#4) are pure functions
//! with no Tauri managed state, so the placeholder/manifest logic is
//! unit-testable. The named phases further down (panic-hook install,
//! preflight checks, the async server bring-up body, managed-state
//! registration, and the startup-waiter thread) are the bodies that used to
//! live inline in `main()`'s `setup(|app| { ... })` closure — see the
//! "main() orchestration phases" section below.

use tauri::Manager;

use crate::commands::{clear_startup_timeout, publish_startup_error, STARTUP_TIMEOUT_CODE};

const PROD_REQUIRED_SECRETS: &[(&str, &str)] = &[
    (
        "OLYMPUS_ADMIN_KEY",
        "operator secret for admin-gated routes",
    ),
    (
        "OLYMPUS_BJJ_AUTHORITY_KEY",
        "persistent Baby Jubjub authority private key",
    ),
    (
        "OLYMPUS_INGEST_SIGNING_KEY",
        "persistent Ed25519 ingest/redaction bundle signing key",
    ),
    (
        "OLYMPUS_REDACTION_BLIND_SECRET",
        "independent redaction blinding secret",
    ),
];

const PLACEHOLDER_CHECK_VARS: &[&str] = &[
    "DATABASE_URL",
    crate::db::MIGRATION_DATABASE_URL_ENV,
    "PSYCOPG_URL",
    "POSTGRES_PASSWORD",
    "OLYMPUS_SEQUENCER_TOKEN",
];

const DEV_ONLY_FLAGS: &[&str] = &[
    "OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP",
    crate::db::DEV_ALLOW_SINGLE_DATABASE_URL_ENV,
    "OLYMPUS_RETURN_RECOVERY_TOKEN",
];

pub(crate) fn production_runtime_config_errors() -> Vec<String> {
    production_runtime_config_errors_with(|name| std::env::var(name).ok())
}

/// Non-fatal production configuration hazards, logged at startup. Unlike the
/// errors above these do not refuse startup — they surface silent fallbacks an
/// operator would otherwise only discover in per-request logs.
pub(crate) fn production_runtime_config_warnings() -> Vec<String> {
    production_runtime_config_warnings_with(|name| std::env::var(name).ok())
}

fn production_runtime_config_warnings_with<F>(mut get: F) -> Vec<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let is_prod = !matches!(
        get("OLYMPUS_ENV").as_deref().map(str::trim),
        Some(v) if matches_ignore_ascii_case(v, &["development", "dev", "test"])
    );
    if !is_prod {
        return Vec::new();
    }

    let mut warnings = Vec::new();

    // Anchoring signs with OLYMPUS_ANCHOR_SIGN_KEY but silently falls back to
    // OLYMPUS_INGEST_SIGNING_KEY when it is unset (`anchoring/own_checkpoint.rs`,
    // `anchoring/rekor.rs`). A shared signer couples the anchoring identity to
    // the ingest key: rotating one rotates the other, and a compromise of
    // either exposes both roles. Only relevant when an anchoring backend is
    // actually configured.
    let anchoring_configured = [
        "OLYMPUS_ANCHOR_RFC3161_URL",
        "OLYMPUS_ANCHOR_REKOR_URL",
        "OLYMPUS_ANCHOR_OTS_CALENDARS",
    ]
    .iter()
    .any(|name| {
        get(name)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    });
    let anchor_key_set = get("OLYMPUS_ANCHOR_SIGN_KEY")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if anchoring_configured && !anchor_key_set {
        warnings.push(
            "OLYMPUS_ANCHOR_SIGN_KEY is unset while anchoring is configured — anchoring \
             falls back to OLYMPUS_INGEST_SIGNING_KEY, coupling the anchoring identity to \
             the ingest signing key (rotating one rotates both). Set a dedicated \
             OLYMPUS_ANCHOR_SIGN_KEY to decouple them (docs/key-rotation.md)."
                .to_owned(),
        );
    }

    warnings
}

fn production_runtime_config_errors_with<F>(mut get: F) -> Vec<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let is_prod = !matches!(
        get("OLYMPUS_ENV").as_deref().map(str::trim),
        Some(v) if matches_ignore_ascii_case(v, &["development", "dev", "test"])
    );
    if !is_prod {
        return Vec::new();
    }

    let mut errors = Vec::new();
    for (name, purpose) in PROD_REQUIRED_SECRETS {
        match get(name) {
            Some(value) => {
                if let Some(reason) = production_secret_issue(name, &value) {
                    errors.push(format!("{name} {reason} ({purpose})"));
                }
            }
            None => errors.push(format!("{name} is required in production ({purpose})")),
        }
    }

    let database_url = get("DATABASE_URL");
    let migration_database_url = get(crate::db::MIGRATION_DATABASE_URL_ENV);
    let database_url_configured = database_url
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let migration_database_url_configured = migration_database_url
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if database_url_configured && !migration_database_url_configured {
        errors.push(format!(
            "{} is required when DATABASE_URL is set in production",
            crate::db::MIGRATION_DATABASE_URL_ENV
        ));
    }
    if migration_database_url_configured && !database_url_configured {
        errors.push(format!(
            "{} must be unset unless DATABASE_URL is configured in production",
            crate::db::MIGRATION_DATABASE_URL_ENV
        ));
    }
    if database_url_configured && get(crate::db::PGOPTIONS_ENV).is_some() {
        errors.push(format!(
            "{} must be unset when DATABASE_URL is configured in production",
            crate::db::PGOPTIONS_ENV
        ));
    }

    if truthy(get("OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION").as_deref()) {
        errors.push(
            "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION=1 is forbidden in production".to_owned(),
        );
    }
    for name in DEV_ONLY_FLAGS {
        if truthy(get(name).as_deref()) {
            errors.push(format!("{name}=1 is dev-only and forbidden in production"));
        }
    }
    if get("OLYMPUS_DEV_SIGNING_KEY")
        .map(|v| {
            let trimmed = v.trim();
            !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("false") && trimmed != "0"
        })
        .unwrap_or(false)
    {
        errors.push(
            "OLYMPUS_DEV_SIGNING_KEY is dev-only; use OLYMPUS_INGEST_SIGNING_KEY in production"
                .to_owned(),
        );
    }

    for name in PLACEHOLDER_CHECK_VARS {
        if let Some(value) = get(name) {
            if placeholder_like(&value) {
                errors.push(format!("{name} contains placeholder-like secret material"));
            }
        }
    }

    errors
}

fn production_secret_issue(name: &str, value: &str) -> Option<&'static str> {
    let trimmed = value.trim();
    if placeholder_like(trimmed) {
        return Some("is missing or placeholder-like");
    }
    match name {
        "OLYMPUS_BJJ_AUTHORITY_KEY"
        | "OLYMPUS_INGEST_SIGNING_KEY"
        | "OLYMPUS_REDACTION_BLIND_SECRET" => {
            if !is_hex_32(trimmed) {
                Some("must be a 32-byte hex value")
            } else {
                None
            }
        }
        "OLYMPUS_ADMIN_KEY" => {
            if trimmed.len() < 32 {
                Some("must be at least 32 characters")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn placeholder_like(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    let marker_hit = [
        "change_me",
        "changeme",
        "your_",
        "replace_me",
        "placeholder",
        "example",
        "dummy",
        "do_not_use",
        "not_a_secret",
        "local_only",
        "dev-only",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    if marker_hit {
        return true;
    }
    let mut chars = trimmed.chars();
    if let Some(first) = chars.next() {
        if chars.all(|ch| ch == first) {
            return true;
        }
    }
    false
}

fn truthy(value: Option<&str>) -> bool {
    value
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn matches_ignore_ascii_case(value: &str, choices: &[&str]) -> bool {
    choices
        .iter()
        .any(|choice| value.eq_ignore_ascii_case(choice))
}

fn is_hex_32(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

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
            app.path()
                .resolve("", tauri::path::BaseDirectory::Executable)
                .ok()
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
        "unified_canonicalization_inclusion_root_sign",
        "federation_quorum",
    ];
    #[cfg(not(feature = "quorum-circuit"))]
    let circuits: &[&str] = &[
        "document_existence",
        "non_existence",
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
///     BJJ-EdDSA signature against `trusted_issuers` (only entries granting
///     `TrustRole::CeremonyCoordinator` count — ADR-0041 role separation);
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
    trusted_contributors: Result<&[crate::api::trusted_issuers::TrustedIssuer], &str>,
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

    // H-04 / A-2: a row count is not a contributor threshold. In production,
    // every contribution must carry a valid signature from an independently
    // configured key, and repeated rows from one key count only once.
    if is_prod {
        match trusted_contributors {
            Ok(trusted) => {
                if let Err(error) =
                    manifest.verify_authenticated_contributors(trusted, MIN_PROD_CONTRIBUTORS)
                {
                    hard_reasons.push(format!(
                        "audit H-04/A-2 authenticated contributor threshold failed: {error}"
                    ));
                }
            }
            Err(error) => hard_reasons.push(format!(
                "audit H-04/A-2 authenticated contributor policy is unavailable: {error}"
            )),
        }
    } else if manifest.contributions.len() < MIN_PROD_CONTRIBUTORS {
        let msg = format!(
            "manifest has only {} contributor(s); audit A-2 requires >= {} for production \
             (single-contributor manifests are dev-only — run `phase2_ceremony.sh` with multiple parties)",
            manifest.contributions.len(),
            MIN_PROD_CONTRIBUTORS
        );
        tracing::warn!(
            "ceremony-integrity: {} {} (dev mode — allowed, but production builds will refuse)",
            circuit,
            msg
        );
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
    use crate::zk::manifest::{
        parse_trusted_contributors_json, ArtifactKind, CeremonyManifest, TRUSTED_CONTRIBUTORS_ENV,
    };
    use crate::zk::verify as zk_verify;

    let circuits: &[(&'static str, &'static str)] = &[
        ("document_existence", zk_verify::EXISTENCE_MANIFEST_JSON),
        ("non_existence", zk_verify::NON_EXISTENCE_MANIFEST_JSON),
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

    // Load this independently managed allowlist once. A missing or malformed
    // production policy remains an error value so every per-circuit result
    // explains why the authenticated threshold could not be enforced.
    let contributor_policy = if is_prod {
        std::env::var(TRUSTED_CONTRIBUTORS_ENV)
            .map_err(|_| format!("{TRUSTED_CONTRIBUTORS_ENV} is required in production"))
            .and_then(|json| {
                parse_trusted_contributors_json(&json)
                    .map_err(|error| format!("invalid {TRUSTED_CONTRIBUTORS_ENV}: {error}"))
            })
    } else {
        Ok(Vec::new())
    };

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
            let trusted_contributors = contributor_policy
                .as_ref()
                .map(|trusted| trusted.as_slice())
                .map_err(|error| error.as_str());
            apply_extra_prod_gates(
                circuit,
                &manifest,
                is_prod,
                bootstrap_pubkey,
                trusted_contributors,
            )
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

// ─── main() orchestration phases ───────────────────────────────────────────
// `fn main()` in `main.rs` extracted its `setup(|app| { ... })` body into the
// named phases below, so `main()` reads as a short sequence of phase calls
// instead of one giant nested closure tree. Each phase keeps the exact
// control flow (including every `std::process::exit(2)`) of the code it was
// lifted from; only where the code physically lives changed.

/// Phase 1: install the best-effort panic-time embedded-postgres reaper.
///
/// Covers the case where this process panics after PG starts (e.g. a
/// setup-hook timeout): the clean-exit path is handled by
/// [`crate::window_events::handle_window_event`]'s `WindowEvent::Destroyed`
/// arm, but that only runs on a normal window-close, not a panic. Without
/// this hook an orphaned `postgres.exe` would hold its port across the next
/// launch.
pub(crate) fn install_embedded_pg_panic_hook(cleanup_dir: std::path::PathBuf) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        crate::db::reap_embedded_pg(&cleanup_dir);
        prev(info);
    }));
}

/// Phase 2: resolve the ZK artifacts directory and enforce every
/// production-only startup gate (unsafe runtime configuration, a stale
/// canonicalization guest image, and placeholder ZK artifacts). Returns
/// `(is_prod, proofs_dir)` for the phases that follow.
///
/// Calls `std::process::exit(2)` itself on a fatal misconfiguration, exactly
/// as the inline code this was extracted from did — this phase does not
/// change that control flow, only where it lives.
pub(crate) fn run_preflight_checks(
    app_handle: &tauri::AppHandle,
) -> (bool, Option<std::path::PathBuf>) {
    let proofs_dir = resolve_proofs_dir(app_handle);
    let is_prod = crate::env::is_production();
    let prod_config_errors = production_runtime_config_errors();
    if !prod_config_errors.is_empty() {
        eprintln!(
            "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
             with unsafe runtime configuration:"
        );
        for reason in &prod_config_errors {
            eprintln!("[olympus-desktop]   - {reason}");
        }
        eprintln!(
            "[olympus-desktop] Rotate any copied development secrets before building or \
             sharing production artifacts."
        );
        std::process::exit(2);
    }
    for warning in production_runtime_config_warnings() {
        eprintln!("[olympus-desktop] WARNING: {warning}");
    }
    if let Err(error) = crate::zk::canonicalization::canonicalization_image_id() {
        eprintln!(
            "[olympus-desktop] WARNING: canonicalization zkVM guest integrity check \
             failed — {error}"
        );
        if is_prod {
            eprintln!(
                "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
                 without the pinned canonicalization guest ELF and matching image ID."
            );
            std::process::exit(2);
        }
    }
    if let Some(ref p) = proofs_dir {
        eprintln!("[olympus-desktop] ZK artifacts dir: {}", p.display());
        let placeholders = detect_placeholder_artifacts(p);
        if !placeholders.is_empty() {
            eprintln!(
                "[olympus-desktop] WARNING: {} placeholder ZK artifact(s) detected — \
                 /zk/prove will return 503 until `proofs/setup_circuits.sh` is run.",
                placeholders.len()
            );
            for path in &placeholders {
                eprintln!("[olympus-desktop]   placeholder: {}", path.display());
            }
            if is_prod {
                eprintln!(
                    "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
                     with placeholder ZK artifacts. Re-build with real Groth16 keys."
                );
                std::process::exit(2);
            }
        }
    } else {
        eprintln!(
            "[olympus-desktop] ZK artifacts dir: NOT FOUND \
             (set OLYMPUS_PROOFS_DIR to enable /zk/prove and /zk/verify)"
        );
        if is_prod {
            eprintln!(
                "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start without \
                 a populated ZK artifacts directory."
            );
            std::process::exit(2);
        }
    }

    (is_prod, proofs_dir)
}

/// The result `main()`'s dedicated bring-up thread reports back over its
/// `mpsc` channel: the bound port (or the reasons it never bound one), plus
/// whatever `main()`'s waiter thread needs to publish into managed state.
/// Named so [`run_server_bringup`] and [`spawn_startup_waiter`] can share it
/// as an explicit function-parameter type without tripping
/// `clippy::type_complexity` — the tuple itself is unchanged from the inline
/// turbofish-annotated channel this was extracted from.
pub(crate) type StartupBringupResult = (
    u16,
    Option<String>,
    Option<crate::db::EmbeddedDb>,
    Option<crate::commands::InitialSecretsSerde>,
);

/// Phase 3: the async server bring-up body run on the dedicated Tokio runtime
/// thread spawned from `main()`'s setup hook — DB connect (embedded or
/// external), bootstrap, BJJ/ingest-key/blind-secret/trusted-issuer
/// resolution, ceremony-manifest verification, the three background crons,
/// federation bootstrap prep + Tor/gossip spawn, `server::start`, reporting
/// the bound port back to `main()` via `tx`, then parking forever.
///
/// Preserves the exact ordering of every step in the code this was extracted
/// from — several of the comments below explain *why* the ordering matters
/// (e.g. spawning the anchor cron before `app_state` moves into
/// `server::start`), and moving this into a named function must not violate
/// the invariant those comments describe.
pub(crate) async fn run_server_bringup(
    app_data_dir: std::path::PathBuf,
    proofs_dir: Option<std::path::PathBuf>,
    tx: std::sync::mpsc::Sender<StartupBringupResult>,
) {
    let (pool, db_error, embedded) = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let pool = crate::db::connect_external(&url).await;
            let error = if pool.is_none() {
                Some(
                    "Could not prepare the external database.\n\
                 Check database connectivity, TLS, and the configured \
                 migration/runtime roles."
                        .to_owned(),
                )
            } else {
                None
            };
            (pool, error, None)
        }
        Err(std::env::VarError::NotPresent) => {
            match crate::db::init_embedded(&app_data_dir).await {
                Ok(embedded) => {
                    let pool = embedded.pool.clone();
                    (Some(pool), None, Some(embedded))
                }
                Err(e) => {
                    let msg = crate::db::embedded_startup_error_message(&e);
                    eprintln!("[olympus-desktop] {msg}");
                    (None, Some(msg), None)
                }
            }
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            let msg = "DATABASE_URL is not valid Unicode; database startup was rejected.\n\
                 Connection credentials are intentionally omitted from diagnostics."
                .to_owned();
            eprintln!("[olympus-desktop] {msg}");
            (None, Some(msg), None)
        }
    };

    // Bootstrap: ensure system user, API key, BJJ authority, and SBT exist.
    let bjj_result = if let Some(ref p) = pool {
        crate::bootstrap::run(p).await
    } else {
        None
    };

    let mut app_state = crate::state::AppState::new_with_error(pool, db_error.clone());
    let mut initial_secrets: Option<crate::commands::InitialSecretsSerde> = None;
    if let Some(br) = bjj_result {
        app_state.bjj_authority_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(
            br.bjj_authority_key,
        )));
        app_state.bjj_authority_pubkey = Some(br.bjj_authority_pubkey);
        // Resolve the Ed25519 redaction-bundle signing key:
        // explicit env key in production, else a stable
        // dev key derived from the (now-set) persisted BJJ
        // authority so `POST /redaction/issue` works on a
        // fresh checkout without extra setup.
        app_state.ingest_signing_key = crate::state::resolve_ingest_signing_key(
            crate::state::secret_bytes(&app_state.bjj_authority_key),
        );
        // Historical redaction/ingest issuer keys
        // (docs/key-rotation.md): record this instance's
        // current Ed25519 verifying key in the registry so
        // GET /redaction/issuer-key can serve prior keys
        // too, not just the live one. Non-fatal — the
        // endpoint falls back to live-key-only if this
        // fails or there's no pool.
        if let (Some(pool), Some(signing_key)) = (
            app_state.pool.as_ref(),
            crate::state::secret_bytes(&app_state.ingest_signing_key),
        ) {
            let pubkey_hex = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(signing_key)
                    .verifying_key()
                    .to_bytes(),
            );
            if let Err(e) = crate::bootstrap::ensure_ingest_signing_key(pool, &pubkey_hex).await {
                tracing::warn!("bootstrap: ingest signing key registry: {e}");
            }
        }
        // Server blinding secret for object-level redaction
        // (ADR-0026): production requires the independent,
        // explicit secret; dev derives a stable fallback from
        // the persisted BJJ authority for zero-setup local use.
        app_state.redaction_blind_secret = crate::state::resolve_redaction_blind_secret(
            crate::state::secret_bytes(&app_state.bjj_authority_key),
        );
        // Blind-secret rotation registry (migration 0058,
        // docs/key-rotation.md): detect a changed
        // OLYMPUS_REDACTION_BLIND_SECRET fingerprint against
        // the last one this database recorded. Unlike the
        // ingest signing key above, a mismatch here is NOT
        // silently adopted — it is refused unless the operator
        // opts in with OLYMPUS_BLIND_SECRET_ROTATION=confirm,
        // because an unnoticed change makes every
        // previously-redacted object's blinding permanently
        // unreproducible. `pool` is always `Some` here — this
        // whole block is inside `bjj_result`, which only exists
        // when bootstrap ran against a real pool. Production-only:
        // dev has no such guarantee to lean on and lower stakes.
        if crate::env::is_production() {
            if let (Some(pool), Some(secret)) = (
                app_state.pool.as_ref(),
                crate::state::secret_bytes(&app_state.redaction_blind_secret),
            ) {
                let fingerprint = crate::state::fingerprint_redaction_blind_secret(secret);
                match crate::bootstrap::ensure_redaction_blind_secret_fingerprint(
                    pool,
                    &fingerprint,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        // Fail closed: discard the mismatched secret so
                        // object-redaction ingest/issue 503s instead of
                        // silently producing blindings the registry can't
                        // account for.
                        app_state.redaction_blind_secret = None;
                    }
                    Err(e) => {
                        tracing::warn!("bootstrap: redaction blind secret registry: {e}");
                    }
                }
            }
        }
        // Audit M-3: resolve the full trusted-issuer set
        // (primary bootstrap pubkey + any rotation entries
        // in OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON + the
        // authority-registry supersession chain from
        // account_signing_keys, migration 0056) once at
        // startup so the scope resolver doesn't re-parse
        // per request.
        app_state.bjj_trusted_issuers =
            crate::api::trusted_issuers::load_trusted_issuers_with_registry(
                app_state.bjj_authority_pubkey.as_ref(),
                app_state.pool.as_ref(),
            )
            .await;
        // Audit CEREMONY_INTEGRITY.md #3 + #4:
        // verify each circuit's embedded ceremony
        // manifest against the trusted-issuer set
        // and the on-disk .ark.zkey. Under
        // OLYMPUS_ENV=production, any non-placeholder
        // failure is fatal — exit(2) before the
        // server starts serving. In dev, surface a
        // tracing::warn! so the operator can fix it
        // (the runtime check in
        // load_proving_key_with_manifest provides
        // belt-and-suspenders at first prove call).
        if let Some(ref proofs_path) = proofs_dir {
            let is_prod = crate::env::is_production();
            let checks = verify_ceremony_manifests(
                proofs_path,
                &app_state.bjj_trusted_issuers,
                is_prod,
                app_state.bjj_authority_pubkey.as_ref(),
            );
            let mut real_failures = 0usize;
            for ManifestCheck { circuit, result } in &checks {
                match result {
                    Ok(coord_x_dec) => {
                        tracing::info!(
                            "ceremony-integrity: {} manifest verified under coordinator x={}",
                            circuit,
                            coord_x_dec
                        );
                    }
                    Err(reason) if reason.contains("placeholder") => {
                        // detect_placeholder_artifacts above checks vkey JSON
                        // but NOT manifest files — so a binary with real
                        // .ark.zkey + placeholder manifest would otherwise
                        // sail past the earlier gate. Treat as fatal in prod
                        // so the runtime can't run without active manifest
                        // verification.
                        if is_prod {
                            real_failures += 1;
                            tracing::error!(
                                "ceremony-integrity: {} FAILED in production — {}",
                                circuit,
                                reason
                            );
                        } else {
                            tracing::warn!("ceremony-integrity: {} skipped — {}", circuit, reason);
                        }
                    }
                    Err(reason) => {
                        real_failures += 1;
                        tracing::error!("ceremony-integrity: {} FAILED — {}", circuit, reason);
                    }
                }
            }
            if real_failures > 0 && is_prod {
                eprintln!(
                    "[olympus-desktop] FATAL: OLYMPUS_ENV=production refuses to start \
                     with {real_failures} ceremony-manifest failure(s). See \
                     tracing::error! above and proofs/CEREMONY_INTEGRITY.md for \
                     the operator runbook."
                );
                std::process::exit(2);
            }
        }
        if !br.freshly_generated.is_empty() {
            // F-4: wrap each secret String in Zeroizing<String> at the
            // earliest point we own the value, so the heap region is
            // scrubbed on drop. The upstream `FreshlyGenerated` still
            // holds plain Strings briefly; widening Zeroizing into
            // bootstrap.rs is a separate larger change.
            initial_secrets = Some(crate::commands::InitialSecretsSerde {
                system_api_key: br
                    .freshly_generated
                    .system_api_key
                    .map(zeroize::Zeroizing::new),
                bjj_authority_key_hex: br
                    .freshly_generated
                    .bjj_authority_key_hex
                    .map(zeroize::Zeroizing::new),
            });
        }
    }
    app_state.proofs_dir = proofs_dir;

    // Audit H-A1: spawn the periodic anchor cron BEFORE
    // moving app_state into server::start. The cron clones
    // only the fields it needs (pool, anchoring cfg, http
    // client, BJJ key + pubkey, proofs_dir). It always runs
    // as the canonical own_checkpoints producer (red-team
    // CR-5/CR-7), but external submission to OLYMPUS_ANCHOR_*
    // backends is gated per-tick on `any_enabled()`, so a
    // build with no anchor URLs still makes no outbound
    // network calls.
    let _anchor_cron = app_state.pool.as_ref().map(|pool| {
        crate::anchoring::cron::spawn(
            pool.clone(),
            app_state.anchoring.clone(),
            app_state.anchor_http.clone(),
            crate::state::secret_bytes(&app_state.bjj_authority_key).copied(),
            app_state.bjj_authority_pubkey,
            // Red-team CR-5 / PR E: the cron is now
            // the canonical own_checkpoint producer
            // (runs `prove_existence` per tick) so
            // it needs the proofs_dir alongside the
            // BJJ key.
            app_state.proofs_dir.clone(),
        )
    });

    // Audit M-A3: spawn the OTS upgrade cron alongside the
    // anchor cron. The anchor cron above creates pending
    // OTS receipts; this one drives them through the
    // upgrade pipeline (pending → upgraded) once the OTS
    // calendars publish their Bitcoin attestations. No-op
    // when no OTS calendars are configured.
    let _ots_upgrade_cron = app_state.pool.as_ref().map(|pool| {
        crate::anchoring::upgrade_cron::spawn(
            pool.clone(),
            app_state.anchor_http.clone(),
            !app_state.anchoring.ots_calendars.is_empty(),
            app_state.anchoring.ots_bitcoin_headers_path.clone(),
        )
    });

    // ADR-0036: keep the signed-request replay cache bounded.
    // The reaper deletes expired rows via
    // ix_signed_request_nonces_expires_at and leaves live
    // nonce reservations intact.
    let _signed_request_nonce_reaper = app_state.pool.as_ref().map(|pool| {
        crate::api::middleware::signed_request::spawn_signed_request_nonce_reaper(pool.clone())
    });

    // Federation: populate the config the Tor-exposed route
    // handlers read (so they don't 503) and capture the
    // handles the Tor + gossip tasks need. The actual Tor
    // bootstrap happens AFTER the server reports its port,
    // because the hidden service proxies to that port and a
    // bootstrap can take 30-60s — longer than the startup
    // budget the Tauri thread waits on. Gated on the
    // `federation` feature AND `OLYMPUS_FEDERATION_ENABLED`.
    #[cfg(feature = "federation")]
    let federation_bootstrap = {
        let fed_cfg = crate::federation::FederationConfig::default();
        if fed_cfg.enabled {
            let state_dir = app_data_dir.join("tor");
            app_state.federation_config = Some(fed_cfg.clone());
            app_state.federation_state_dir = Some(state_dir.clone());
            // Capture proofs_dir here BEFORE app_state
            // is moved into server::start below — the
            // gossip task needs it for prove_existence
            // in build_own_checkpoint (H-11/M-5 closure).
            let proofs_dir = app_state.proofs_dir.clone();
            // Shared cell the bootstrap task publishes the
            // Tor handle into, so the credentials handler
            // can collect quorum co-signatures over Tor.
            let tor_handle_cell = app_state.tor_handle.clone();
            match (
                app_state.pool.clone(),
                crate::state::secret_bytes(&app_state.bjj_authority_key).copied(),
                app_state.bjj_authority_pubkey,
            ) {
                (Some(pool), Some(bjj_key), Some(bjj_pubkey)) => {
                    // Clone AppState for the verify-only
                    // Tor-facing listener BEFORE app_state
                    // is moved into server::start below.
                    let tor_state = app_state.clone();
                    Some((
                        pool,
                        fed_cfg,
                        bjj_key,
                        bjj_pubkey,
                        state_dir,
                        proofs_dir,
                        tor_handle_cell,
                        tor_state,
                    ))
                }
                _ => {
                    tracing::warn!(
                        "federation: OLYMPUS_FEDERATION_ENABLED set but the BJJ \
                         authority key or database is unavailable; hidden service \
                         and gossip not started"
                    );
                    None
                }
            }
        } else {
            tracing::info!(
                "federation: compiled in but OLYMPUS_FEDERATION_ENABLED not set; \
                 hidden service and gossip not started"
            );
            None
        }
    };

    let addr = crate::server::start(app_state)
        .await
        .expect("axum server failed to bind");
    let local_port = addr.port();
    tx.send((local_port, db_error, embedded, initial_secrets))
        .expect("receiver dropped before port was sent");

    // Bootstrap Tor + start gossip off the critical path so a
    // slow Tor bootstrap can't stall app startup. The task
    // owns the `Arc<TorHandle>` for its lifetime, keeping the
    // hidden service alive.
    #[cfg(feature = "federation")]
    if let Some((
        pool,
        fed_cfg,
        bjj_key,
        bjj_pubkey,
        state_dir,
        fed_proofs_dir,
        tor_handle_cell,
        tor_state,
    )) = federation_bootstrap
    {
        tokio::spawn(async move {
            // Bind the verify-only Tor-facing listener and
            // point the hidden service at IT, not the full
            // router's port. This keeps admin/auth/key/write
            // and /zk/prove off the onion surface entirely.
            let tor_local_port = match crate::server::start_tor_listener(tor_state).await {
                Ok(addr) => addr.port(),
                Err(e) => {
                    tracing::error!(
                        "federation: failed to bind Tor-facing listener: {e}; \
                         hidden service not started"
                    );
                    return;
                }
            };
            tracing::info!("federation: bootstrapping Tor hidden service (may take 30-60s)");
            match crate::federation::tor::start_hidden_service(state_dir, tor_local_port).await {
                Ok(handle) => {
                    tracing::info!(
                        "federation: hidden service live at {}; starting gossip",
                        handle.onion_address
                    );
                    let handle = std::sync::Arc::new(handle);
                    // Publish the handle so issue-time quorum
                    // co-sign collection can reach peers over
                    // Tor. Ignore the error: set() only fails
                    // if already set (a second bootstrap),
                    // which keeps the first live handle.
                    let _ = tor_handle_cell.set(handle.clone());
                    let _gossip = crate::federation::gossip::spawn(
                        pool,
                        fed_cfg,
                        bjj_key,
                        bjj_pubkey,
                        handle,
                        // proofs_dir is needed for
                        // build_own_checkpoint's
                        // prove_existence call (H-11/M-5
                        // producer-side closure). When
                        // None, build_own_checkpoint
                        // returns Err and the gossip
                        // round skips emission.
                        fed_proofs_dir.clone(),
                    );
                }
                Err(e) => {
                    tracing::error!("federation: Tor bootstrap failed; gossip not started: {e}");
                }
            }
        });
    }

    std::future::pending::<()>().await;
}

/// Phase 4: register the managed state `main()`'s setup hook depends on, up
/// front and unpopulated (the port, DB error, embedded-DB handle, and
/// one-shot initial secrets are all filled in later by
/// [`spawn_startup_waiter`]).
///
/// Overrunning the startup budget must not fail the setup hook: returning
/// `Err` from it panics Tauri with a bare "Failed to setup app" and kills the
/// process, so the one failure the user most needs explained is the one that
/// never reaches the GUI. Instead the app always comes up, and either the
/// port or a startup-error screen is published — see
/// [`spawn_startup_waiter`].
///
/// Also translates the one fatal-style startup config error that can be
/// known this early (`OLYMPUS_ENV=production` with no proofs dir) into the
/// GUI startup-error surface, rather than letting it die only on stderr.
pub(crate) fn register_initial_managed_state(
    app: &tauri::AppHandle,
    proofs_dir: &Option<std::path::PathBuf>,
    is_prod: bool,
) {
    app.manage(crate::commands::ApiState::new(
        crate::commands::ApiState::NOT_READY,
    ));
    app.manage(crate::commands::DbErrorState {
        error: std::sync::Mutex::new(None),
    });
    app.manage(crate::commands::EmbeddedDbState {
        inner: std::sync::Mutex::new(None),
    });
    app.manage(crate::commands::InitialSecretsState {
        inner: std::sync::Mutex::new(None),
    });

    // Surface fatal-style startup config errors to the GUI rather
    // than letting them die only on stderr. Populated here by the
    // OLYMPUS_ENV=production placeholder check above, and later by
    // the waiter thread if the server never reports a port.
    let startup_error = if proofs_dir.is_none() && is_prod {
        Some(crate::commands::StartupError {
            code: "PROD_NO_PROOFS_DIR".to_owned(),
            message: "OLYMPUS_ENV=production but no usable ZK artifacts \
                      directory was found. Set OLYMPUS_PROOFS_DIR or run \
                      proofs/setup_circuits.sh to populate proofs/keys/."
                .to_owned(),
            doc_url: Some(
                "https://github.com/OlympusLedgerOrg/Olympus/blob/main/proofs/README.md".to_owned(),
            ),
        })
    } else {
        None
    };
    app.manage(crate::commands::StartupErrorState {
        inner: std::sync::Mutex::new(startup_error),
    });
}

/// Phase 5: spawn the waiter thread that publishes the server thread's
/// eventual result — a bound port, or a terminal startup error — into the
/// managed state [`register_initial_managed_state`] registered.
///
/// The function itself does the `std::thread::spawn`, so the call site in
/// `main()` is one line.
pub(crate) fn spawn_startup_waiter(
    app: tauri::AppHandle,
    rx: std::sync::mpsc::Receiver<StartupBringupResult>,
) {
    // Budget for the whole embedded-Postgres bring-up, not just the
    // bind: initdb + start_db + pool connect + migrations all run
    // before the port is reported. A cold Windows start routinely
    // spends 25s+ in initdb/start_db alone.
    const STARTUP_PORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    // Publish the server thread's result into managed state, either
    // within the budget or — for a merely slow start — whenever it
    // lands. The wait is deliberately *not* cancelled at the deadline:
    // the server thread owns a live postmaster and the embedded
    // instance lock, so abandoning the channel would strand both. It
    // keeps blocking, and the app heals if startup eventually
    // completes.
    let startup_handle = app;
    std::thread::spawn(move || {
        let published = match rx.recv_timeout(STARTUP_PORT_TIMEOUT) {
            Ok(result) => Some(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                publish_startup_error(
                    &startup_handle,
                    crate::commands::StartupError {
                        code: STARTUP_TIMEOUT_CODE.to_owned(),
                        message: format!(
                            "The local server did not finish starting within {}s. \
                             Embedded PostgreSQL is usually the slow step. The app \
                             is still waiting and will recover on its own if startup \
                             completes; if it does not, check the embedded-PostgreSQL \
                             debug log next to the database directory.",
                            STARTUP_PORT_TIMEOUT.as_secs()
                        ),
                        doc_url: None,
                    },
                );
                // Keep waiting — see the comment above.
                rx.recv().ok()
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
        };

        let Some((port, db_error, embedded, initial_secrets)) = published else {
            // The channel closed without a port: the server thread is
            // gone, so nothing will arrive later. This is terminal.
            //
            // Retract first. On the timeout-then-disconnect path a
            // STARTUP_TIMEOUT is already recorded, and the first-writer-
            // wins rule would otherwise drop the terminal error and
            // leave the user reading "still waiting, will recover on its
            // own" about a thread that is dead. Retraction stays scoped
            // to the timeout code, so any other error keeps precedence.
            clear_startup_timeout(&startup_handle);
            publish_startup_error(
                &startup_handle,
                crate::commands::StartupError {
                    code: "STARTUP_FAILED".to_owned(),
                    message: "The local server stopped before it could start \
                              listening. Restart the app; if this repeats, check \
                              the console output for the underlying error."
                        .to_owned(),
                    doc_url: None,
                },
            );
            return;
        };

        if let Some(state) = startup_handle.try_state::<crate::commands::DbErrorState>() {
            if let Ok(mut guard) = state.error.lock() {
                *guard = db_error;
            }
        }
        if let Some(state) = startup_handle.try_state::<crate::commands::EmbeddedDbState>() {
            if let Ok(mut guard) = state.inner.lock() {
                *guard = embedded;
            }
        }
        if let Some(state) = startup_handle.try_state::<crate::commands::InitialSecretsState>() {
            if let Ok(mut guard) = state.inner.lock() {
                *guard = initial_secrets;
            }
        }
        // Clear a STARTUP_TIMEOUT raised above — the server did come
        // up, so the screen must not outlive the condition. Retraction
        // stays scoped to that one code so a success can only ever
        // withdraw the claim it actually disproves.
        clear_startup_timeout(&startup_handle);
        // Store the port last, so no command can observe a ready port
        // while the states it depends on are still unpopulated.
        if let Some(state) = startup_handle.try_state::<crate::commands::ApiState>() {
            state.set_port(port);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detect_placeholder_artifacts_flags_only_stubs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
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

        let offenders = detect_placeholder_artifacts(base);
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
    }

    #[test]
    fn first_populated_proofs_dir_selects_first_with_verification_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
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
                signature: None,
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
        crate::zk::manifest::BjjPubkeyJson {
            x: fr_decimal(&pk.x),
            y: fr_decimal(&pk.y),
        }
    }

    fn fr_decimal(value: &ark_bn254::Fr) -> String {
        use ark_ff::{BigInteger, PrimeField};
        num_bigint::BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_string()
    }

    /// Replace the skeleton rows with a valid contribution chain signed by
    /// the supplied keys, and return the independent allowlist for those
    /// identities. This exercises the production threshold rather than a
    /// superficial row count.
    fn authenticate_contributions(
        manifest: &mut crate::zk::manifest::CeremonyManifest,
        keys: &[[u8; 32]],
    ) -> Vec<crate::api::trusted_issuers::TrustedIssuer> {
        use crate::api::trusted_issuers::TrustedIssuer;
        use crate::zk::manifest::{BjjSignatureJson, Contribution};
        use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey};
        use ark_ff::PrimeField;

        manifest.contributions.clear();
        let mut previous = [0u8; 32];
        let mut trusted = Vec::with_capacity(keys.len());
        for (index, key) in keys.iter().enumerate() {
            let contribution_hash =
                blake3::hash(format!("startup-contribution-{index}").as_bytes());
            let mut chain = blake3::Hasher::new();
            chain.update(b"OLY:CEREMONY:CHAIN:V1");
            chain.update(&previous);
            chain.update(contribution_hash.as_bytes());
            previous = *chain.finalize().as_bytes();

            let pubkey = BabyJubJubPubKey::from_private(key).expect("contributor pubkey");
            manifest.contributions.push(Contribution {
                index: index as u32,
                contributor_id: format!("trusted-contributor-{index}"),
                contribution_hash: contribution_hash.to_hex().to_string(),
                running_chain_hash: hex::encode(previous),
                timestamp_unix: 1_748_000_000 + index as i64,
                bjj_pubkey: pubkey_json_of(&pubkey),
                signature: None,
            });
            let digest = manifest
                .contribution_signing_digest(index)
                .expect("contribution digest");
            let signature = baby_jubjub::sign(key, ark_bn254::Fr::from_le_bytes_mod_order(&digest))
                .expect("contributor signature");
            manifest.contributions[index].signature = Some(BjjSignatureJson {
                r8x: fr_decimal(&signature.r8x),
                r8y: fr_decimal(&signature.r8y),
                s: fr_decimal(&signature.s),
            });
            trusted.push(TrustedIssuer {
                pubkey,
                x_dec: fr_decimal(&pubkey.x),
                y_dec: fr_decimal(&pubkey.y),
                valid_from: None,
                valid_until: None,
                roles: Vec::new(),
            });
        }
        trusted
    }

    #[test]
    fn extra_prod_gates_dev_allows_single_contributor() {
        // Red-team A-2: in dev mode, single-contributor is allowed
        // (with a warning). Production refuses (separate test).
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", 1, pubkey_json_of(&pk));
        apply_extra_prod_gates(
            "document_existence",
            &m,
            false,
            None,
            Err("not configured in dev"),
        )
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
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&manifest_pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32]]);
        let err =
            apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk), Ok(&trusted))
                .expect_err("prod mode must refuse a one-identity threshold");
        assert!(err.contains("H-04/A-2"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_prod_requires_trusted_contributor_policy() {
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&manifest_pk));
        authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        let err = apply_extra_prod_gates(
            "document_existence",
            &m,
            true,
            Some(&boot_pk),
            Err("policy missing"),
        )
        .expect_err("production must not fall back to counting signed or unsigned rows");
        assert!(err.contains("H-04/A-2"), "error must cite finding: {err}");
        assert!(
            err.contains("policy missing"),
            "error must surface cause: {err}"
        );
    }

    #[test]
    fn extra_prod_gates_prod_accepts_three_contributors() {
        // Boundary: exactly MIN_PROD_CONTRIBUTORS contributors clears A-2.
        // Pass a distinct bootstrap pubkey so A-3's mandatory-key gate
        // (CodeRabbit follow-up) and the self-attestation check both
        // clear — the boundary we want to exercise is A-2 only.
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&manifest_pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk), Ok(&trusted))
            .expect("three authenticated identities clear H-04/A-2");
    }

    #[test]
    fn extra_prod_gates_prod_refuses_self_attesting_coordinator() {
        // Red-team A-3: coordinator pubkey equals bootstrap pubkey.
        let pk = nonzero_pubkey();
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        let err = apply_extra_prod_gates("document_existence", &m, true, Some(&pk), Ok(&trusted))
            .expect_err("self-attesting coordinator must reject in prod");
        assert!(err.contains("A-3"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_prod_accepts_distinct_coordinator() {
        let manifest_pk = nonzero_pubkey();
        let bootstrap_pk =
            crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&[11u8; 32])
                .expect("pubkey");
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&manifest_pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        apply_extra_prod_gates(
            "document_existence",
            &m,
            true,
            Some(&bootstrap_pk),
            Ok(&trusted),
        )
        .expect("distinct coordinator clears A-3");
    }

    #[test]
    fn extra_prod_gates_prod_requires_bootstrap_pubkey_for_a3() {
        // Fail-closed (review follow-up): prod must NOT silently skip A-3 when
        // no bootstrap pubkey is available to compare the coordinator against.
        let pk = nonzero_pubkey();
        let mut m = skeleton_manifest("real-ceremony", 0, pubkey_json_of(&pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        let err = apply_extra_prod_gates("document_existence", &m, true, None, Ok(&trusted))
            .expect_err("prod must refuse when the bootstrap pubkey is absent");
        assert!(err.contains("A-3"), "error must cite finding: {err}");
    }

    #[test]
    fn extra_prod_gates_dev_allows_missing_bootstrap_pubkey() {
        // Dev mode keeps working without a bootstrap pubkey (warn + continue).
        let pk = nonzero_pubkey();
        let m = skeleton_manifest("real-ceremony", MIN_PROD_CONTRIBUTORS, pubkey_json_of(&pk));
        apply_extra_prod_gates(
            "document_existence",
            &m,
            false,
            None,
            Err("not configured in dev"),
        )
        .expect("dev mode must allow a missing bootstrap pubkey");
    }

    #[test]
    fn extra_prod_gates_prod_refuses_dev_ceremony_id() {
        // Red-team A-4: ceremony_id starts with "olympus-dev-".
        // Distinct bootstrap key isolates A-4 from the new A-3
        // mandatory-key gate.
        let manifest_pk = nonzero_pubkey();
        let boot_pk = second_nonzero_pubkey();
        let mut m = skeleton_manifest("olympus-dev-1748000000", 0, pubkey_json_of(&manifest_pk));
        let trusted = authenticate_contributions(&mut m, &[[0x21; 32], [0x22; 32], [0x23; 32]]);
        let err =
            apply_extra_prod_gates("document_existence", &m, true, Some(&boot_pk), Ok(&trusted))
                .expect_err("dev-prefix ceremony_id must reject in prod");
        assert!(err.contains("A-4"), "error must cite finding: {err}");
    }

    fn runtime_errors_from(entries: &[(&str, &str)]) -> Vec<String> {
        let env: std::collections::HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        production_runtime_config_errors_with(|name| env.get(name).cloned())
    }

    fn runtime_warnings_from(entries: &[(&str, &str)]) -> Vec<String> {
        let env: std::collections::HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        production_runtime_config_warnings_with(|name| env.get(name).cloned())
    }

    #[test]
    fn prod_warning_on_anchor_key_fallback_when_anchoring_configured() {
        let warnings = runtime_warnings_from(&[
            ("OLYMPUS_ENV", "production"),
            ("OLYMPUS_ANCHOR_REKOR_URL", "https://rekor.sigstore.dev"),
        ]);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("OLYMPUS_ANCHOR_SIGN_KEY")
                    && w.contains("OLYMPUS_INGEST_SIGNING_KEY")),
            "expected shared-signer fallback warning: {warnings:?}"
        );
    }

    #[test]
    fn no_anchor_warning_when_dedicated_key_set_or_anchoring_unconfigured() {
        // Dedicated key set → no warning.
        let warnings = runtime_warnings_from(&[
            ("OLYMPUS_ENV", "production"),
            ("OLYMPUS_ANCHOR_REKOR_URL", "https://rekor.sigstore.dev"),
            ("OLYMPUS_ANCHOR_SIGN_KEY", &valid_hex_32(0x40)),
        ]);
        assert!(
            warnings.is_empty(),
            "dedicated anchor key must silence the warning: {warnings:?}"
        );
        // No anchoring backend configured → no warning either.
        let warnings = runtime_warnings_from(&[("OLYMPUS_ENV", "production")]);
        assert!(
            warnings.is_empty(),
            "unconfigured anchoring must not warn: {warnings:?}"
        );
        // Dev mode skips the check entirely.
        let warnings = runtime_warnings_from(&[
            ("OLYMPUS_ENV", "development"),
            ("OLYMPUS_ANCHOR_REKOR_URL", "https://rekor.sigstore.dev"),
        ]);
        assert!(warnings.is_empty(), "dev mode must not warn: {warnings:?}");
    }

    fn valid_hex_32(seed: u8) -> String {
        (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn prod_runtime_config_dev_mode_skips_checks() {
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "development"),
            ("OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION", "1"),
        ]);
        assert!(
            errors.is_empty(),
            "dev mode should not enforce prod gates: {errors:?}"
        );
    }

    #[test]
    fn prod_runtime_config_missing_env_fails_closed() {
        let errors = runtime_errors_from(&[]);
        let joined = errors.join("\n");
        assert!(
            joined.contains("OLYMPUS_ADMIN_KEY") && joined.contains("OLYMPUS_BJJ_AUTHORITY_KEY"),
            "unset OLYMPUS_ENV should enforce production secret gates:\n{joined}"
        );
    }

    #[test]
    fn prod_runtime_config_requires_explicit_secrets_and_blocks_public_write() {
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "production"),
            ("OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION", "1"),
        ]);
        let joined = errors.join("\n");
        for expected in [
            "OLYMPUS_ADMIN_KEY",
            "OLYMPUS_BJJ_AUTHORITY_KEY",
            "OLYMPUS_INGEST_SIGNING_KEY",
            "OLYMPUS_REDACTION_BLIND_SECRET",
            "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION",
        ] {
            assert!(
                joined.contains(expected),
                "missing {expected} in errors:\n{joined}"
            );
        }
    }

    #[test]
    fn prod_runtime_config_requires_migration_url_for_external_database() {
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "production"),
            (
                "DATABASE_URL",
                "postgresql://olympus_runtime:real-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
        ]);
        assert!(
            errors.iter().any(|error| {
                error
                    == "OLYMPUS_DATABASE_MIGRATION_URL is required when DATABASE_URL is set in production"
            }),
            "missing external migration-role error: {errors:?}"
        );
    }

    #[test]
    fn prod_runtime_config_rejects_orphaned_migration_url() {
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "production"),
            (
                "OLYMPUS_DATABASE_MIGRATION_URL",
                "postgresql://olympus_migrator:real-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
        ]);
        assert!(
            errors.iter().any(|error| {
                error
                    == "OLYMPUS_DATABASE_MIGRATION_URL must be unset unless DATABASE_URL is configured in production"
            }),
            "orphaned external migration-role error missing: {errors:?}"
        );
    }

    #[test]
    fn prod_runtime_config_rejects_pgoptions_for_external_database() {
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "production"),
            (
                "DATABASE_URL",
                "postgresql://olympus_runtime:real-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
            (
                "OLYMPUS_DATABASE_MIGRATION_URL",
                "postgresql://olympus_migrator:real-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
            ("PGOPTIONS", "-c search_path=attacker_schema"),
        ]);
        assert!(
            errors.iter().any(|error| {
                error == "PGOPTIONS must be unset when DATABASE_URL is configured in production"
            }),
            "ambient PostgreSQL session options were not rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .all(|error| !error.contains("attacker_schema")),
            "PGOPTIONS value leaked into startup errors: {errors:?}"
        );
    }

    #[test]
    fn prod_runtime_config_accepts_strong_explicit_values() {
        let bjj = valid_hex_32(1);
        let ingest = valid_hex_32(65);
        let redaction = valid_hex_32(129);
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", " production "),
            (
                "OLYMPUS_ADMIN_KEY",
                "prod-admin-key-0123456789abcdef-strong",
            ),
            ("OLYMPUS_BJJ_AUTHORITY_KEY", &bjj),
            ("OLYMPUS_INGEST_SIGNING_KEY", &ingest),
            ("OLYMPUS_REDACTION_BLIND_SECRET", &redaction),
            ("OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION", "0"),
            ("OLYMPUS_DEV_SIGNING_KEY", "false"),
            (
                "DATABASE_URL",
                "postgresql://olympus_runtime:real-runtime-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
            (
                "OLYMPUS_DATABASE_MIGRATION_URL",
                "postgresql://olympus_migrator:real-migration-passphrase@db:5432/olympus?sslmode=verify-full",
            ),
        ]);
        assert!(
            errors.is_empty(),
            "valid production config rejected: {errors:?}"
        );
    }

    #[test]
    fn prod_runtime_config_rejects_dev_and_placeholder_values() {
        let good_hex = valid_hex_32(33);
        let errors = runtime_errors_from(&[
            ("OLYMPUS_ENV", "production"),
            ("OLYMPUS_ADMIN_KEY", "change_me_use_a_real_admin_key"),
            ("OLYMPUS_BJJ_AUTHORITY_KEY", &good_hex),
            (
                "OLYMPUS_INGEST_SIGNING_KEY",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("OLYMPUS_REDACTION_BLIND_SECRET", "not-a-hex-secret"),
            ("OLYMPUS_DEV_SIGNING_KEY", "true"),
            ("OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP", "1"),
            ("OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL", "true"),
            (
                "DATABASE_URL",
                "postgresql://olympus:example_password_do_not_use@localhost/olympus",
            ),
            (
                "OLYMPUS_DATABASE_MIGRATION_URL",
                "postgresql://olympus:replace_me@localhost/olympus",
            ),
        ]);
        let joined = errors.join("\n");
        for expected in [
            "OLYMPUS_ADMIN_KEY",
            "OLYMPUS_INGEST_SIGNING_KEY",
            "OLYMPUS_REDACTION_BLIND_SECRET",
            "OLYMPUS_DEV_SIGNING_KEY",
            "OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP",
            "OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL",
            "DATABASE_URL",
            "OLYMPUS_DATABASE_MIGRATION_URL",
        ] {
            assert!(
                joined.contains(expected),
                "missing {expected} in errors:\n{joined}"
            );
        }
    }
}
