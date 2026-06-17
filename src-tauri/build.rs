use std::path::Path;

/// The three ceremony-bound circuits in current production scope plus
/// `federation_quorum` (gated behind the `quorum-circuit` feature).
/// Centralised so placeholder dropping and manifest checks iterate the
/// same list.
const CIRCUITS: &[&str] = &[
    "document_existence",
    "non_existence",
    "unified_canonicalization_inclusion_root_sign",
    "federation_quorum",
];

const PLACEHOLDER_STUB: &[u8] =
    b"PLACEHOLDER \xE2\x80\x94 replace by running proofs/setup_circuits.sh\n";
const JSON_PLACEHOLDER_STUB: &[u8] =
    b"{\"placeholder\": true, \"note\": \"Replaced by proofs/setup_circuits.sh\"}\n";

/// True if the file at `path` starts with one of the placeholder magic
/// bytes that `ensure_zk_artifact_placeholders` drops. Mirrored from
/// `main.rs::detect_placeholder_artifacts` so build.rs can recognise
/// pre-setup files and skip the manifest check on them.
fn is_placeholder(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PLACEHOLDER") || bytes.starts_with(b"{\"placeholder")
}

/// Ensure every artifact path listed in `tauri.conf.json`'s `bundle.resources`
/// exists at build time. The `.wasm/.r1cs/.ark.zkey` files are gitignored
/// (they're produced by `proofs/setup_circuits.sh`), but Tauri's resource
/// glob refuses to package zero-match patterns and aborts the build script.
///
/// For each missing file we drop a clearly-marked placeholder. At runtime,
/// main.rs scans for the `PLACEHOLDER` magic and refuses to start under
/// `OLYMPUS_ENV=production`; in dev it logs a loud warning and continues.
fn ensure_zk_artifact_placeholders() {
    let proofs_keys = Path::new("../proofs/keys");
    if !proofs_keys.exists() {
        return;
    }
    let manifests_dir = proofs_keys.join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap_or_else(|e| {
        panic!(
            "build.rs: failed to create manifests dir at {}: {e}",
            manifests_dir.display()
        )
    });
    for c in CIRCUITS {
        for ext in ["wasm", "r1cs", "ark.zkey"] {
            let path = proofs_keys.join(format!("{c}.{ext}"));
            if !path.exists() {
                std::fs::write(&path, PLACEHOLDER_STUB).unwrap_or_else(|e| {
                    panic!(
                        "build.rs: failed to drop placeholder artifact at {}: {e}",
                        path.display()
                    )
                });
            }
        }
        let vkey_path = proofs_keys
            .join("verification_keys")
            .join(format!("{c}_vkey.json"));
        if !vkey_path.exists() {
            std::fs::write(&vkey_path, JSON_PLACEHOLDER_STUB).unwrap_or_else(|e| {
                panic!(
                    "build.rs: failed to drop placeholder vkey at {}: {e}",
                    vkey_path.display()
                )
            });
        }
        // CEREMONY_INTEGRITY.md #1: manifest file must exist for the
        // `include_str!` in `zk/verify.rs` to resolve at compile time,
        // even on a fresh checkout that hasn't run `setup_circuits.sh`.
        // The placeholder fails `CeremonyManifest::parse` at runtime,
        // surfacing as a clear startup error rather than a missing-file
        // build failure.
        let manifest_path = manifests_dir.join(format!("{c}_manifest.json"));
        if !manifest_path.exists() {
            std::fs::write(&manifest_path, JSON_PLACEHOLDER_STUB).unwrap_or_else(|e| {
                panic!(
                    "build.rs: failed to drop placeholder manifest at {}: {e}",
                    manifest_path.display()
                )
            });
        }
    }
}

/// Audit CEREMONY_INTEGRITY.md #1 (compile-time manifest embed):
/// for each circuit, if a manifest + vkey are both present (i.e. setup
/// has been run), assert `manifest.artifacts.vkey.blake3` equals
/// `blake3(vkey_bytes)`. Panics on mismatch with a clear message naming
/// the file and the expected/computed digests.
///
/// Skipped per-circuit when either file is a placeholder stub — we
/// don't want the build to fail on a fresh checkout that hasn't run
/// `proofs/setup_circuits.sh` yet. The runtime startup gate in main.rs
/// catches that case under `OLYMPUS_ENV=production`.
fn verify_manifest_vkey_blake3() {
    let proofs_keys = Path::new("../proofs/keys");
    let manifests_dir = proofs_keys.join("manifests");
    if !manifests_dir.exists() {
        // No manifests directory at all — operator hasn't generated
        // any. Builder gets the placeholder gate as the only line of
        // defense. This is acceptable on a clean checkout but a real
        // ceremony will populate this directory.
        println!(
            "cargo:warning=proofs/keys/manifests/ missing — \
             no ceremony manifests embedded. Build will succeed but \
             runtime ceremony-integrity checks will be inert. Run \
             `proofs/setup_circuits.sh` to populate."
        );
        return;
    }

    for c in CIRCUITS {
        let manifest_path = manifests_dir.join(format!("{c}_manifest.json"));
        let vkey_path = proofs_keys
            .join("verification_keys")
            .join(format!("{c}_vkey.json"));

        // Always emit rerun-if-changed so cargo recompiles when either
        // file changes (cargo defaults to scanning the package only).
        println!("cargo:rerun-if-changed={}", manifest_path.display());
        println!("cargo:rerun-if-changed={}", vkey_path.display());

        let (Ok(manifest_bytes), Ok(vkey_bytes)) =
            (std::fs::read(&manifest_path), std::fs::read(&vkey_path))
        else {
            continue;
        };
        if is_placeholder(&manifest_bytes) || is_placeholder(&vkey_bytes) {
            continue;
        }

        // Pull `manifest.artifacts.vkey.blake3` out without deserializing
        // the whole struct (build.rs has no access to the `zk::manifest`
        // module — it's part of the crate it's building). Plain
        // `serde_json::Value` is enough; the runtime check uses the
        // strong-typed deserializer.
        let manifest: serde_json::Value = match serde_json::from_slice(&manifest_bytes) {
            Ok(v) => v,
            Err(e) => {
                panic!(
                    "build.rs: manifest at {} is not valid JSON: {e}",
                    manifest_path.display()
                );
            }
        };
        let claimed_circuit = manifest
            .get("circuit")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if claimed_circuit != *c {
            panic!(
                "build.rs: manifest at {} claims circuit `{claimed_circuit}` but is embedded \
                 against `{c}` (audit CEREMONY_INTEGRITY.md — wrong manifest under this circuit's \
                 vkey)",
                manifest_path.display()
            );
        }
        let expected_blake3 = manifest
            .get("artifacts")
            .and_then(|a| a.get("vkey"))
            .and_then(|v| v.get("blake3"))
            .and_then(|h| h.as_str())
            .unwrap_or("");
        if expected_blake3.is_empty() {
            panic!(
                "build.rs: manifest at {} missing artifacts.vkey.blake3 field",
                manifest_path.display()
            );
        }
        // LF-normalize the vkey bytes before hashing. git stores text
        // with LF and Windows checkouts re-convert to CRLF on the
        // working tree — without this, the manifest blake3 computed on
        // Windows would not match CI's Linux checkout for the same
        // logical content. Stripping `\r` is equivalent to `\r\n -> \n`
        // because JSON cannot contain a bare `\r` elsewhere. The
        // matching normalization lives in
        // `src-tauri/src/bin/generate_manifest.rs::normalize_text`.
        let vkey_lf: Vec<u8> = vkey_bytes.iter().copied().filter(|&b| b != b'\r').collect();
        let computed_blake3 = blake3::hash(&vkey_lf).to_hex().to_string();
        if expected_blake3 != computed_blake3 {
            panic!(
                "build.rs: vkey/manifest mismatch for circuit `{c}` (audit \
                 CEREMONY_INTEGRITY.md #1)\n  vkey:     {}\n  manifest: {}\n  \
                 expected blake3: {expected_blake3}\n  computed blake3: {computed_blake3}\n\n\
                 Either:\n  - the vkey was regenerated and the manifest wasn't (rerun \
                 `cargo run --release --bin generate_manifest`), or\n  - the manifest was \
                 modified without re-running the ceremony.",
                vkey_path.display(),
                manifest_path.display()
            );
        }
        println!("cargo:warning=ceremony-integrity ok: {c} vkey blake3 matches manifest");
    }
}

fn main() {
    ensure_zk_artifact_placeholders();
    verify_manifest_vkey_blake3();
    tauri_build::build()
}
