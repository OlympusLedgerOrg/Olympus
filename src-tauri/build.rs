use std::path::Path;

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
    let circuits = [
        "document_existence",
        "non_existence",
        "redaction_validity",
        "unified_canonicalization_inclusion_root_sign",
        "federation_quorum",
    ];
    let placeholder = b"PLACEHOLDER \xE2\x80\x94 replace by running proofs/setup_circuits.sh\n";
    let json_placeholder =
        b"{\"placeholder\": true, \"note\": \"Replaced by proofs/setup_circuits.sh\"}\n";
    for c in circuits {
        for ext in ["wasm", "r1cs", "ark.zkey"] {
            let path = proofs_keys.join(format!("{c}.{ext}"));
            if !path.exists() {
                let _ = std::fs::write(&path, placeholder.as_slice());
            }
        }
        let vkey_path = proofs_keys
            .join("verification_keys")
            .join(format!("{c}_vkey.json"));
        if !vkey_path.exists() {
            let _ = std::fs::write(&vkey_path, json_placeholder.as_slice());
        }
    }
}

fn main() {
    ensure_zk_artifact_placeholders();
    tauri_build::build()
}
