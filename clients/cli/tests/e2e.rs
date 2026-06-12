//! End-to-end CLI test: drive the compiled `olympus` binary through the full
//! offline pipeline — build, prove (inclusion + exclusion), verify, and an
//! incremental version diff + link — over a temp dataset.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_olympus")
}

fn run(dir: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn olympus");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write(p: PathBuf, b: &[u8]) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, b).unwrap();
}

#[test]
fn full_pipeline_build_prove_verify_diff_link() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // ── v1 dataset ────────────────────────────────────────────────────────────
    let v1 = root.join("data_v1");
    write(v1.join("keep.txt"), b"alpha");
    write(v1.join("drop.txt"), b"beta");

    let (ok, out, err) = run(
        root,
        &[
            "build",
            "--data",
            v1.to_str().unwrap(),
            "--dataset-id",
            "demo",
            "--version",
            "1",
            "--shard",
            "files",
            "--out",
            "m1.json",
            "--index",
            "i1.json",
            "--created-at",
            "1700000000",
        ],
    );
    assert!(ok, "build v1 failed: {err}");
    assert!(out.contains("manifest_root:"), "{out}");

    // ── inclusion proof for a present record, then verify ─────────────────────
    let (ok, _o, err) = run(
        root,
        &[
            "prove",
            "--manifest",
            "m1.json",
            "--index",
            "i1.json",
            "--shard",
            "files",
            "--record",
            "keep.txt",
            "--out",
            "inc.json",
        ],
    );
    assert!(ok, "prove inclusion failed: {err}");
    let (ok, out, err) = run(
        root,
        &["verify", "--proof", "inc.json", "--manifest", "m1.json"],
    );
    assert!(ok, "verify inclusion failed: {err}");
    assert!(out.contains("VALID INCLUSION"), "{out}");

    // ── exclusion proof for an absent record, then verify ─────────────────────
    let (ok, _o, err) = run(
        root,
        &[
            "prove",
            "--manifest",
            "m1.json",
            "--index",
            "i1.json",
            "--shard",
            "files",
            "--record",
            "ghost.txt",
            "--out",
            "exc.json",
        ],
    );
    assert!(ok, "prove exclusion failed: {err}");
    let (ok, out, _e) = run(
        root,
        &["verify", "--proof", "exc.json", "--manifest", "m1.json"],
    );
    assert!(ok, "verify exclusion failed");
    assert!(out.contains("VALID EXCLUSION"), "{out}");

    // ── v2 dataset: drop.txt removed, new.txt added ───────────────────────────
    let v2 = root.join("data_v2");
    write(v2.join("keep.txt"), b"alpha");
    write(v2.join("new.txt"), b"gamma");
    let (ok, _o, err) = run(
        root,
        &[
            "build",
            "--data",
            v2.to_str().unwrap(),
            "--dataset-id",
            "demo",
            "--version",
            "2",
            "--shard",
            "files",
            "--out",
            "m2.json",
            "--index",
            "i2.json",
            "--created-at",
            "1700000001",
        ],
    );
    assert!(ok, "build v2 failed: {err}");

    // ── tamper detection: the v1 inclusion proof must NOT verify against the
    // v2 manifest (different root → RootMismatch → non-zero exit).
    let (ok, out, err) = run(
        root,
        &["verify", "--proof", "inc.json", "--manifest", "m2.json"],
    );
    assert!(!ok, "v1 proof should fail against v2 root: {out}");
    // Assert the specific cryptographic failure mode, not just a non-zero exit.
    let combined = format!("{out}{err}");
    assert!(
        combined.contains("RootMismatch") && combined.contains("INVALID INCLUSION"),
        "expected a RootMismatch INVALID INCLUSION marker, got stdout={out:?} stderr={err:?}"
    );

    // ── seal the incremental diff (v2 = v1 − drop + new) ──────────────────────
    let (ok, out, err) = run(
        root,
        &[
            "diff",
            "--parent-manifest",
            "m1.json",
            "--parent-index",
            "i1.json",
            "--child-manifest",
            "m2.json",
            "--child-index",
            "i2.json",
            "--out-child",
            "m2_linked.json",
            "--out-diff",
            "diff.json",
        ],
    );
    assert!(ok, "diff failed: {err}");
    assert!(out.contains("added:     1"), "{out}");
    assert!(out.contains("removed:   1"), "{out}");

    // Pull parent root out of m1.json for the link check.
    let m1: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("m1.json")).unwrap()).unwrap();
    let parent_root = m1["manifest_root"].as_str().unwrap();

    let (ok, out, err) = run(
        root,
        &[
            "link",
            "--child",
            "m2_linked.json",
            "--parent-version",
            "1",
            "--parent-root",
            parent_root,
            "--diff",
            "diff.json",
        ],
    );
    assert!(ok, "link failed: {err}");
    assert!(out.contains("VALID LINK"), "{out}");
}

#[test]
fn hash_matches_blake3() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path().join("f.bin"), b"hello");
    let (ok, out, _e) = run(tmp.path(), &["hash", "f.bin"]);
    assert!(ok);
    let want = blake3::hash(b"hello").to_hex().to_string();
    assert!(out.starts_with(&want), "got {out}");
}
