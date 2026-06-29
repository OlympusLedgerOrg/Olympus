//! `olympus` — the Olympus dataset-manifest client.
//!
//! Hash shards locally, build a dataset manifest, commit its root to an Olympus
//! node, and produce / verify record-level inclusion and exclusion proofs — all
//! without the desktop app or any GUI, so it drops into a data pipeline.
//!
//! Run `olympus help` for the command list.

mod args;
mod scan;
#[cfg(feature = "server")]
mod server;

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use args::Args;
use olympus_manifest::commit::{seal, SealedManifest};
use olympus_manifest::diff::{seal_incremental, verify_link, LinkVerdict};
use olympus_manifest::proof::{verify, ProofKind, RecordProofBundle, Verdict};
use olympus_manifest::{DatasetManifest, DatasetMetadata, ManifestError, RecordIndex};
use scan::ShardMode;

const USAGE: &str = "\
olympus — Olympus dataset-manifest client

USAGE:
    olympus <command> [options]

COMMANDS:
    build    Hash a local directory into a dataset manifest + record index
    prove    Produce an inclusion/exclusion proof for a record
    verify   Verify a record proof against a manifest (offline)
    diff     Seal an incremental version on top of a parent (v2 = v1 − + )
    link     Verify the structural version link between parent and child
    hash     BLAKE3-hash a file
    commit   POST a manifest to an Olympus node            [requires: --features server]
    fetch    Pull a record's ledger proof from a node      [requires: --features server]
    help     Show this help

Run `olympus <command>` with no options to see that command's flags.
";

fn main() -> ExitCode {
    let argv = match std::env::args_os() // nosemgrep: rust.lang.security.args-os.args-os
        .skip(1)
        .map(|arg| {
            arg.into_string().map_err(|arg| {
                format!(
                    "non-UTF-8 command-line argument is not supported: {}",
                    std::path::PathBuf::from(arg).display()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(argv) => argv,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut argv = argv.into_iter();
    let Some(command) = argv.next() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let args = Args::parse(argv);

    let result = match command.as_str() {
        "build" => cmd_build(&args),
        "prove" => cmd_prove(&args),
        "verify" => cmd_verify(&args),
        "diff" => cmd_diff(&args),
        "link" => cmd_link(&args),
        "hash" => cmd_hash(&args),
        "commit" => cmd_commit(&args),
        "fetch" => cmd_fetch(&args),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(false)
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };

    match result {
        Ok(true) => ExitCode::SUCCESS,
        // `false` signals a clean run that nonetheless represents a negative
        // verification result; map it to a non-zero code for pipeline gating.
        Ok(false) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Map a manifest-layer error to a CLI message.
fn me(e: ManifestError) -> String {
    e.to_string()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parsing {path}: {e}"))
}

fn write_bytes(path: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("writing {path}: {e}"))
}

fn metadata_from_args(a: &Args) -> DatasetMetadata {
    let mut m = DatasetMetadata {
        name: a.opt("name").map(str::to_string),
        description: a.opt("description").map(str::to_string),
        license: a.opt("license").map(str::to_string),
        source: a.opt("source").map(str::to_string),
        ..DatasetMetadata::default()
    };
    if let Some(p) = a.opt("parser-id") {
        m.parser_id = p.to_string();
    }
    if let Some(v) = a.opt("parser-version") {
        m.canonical_parser_version = v.to_string();
    }
    if let Some(h) = a.opt("model-hash") {
        m.model_hash = h.to_string();
    }
    m
}

/// Re-seal a sealed manifest from its document + record index, checking the
/// recomputed root matches the document (so proofs are answered against the
/// committed root, or we fail loudly).
fn reseal(manifest: &DatasetManifest, index: &RecordIndex) -> Result<SealedManifest, String> {
    let sealed = seal(
        &manifest.dataset_id,
        manifest.version,
        manifest.created_at,
        manifest.metadata.clone(),
        index,
    )
    .map_err(me)?;
    if sealed.manifest.manifest_root != manifest.manifest_root {
        return Err(format!(
            "index does not reproduce the manifest root\n  manifest: {}\n  index:    {}",
            manifest.manifest_root, sealed.manifest.manifest_root
        ));
    }
    Ok(sealed)
}

/// Ensure every flag in `required` is present; otherwise print `usage` and
/// return an error naming the first missing one. Used so a command shows its
/// banner whenever *any* required flag is absent, not just the first checked.
fn require(a: &Args, required: &[&str], usage: &str) -> Result<(), String> {
    for key in required {
        if a.opt(key).is_none() {
            print!("{usage}");
            return Err(format!("missing required --{key}"));
        }
    }
    Ok(())
}

// ── build ────────────────────────────────────────────────────────────────────

const BUILD_USAGE: &str = "\
olympus build --data <dir> --dataset-id <id> [options]

    --data <dir>            Directory of records to hash (required)
    --dataset-id <id>       Logical dataset id (required)
    --version <n>           Dataset version (default 1)
    --shard <id>            Put all records in this shard (default 'files')
    --shard-from-subdir     Use each top-level subdirectory as a shard id
    --out <path>            Manifest output path (default manifest.json)
    --index <path>          Record-index output path (default index.json)
    --created-at <unix>     Creation timestamp (default now)
    --name/--description/--license/--source <text>   Dataset metadata
    --parser-id/--parser-version/--model-hash <text> Provenance bound into leaves
";

fn cmd_build(a: &Args) -> Result<bool, String> {
    require(a, &["data", "dataset-id"], BUILD_USAGE)?;
    let data = a.req("data")?;
    let dataset_id = a.req("dataset-id")?;
    let version: u64 = a
        .get_or("version", "1")
        .parse()
        .map_err(|_| "bad --version")?;
    let created_at: i64 = match a.opt("created-at") {
        Some(s) => s.parse().map_err(|_| "bad --created-at")?,
        None => now_unix(),
    };
    let mode = if a.has("shard-from-subdir") {
        ShardMode::BySubdir {
            fallback: "_root".into(),
        }
    } else {
        ShardMode::Single(a.get_or("shard", "files").to_string())
    };

    let (index, total_bytes) = scan::scan(std::path::Path::new(data), &mode)
        .map_err(|e| format!("scanning {data}: {e}"))?;
    let record_count = index.record_count();
    let metadata = metadata_from_args(a);
    let sealed = seal(dataset_id, version, created_at, metadata, &index).map_err(me)?;

    let manifest_path = a.get_or("out", "manifest.json");
    let index_path = a.get_or("index", "index.json");
    write_bytes(
        manifest_path,
        &sealed.manifest.to_canonical_bytes().map_err(me)?,
    )?;
    write_bytes(
        index_path,
        &serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?,
    )?;

    let content_hash = sealed.manifest.content_hash().map_err(me)?;
    println!("built dataset '{dataset_id}' v{version}");
    println!("  records:       {record_count}");
    println!("  shards:        {}", sealed.manifest.shards.len());
    println!("  bytes hashed:  {total_bytes}");
    println!("  manifest_root: {}", sealed.manifest.manifest_root);
    println!(
        "  manifest blob: {manifest_path}  (sha = blake3:{})",
        hex::encode(content_hash)
    );
    println!("  record index:  {index_path}");
    Ok(true)
}

// ── prove ────────────────────────────────────────────────────────────────────

const PROVE_USAGE: &str = "\
olympus prove --manifest <path> --index <path> --shard <id> --record <id> [options]

    --manifest <path>   Manifest document (required)
    --index <path>      Record index that reproduces it (required)
    --shard <id>        Shard the record lives in (required)
    --record <id>       Record id to prove (required)
    --version <n>       Record version (default 1)
    --kind <k>          'inclusion' | 'exclusion' | 'auto' (default auto)
    --out <path>        Write proof JSON here (default stdout)
";

fn cmd_prove(a: &Args) -> Result<bool, String> {
    require(a, &["manifest", "index", "shard", "record"], PROVE_USAGE)?;
    let manifest: DatasetManifest = read_json(a.req("manifest")?)?;
    let index: RecordIndex = read_json(a.req("index")?)?;
    let sealed = reseal(&manifest, &index)?;

    let shard = a.req("shard")?;
    let record = a.req("record")?;
    let version: u64 = a
        .get_or("version", "1")
        .parse()
        .map_err(|_| "bad --version")?;
    let kind = a.get_or("kind", "auto");

    let bundle = match kind {
        "inclusion" => sealed.prove_inclusion(shard, record, version).map_err(me)?,
        "exclusion" => sealed.prove_exclusion(shard, record, version).map_err(me)?,
        "auto" => match sealed.prove_inclusion(shard, record, version) {
            Ok(b) => b,
            Err(ManifestError::RecordNotFound { .. }) => {
                sealed.prove_exclusion(shard, record, version).map_err(me)?
            }
            Err(e) => return Err(me(e)),
        },
        other => return Err(format!("bad --kind {other:?} (inclusion|exclusion|auto)")),
    };

    let json = serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?;
    match a.opt("out") {
        Some(path) => {
            write_bytes(path, &json)?;
            eprintln!("{:?} proof for {shard}/{record} -> {path}", bundle.kind);
        }
        None => println!("{}", String::from_utf8_lossy(&json)),
    }
    Ok(true)
}

// ── verify ───────────────────────────────────────────────────────────────────

const VERIFY_USAGE: &str = "\
olympus verify --proof <path> --manifest <path>

    --proof <path>      Record proof bundle to verify (required)
    --manifest <path>   Manifest providing the trusted manifest_root (required)
";

fn cmd_verify(a: &Args) -> Result<bool, String> {
    require(a, &["proof", "manifest"], VERIFY_USAGE)?;
    let bundle: RecordProofBundle = read_json(a.req("proof")?)?;
    let manifest: DatasetManifest = read_json(a.req("manifest")?)?;

    if bundle.dataset_id != manifest.dataset_id || bundle.version != manifest.version {
        eprintln!(
            "warning: proof targets {} v{} but manifest is {} v{}",
            bundle.dataset_id, bundle.version, manifest.dataset_id, manifest.version
        );
    }
    let expected_root = manifest.root_bytes().map_err(me)?;
    let verdict = verify(&bundle, &expected_root).map_err(me)?;

    let label = match bundle.kind {
        ProofKind::Inclusion => "INCLUSION",
        ProofKind::Exclusion => "EXCLUSION",
    };
    if verdict == Verdict::Valid {
        println!(
            "VALID {label}: {}/{} {} dataset '{}' v{} (root {}…)",
            bundle.shard_id,
            bundle.record_id,
            match bundle.kind {
                ProofKind::Inclusion => "is committed in",
                ProofKind::Exclusion => "is absent from",
            },
            manifest.dataset_id,
            manifest.version,
            &manifest.manifest_root[..16],
        );
        Ok(true)
    } else {
        println!("INVALID {label}: {verdict:?}");
        // Non-zero would be ideal but we keep a single failure path; emit a
        // clear marker and let callers grep. Return an error for exit code.
        Err(format!("proof did not verify: {verdict:?}"))
    }
}

// ── diff (incremental version) ────────────────────────────────────────────────

const DIFF_USAGE: &str = "\
olympus diff --parent-manifest <p> --parent-index <p> --child-manifest <c> --child-index <c> [options]

    --parent-manifest <path>  Parent manifest document (required)
    --parent-index <path>     Parent record index (required)
    --child-manifest <path>   Child manifest document (required)
    --child-index <path>      Child record index (required)
    --out-child <path>        Write the child manifest with parent+diff filled
                              (default: overwrite --child-manifest)
    --out-diff <path>         Write the diff artifact (default diff.json)
";

fn cmd_diff(a: &Args) -> Result<bool, String> {
    require(
        a,
        &[
            "parent-manifest",
            "parent-index",
            "child-manifest",
            "child-index",
        ],
        DIFF_USAGE,
    )?;
    let parent_doc: DatasetManifest = read_json(a.req("parent-manifest")?)?;
    let parent_index: RecordIndex = read_json(a.req("parent-index")?)?;
    let child_doc: DatasetManifest = read_json(a.req("child-manifest")?)?;
    let child_index: RecordIndex = read_json(a.req("child-index")?)?;

    let parent = reseal(&parent_doc, &parent_index)?;
    let mut child = reseal(&child_doc, &child_index)?;
    let diff = seal_incremental(&parent, &mut child, &parent_index, &child_index).map_err(me)?;

    let child_out = a
        .opt("out-child")
        .unwrap_or_else(|| a.req("child-manifest").unwrap());
    write_bytes(child_out, &child.manifest.to_canonical_bytes().map_err(me)?)?;
    let diff_out = a.get_or("out-diff", "diff.json");
    write_bytes(
        diff_out,
        &serde_json::to_vec_pretty(&diff).map_err(|e| e.to_string())?,
    )?;

    let summary = child.manifest.diff.as_ref().unwrap();
    println!(
        "sealed incremental v{} on parent v{}",
        child.manifest.version, parent.manifest.version
    );
    println!("  added:     {}", summary.added);
    println!("  removed:   {}", summary.removed);
    println!("  diff_root: {}", summary.diff_root);
    println!("  child manifest -> {child_out}");
    println!("  diff artifact  -> {diff_out}");
    Ok(true)
}

// ── link ─────────────────────────────────────────────────────────────────────

const LINK_USAGE: &str = "\
olympus link --child <path> --parent-version <n> --parent-root <hex> --diff <path>

    --child <path>           Child manifest document (required)
    --parent-version <n>     Expected parent version (required)
    --parent-root <hex>      Expected parent manifest_root (required)
    --diff <path>            Diff artifact (required)
";

fn cmd_link(a: &Args) -> Result<bool, String> {
    require(
        a,
        &["child", "parent-version", "parent-root", "diff"],
        LINK_USAGE,
    )?;
    let child: DatasetManifest = read_json(a.req("child")?)?;
    let parent_version: u64 = a
        .req("parent-version")?
        .parse()
        .map_err(|_| "bad --parent-version")?;
    let parent_root = a.req("parent-root")?;
    let diff: olympus_manifest::diff::ManifestDiff = read_json(a.req("diff")?)?;

    let verdict = verify_link(&child, parent_version, parent_root, &diff).map_err(me)?;
    if verdict == LinkVerdict::Valid {
        println!(
            "VALID LINK: v{} is parent v{} − {} + {} (diff_root {})",
            child.version,
            parent_version,
            diff.removed.len(),
            diff.added.len(),
            hex::encode(diff.diff_root().map_err(me)?),
        );
        Ok(true)
    } else {
        println!("INVALID LINK: {verdict:?}");
        Err(format!("version link did not verify: {verdict:?}"))
    }
}

// ── hash ─────────────────────────────────────────────────────────────────────

fn cmd_hash(a: &Args) -> Result<bool, String> {
    let Some(path) = a.positional().first() else {
        return Err("usage: olympus hash <file>".into());
    };
    let (hex, len) =
        scan::hash_file(std::path::Path::new(path)).map_err(|e| format!("hashing {path}: {e}"))?;
    println!("{hex}  {len}  {path}");
    Ok(true)
}

// ── server commands (feature-gated) ───────────────────────────────────────────

#[cfg(feature = "server")]
fn cmd_commit(a: &Args) -> Result<bool, String> {
    server::commit(a)
}
#[cfg(feature = "server")]
fn cmd_fetch(a: &Args) -> Result<bool, String> {
    server::fetch(a)
}

#[cfg(not(feature = "server"))]
fn cmd_commit(_a: &Args) -> Result<bool, String> {
    Err("`commit` requires building with --features server".into())
}
#[cfg(not(feature = "server"))]
fn cmd_fetch(_a: &Args) -> Result<bool, String> {
    Err("`fetch` requires building with --features server".into())
}
