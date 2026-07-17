// SPDX-License-Identifier: Apache-2.0

//! Standalone judge demo for ADR-0039 transactional SMT storage.
//!
//! The binary deliberately drives the same `PersistentSmt<SqliteBackend>` used
//! by embedders and tests. It requires no network, PostgreSQL, Tauri UI, or ZK
//! ceremony artifacts.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use olympus_crypto::smt::{shard_record_key, verify_proof, Proof, SparseMerkleTree};
use olympus_tauri_lib::smt::{
    LeafRecord, LeafUpdate, NodeBackend, NodeRead, NodeWriteTransaction, PersistentSmt,
    SqliteBackend, WriteOnceViolation,
};
use serde_json::json;

const PARSER_ID: &str = "build-week-demo-parser";
const CANONICAL_VERSION: &str = "canonical_v2";
const MODEL_HASH: &str = "blake3:build-week-demo-model";

struct Options {
    database: PathBuf,
    reset: bool,
}

fn usage() {
    println!(
        "Olympus transactional SMT judge demo\n\n\
         Usage: olympus-smt-demo [--database PATH] [--reset]\n\n\
         --database PATH  SQLite file to create or reopen\n\
                          (default: olympus-build-week-demo.sqlite)\n\
         --reset          Delete only the selected demo database and its SQLite\n\
                          sidecars before running\n\
         --help           Show this help"
    );
}

fn parse_options() -> anyhow::Result<Option<Options>> {
    let mut database = PathBuf::from("olympus-build-week-demo.sqlite");
    let mut reset = false;
    let mut args = std::env::args_os().skip(1);

    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--database") => {
                let value = args.next().context("--database requires a file path")?;
                ensure!(!value.is_empty(), "--database requires a non-empty path");
                database = PathBuf::from(value);
            }
            Some("--reset") => reset = true,
            Some("--help" | "-h") => {
                usage();
                return Ok(None);
            }
            _ => anyhow::bail!(
                "unknown argument {:?}; run with --help",
                argument.to_string_lossy()
            ),
        }
    }

    ensure!(
        database.file_name().is_some(),
        "the database path must name a file, not a filesystem root"
    );
    Ok(Some(Options { database, reset }))
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn reset_database(path: &Path) -> anyhow::Result<()> {
    for target in [
        path.to_path_buf(),
        sqlite_sidecar(path, "-journal"),
        sqlite_sidecar(path, "-shm"),
        sqlite_sidecar(path, "-wal"),
    ] {
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", target.display()));
            }
        }
    }
    Ok(())
}

fn update(shard: &str, index: u64) -> LeafUpdate {
    let mut record_key = [0u8; 32];
    record_key[..8].copy_from_slice(&index.to_be_bytes());
    record_key[31] = 0xA5;

    let mut value_hash = [0u8; 32];
    value_hash[..8].copy_from_slice(&index.to_le_bytes());
    value_hash[31] = 0x5A;

    LeafUpdate {
        key: shard_record_key(shard, &record_key),
        value_hash,
        shard_id: shard.to_owned(),
        parser_id: PARSER_ID.to_owned(),
        canonical_parser_version: CANONICAL_VERSION.to_owned(),
        model_hash: MODEL_HASH.to_owned(),
    }
}

fn reference_tree(updates: &[LeafUpdate]) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    for update in updates {
        tree.update(
            update.key,
            update.value_hash,
            &update.shard_id,
            &update.parser_id,
            &update.canonical_parser_version,
            &update.model_hash,
        );
    }
    tree
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };

    if options.reset {
        reset_database(&options.database)?;
    }
    if let Some(parent) = options
        .database
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create database directory {}", parent.display()))?;
    }

    let updates: Vec<_> = (0..16)
        .map(|index| update(if index % 2 == 0 { "alpha" } else { "beta" }, index))
        .collect();
    let reference = reference_tree(&updates);
    let expected_root = reference.root();

    let writer_backend = SqliteBackend::connect_path(&options.database).await?;
    let mut writer = PersistentSmt::open(writer_backend).await?;
    writer.update_batch(&updates[..8]).await?;

    // Open a second handle before the next commit. Its proof must refresh from
    // a stable read snapshot instead of trusting its now-stale resident cache.
    let stale_backend = SqliteBackend::connect_path(&options.database).await?;
    let stale_reader = PersistentSmt::open(stale_backend).await?;
    let committed_root = writer.update_batch(&updates[8..]).await?;
    ensure!(
        committed_root == expected_root,
        "persistent root disagrees with the reference SMT"
    );
    let stale_root = stale_reader.root().await?;
    let stale_proof = stale_reader.prove(&updates[12].key).await?;
    let stale_snapshot_refresh =
        stale_root == expected_root && verify_proof(&stale_proof, Some(&expected_root));
    ensure!(
        stale_snapshot_refresh,
        "stale-reader snapshot refresh failed"
    );

    let existence_proof = writer.prove(&updates[7].key).await?;
    let existence_verified = matches!(existence_proof, Proof::Existence(_))
        && verify_proof(&existence_proof, Some(&expected_root));
    ensure!(existence_verified, "existence proof verification failed");

    let absent = update("gamma", 10_000);
    let non_existence_proof = writer.prove(&absent.key).await?;
    let non_existence_verified = matches!(non_existence_proof, Proof::NonExistence(_))
        && verify_proof(&non_existence_proof, Some(&expected_root));
    ensure!(
        non_existence_verified,
        "non-existence proof verification failed"
    );

    // Stage a leaf and an internal node in the same backend transaction, then
    // roll both back. This is a direct smoke test of ADR-0039's atomic unit.
    let audit_backend = SqliteBackend::connect_path(&options.database).await?;
    let rollback_update = update("rollback-demo", 20_000);
    let rollback_path = vec![1u8; 255];
    let nodes_before = audit_backend
        .get_nodes(std::slice::from_ref(&rollback_path))
        .await?;
    let transaction = audit_backend.begin_write().await?;
    transaction
        .put_leaves(&[(
            rollback_update.key,
            LeafRecord {
                value_hash: rollback_update.value_hash,
                shard_id: rollback_update.shard_id.clone(),
                parser_id: rollback_update.parser_id.clone(),
                canonical_parser_version: rollback_update.canonical_parser_version.clone(),
                model_hash: rollback_update.model_hash.clone(),
            },
        )])
        .await?;
    transaction
        .put_nodes(&[(rollback_path.clone(), [0x77; 32])])
        .await?;
    transaction.rollback().await?;
    let rollback_atomic = audit_backend
        .get_leaves(&[rollback_update.key])
        .await?
        .is_empty()
        && audit_backend
            .get_nodes(std::slice::from_ref(&rollback_path))
            .await?
            == nodes_before;
    ensure!(
        rollback_atomic,
        "explicit leaf/node rollback was not atomic"
    );

    // A conflicting re-commit must abort the whole batch, including an
    // otherwise-valid new leaf staged alongside it.
    let root_before_conflict = writer.root().await?;
    let new_leaf = update("alpha", 30_000);
    let mut conflict = updates[0].clone();
    conflict.value_hash = [0xFF; 32];
    let error = match writer.update_batch(&[new_leaf.clone(), conflict]).await {
        Ok(_) => anyhow::bail!("a conflicting write-once batch unexpectedly succeeded"),
        Err(error) => error,
    };
    let write_once_batch_rollback = error.downcast_ref::<WriteOnceViolation>().is_some()
        && writer.get(&new_leaf.key).await?.is_none()
        && writer.root().await? == root_before_conflict;
    ensure!(
        write_once_batch_rollback,
        "write-once conflict did not roll back the whole batch"
    );

    drop(stale_reader);
    drop(writer);
    drop(audit_backend);

    let reopened_backend = SqliteBackend::connect_path(&options.database).await?;
    let reopened = PersistentSmt::open(reopened_backend).await?;
    let durability_reopen = reopened.root().await? == expected_root
        && reopened.get(&updates[7].key).await? == Some(updates[7].value_hash);
    ensure!(durability_reopen, "durable reopen verification failed");

    let report = json!({
        "project": "Olympus",
        "build_week_feature": "transactional database-agnostic SMT storage",
        "build_commit": option_env!("OLYMPUS_DEMO_BUILD_SHA")
            .unwrap_or("unrecorded-local-build"),
        "backend": "SQLite (bundled)",
        "database": options.database.to_string_lossy(),
        "inserted_leaves": updates.len(),
        "root_blake3_hex": hex::encode(expected_root),
        "checks": {
            "existence_proof": existence_verified,
            "non_existence_proof": non_existence_verified,
            "leaf_and_node_rollback_atomic": rollback_atomic,
            "stale_reader_snapshot_refresh": stale_snapshot_refresh,
            "write_once_batch_rollback": write_once_batch_rollback,
            "durability_reopen": durability_reopen
        },
        "status": "PASS"
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
