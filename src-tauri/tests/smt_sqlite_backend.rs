// SPDX-License-Identifier: Apache-2.0

//! SQLite `NodeBackend` parity, durability, and transaction-atomicity tests.

use olympus_crypto::smt::{shard_record_key, verify_proof, SparseMerkleTree};
use olympus_tauri_lib::smt::{
    LeafRecord, LeafUpdate, NodeBackend, NodeRead, NodeWriteTransaction, PersistentSmt,
    SqliteBackend, WriteOnceViolation,
};

const PARSER_ID: &str = "sqlite-test-parser";
const CPV: &str = "v1";
const MODEL_HASH: &str = "sqlite-test-model";

#[tokio::test]
async fn sqlite_connect_rejects_a_non_sqlite_url() {
    assert!(SqliteBackend::connect("sqlite:").await.is_err());
    assert!(SqliteBackend::connect_path("").await.is_err());
    assert!(SqliteBackend::connect("postgres://localhost/not-sqlite")
        .await
        .is_err());
    assert!(SqliteBackend::connect("sqlite:unsafe.sqlite?vfs=unix-none")
        .await
        .is_err());
    assert!(
        SqliteBackend::connect("sqlite:file:unsafe.sqlite%3Fvfs%3Dunix-none")
            .await
            .is_err()
    );
    assert!(
        SqliteBackend::connect("sqlite:file%3Aunsafe.sqlite%3Fvfs%3Dunix-none")
            .await
            .is_err()
    );
    assert!(SqliteBackend::connect("sqlite:%3Amemory%3A").await.is_err());
    assert!(
        SqliteBackend::connect_path("file:unsafe.sqlite?vfs=unix-none")
            .await
            .is_err()
    );
}

fn update(shard: &str, i: u64) -> LeafUpdate {
    let mut record_key = [0u8; 32];
    record_key[..8].copy_from_slice(&i.to_be_bytes());
    record_key[31] = 0xA5;
    let mut value_hash = [0u8; 32];
    value_hash[..8].copy_from_slice(&i.to_le_bytes());
    value_hash[31] = 0x5A;
    LeafUpdate {
        key: shard_record_key(shard, &record_key),
        value_hash,
        shard_id: shard.to_owned(),
        parser_id: PARSER_ID.to_owned(),
        canonical_parser_version: CPV.to_owned(),
        model_hash: MODEL_HASH.to_owned(),
    }
}

fn reference(updates: &[LeafUpdate]) -> SparseMerkleTree {
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

#[tokio::test]
async fn sqlite_root_proof_and_reopen_match_reference() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("smt.sqlite");
    let backend = SqliteBackend::connect_path(&path).await.unwrap();

    let updates: Vec<_> = (0..64)
        .map(|i| update(if i % 2 == 0 { "alpha" } else { "beta" }, i))
        .collect();
    let expected = reference(&updates);
    let expected_root = expected.root();

    let mut tree = PersistentSmt::open(backend.clone()).await.unwrap();
    assert_eq!(tree.update_batch(&updates).await.unwrap(), expected_root);

    let proof = tree.prove(&updates[17].key).await.unwrap();
    assert_eq!(proof, expected.prove(&updates[17].key));
    assert!(verify_proof(&proof, Some(&expected_root)));
    drop(tree);
    drop(backend);

    let reopened = SqliteBackend::connect_path(&path).await.unwrap();
    let tree = PersistentSmt::open(reopened).await.unwrap();
    assert_eq!(tree.root().await.unwrap(), expected_root);
    assert_eq!(
        tree.get(&updates[17].key).await.unwrap(),
        Some(updates[17].value_hash)
    );
}

#[tokio::test]
async fn sqlite_explicit_rollback_discards_leaf_and_node_stages() {
    let dir = tempfile::tempdir().unwrap();
    let backend = SqliteBackend::connect_path(dir.path().join("rollback.sqlite"))
        .await
        .unwrap();
    let key = [0x44; 32];
    let tx = backend.begin_write().await.unwrap();
    tx.put_leaves(&[(
        key,
        LeafRecord {
            value_hash: [0x55; 32],
            shard_id: "rollback".into(),
            parser_id: PARSER_ID.into(),
            canonical_parser_version: CPV.into(),
            model_hash: MODEL_HASH.into(),
        },
    )])
    .await
    .unwrap();
    tx.put_nodes(&[(vec![], [0x66; 32])]).await.unwrap();
    tx.rollback().await.unwrap();

    assert!(backend.get_leaves(&[key]).await.unwrap().is_empty());
    assert!(backend.get_nodes(&[vec![]]).await.unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_transaction_leaf_records_are_write_once() {
    let dir = tempfile::tempdir().unwrap();
    let backend = SqliteBackend::connect_path(dir.path().join("leaf-write-once.sqlite"))
        .await
        .unwrap();
    let key = shard_record_key("immutable", &[7u8; 32]);
    let original = LeafRecord {
        value_hash: [8u8; 32],
        shard_id: "immutable".into(),
        parser_id: PARSER_ID.into(),
        canonical_parser_version: CPV.into(),
        model_hash: MODEL_HASH.into(),
    };

    let tx = backend.begin_write().await.unwrap();
    tx.put_leaves(&[(key, original.clone())]).await.unwrap();
    tx.commit().await.unwrap();

    let tx = backend.begin_write().await.unwrap();
    tx.put_leaves(&[(key, original.clone())]).await.unwrap();
    tx.commit().await.unwrap();

    let mut conflict = original.clone();
    conflict.parser_id = "different-parser".into();
    let tx = backend.begin_write().await.unwrap();
    let error = tx.put_leaves(&[(key, conflict)]).await.unwrap_err();
    assert!(error.downcast_ref::<WriteOnceViolation>().is_some());
    tx.rollback().await.unwrap();
    assert_eq!(backend.get_leaves(&[key]).await.unwrap()[&key], original);
}

#[tokio::test]
async fn sqlite_constraint_failure_after_leaf_stage_rolls_back_everything() {
    let dir = tempfile::tempdir().unwrap();
    let backend = SqliteBackend::connect_path(dir.path().join("failed-stage.sqlite"))
        .await
        .unwrap();
    let key = [0x71; 32];
    let tx = backend.begin_write().await.unwrap();
    tx.put_leaves(&[(
        key,
        LeafRecord {
            value_hash: [0x72; 32],
            shard_id: "rollback".into(),
            parser_id: PARSER_ID.into(),
            canonical_parser_version: CPV.into(),
            model_hash: MODEL_HASH.into(),
        },
    )])
    .await
    .unwrap();

    // Internal nodes stop at depth 255. A valid 256-bit path reaches SQLite
    // and fails the schema constraint after the leaf upsert was staged.
    assert!(tx.put_nodes(&[(vec![0; 256], [0x73; 32])]).await.is_err());
    tx.rollback().await.unwrap();

    assert!(backend.get_leaves(&[key]).await.unwrap().is_empty());
    assert!(backend.get_nodes(&[vec![]]).await.unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_independent_pools_serialize_disjoint_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.sqlite");
    let backend_a = SqliteBackend::connect_path(&path).await.unwrap();
    let backend_b = SqliteBackend::connect_path(&path).await.unwrap();
    let mut tree_a = PersistentSmt::open(backend_a).await.unwrap();
    let mut tree_b = PersistentSmt::open(backend_b).await.unwrap();
    let a: Vec<_> = (0..32).map(|i| update("alpha", i)).collect();
    let b: Vec<_> = (100..132).map(|i| update("beta", i)).collect();

    let (a_result, b_result) = tokio::join!(tree_a.update_batch(&a), tree_b.update_batch(&b));
    a_result.unwrap();
    b_result.unwrap();

    let mut union = a;
    union.extend(b);
    let expected_root = reference(&union).root();
    let final_backend = SqliteBackend::connect_path(&path).await.unwrap();
    let final_tree = PersistentSmt::open(final_backend).await.unwrap();
    assert_eq!(final_tree.root().await.unwrap(), expected_root);
}

#[tokio::test]
async fn sqlite_stale_handle_refreshes_proof_inside_read_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read-snapshot.sqlite");
    let backend_a = SqliteBackend::connect_path(&path).await.unwrap();
    let backend_b = SqliteBackend::connect_path(&path).await.unwrap();
    let first = update("snapshot", 1);
    let second = update("snapshot", 2);

    let mut writer = PersistentSmt::open(backend_a).await.unwrap();
    writer
        .update_batch(std::slice::from_ref(&first))
        .await
        .unwrap();
    let stale_reader = PersistentSmt::open(backend_b).await.unwrap();

    writer
        .update_batch(std::slice::from_ref(&second))
        .await
        .unwrap();
    let expected = reference(&[first, second.clone()]);
    let expected_root = expected.root();

    assert_eq!(stale_reader.root().await.unwrap(), expected_root);
    let proof = stale_reader.prove(&second.key).await.unwrap();
    assert_eq!(proof, expected.prove(&second.key));
    assert!(verify_proof(&proof, Some(&expected_root)));
}

#[tokio::test]
async fn sqlite_write_once_conflict_rolls_back_the_whole_batch() {
    let dir = tempfile::tempdir().unwrap();
    let backend = SqliteBackend::connect_path(dir.path().join("write-once.sqlite"))
        .await
        .unwrap();
    let mut tree = PersistentSmt::open(backend).await.unwrap();
    let original = update("immutable", 1);
    tree.update_batch_write_once(std::slice::from_ref(&original))
        .await
        .unwrap();

    let new_leaf = update("immutable", 2);
    let mut conflict = original.clone();
    conflict.value_hash = [0xFF; 32];
    let error = tree
        .update_batch_write_once(&[new_leaf.clone(), conflict])
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<WriteOnceViolation>().is_some());
    assert_eq!(tree.get(&new_leaf.key).await.unwrap(), None);
    assert_eq!(
        tree.get(&original.key).await.unwrap(),
        Some(original.value_hash)
    );
}
// SPDX-License-Identifier: Apache-2.0
