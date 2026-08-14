// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic violations for the `ledger-delete-violates-insert-only` rule
// (../olympus-rules.yml). See smt_write_violations.rs for how these are run
// and why they live outside application code.

use sqlx::QueryBuilder;

async fn direct_delete(pool: &sqlx::PgPool) {
    sqlx::query("DELETE FROM smt_nodes WHERE depth = $1")
        .execute(pool)
        .await
        .unwrap();
}

async fn bare_truncate(pool: &sqlx::PgPool) {
    sqlx::query("TRUNCATE smt_leaves").execute(pool).await.unwrap();
}

async fn truncate_table_cascade(pool: &sqlx::PgPool) {
    sqlx::query("TRUNCATE TABLE smt_nodes CASCADE")
        .execute(pool)
        .await
        .unwrap();
}

async fn macro_delete(pool: &sqlx::PgPool) {
    sqlx::query!("DELETE FROM smt_nodes WHERE depth = $1", 1)
        .execute(pool)
        .await
        .unwrap();
}

async fn builder_push_delete() {
    let mut q = QueryBuilder::<sqlx::Postgres>::new("");
    q.push("DELETE FROM smt_leaves WHERE key = 'x'");
}

// The multi-table form that motivated broadening the TRUNCATE regex to
// match smt_nodes/smt_leaves anywhere in the table list, not just
// immediately after the keyword -- mirrors the real shape found in
// src-tauri/tests/checkpoint_smt_root_attestation.rs.
async fn multi_table_truncate(pool: &sqlx::PgPool) {
    sqlx::query("TRUNCATE own_checkpoints, ingest_records, smt_leaves, smt_nodes CASCADE")
        .execute(pool)
        .await
        .unwrap();
}
