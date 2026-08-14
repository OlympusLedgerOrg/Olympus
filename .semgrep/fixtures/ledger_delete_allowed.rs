// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic non-violations for the `ledger-delete-violates-insert-only`
// rule -- must produce zero findings.

fn other_table_delete_is_fine(pool: &sqlx::PgPool) {
    let _ = sqlx::query("DELETE FROM sessions WHERE id = $1");
}

fn select_is_fine(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT * FROM smt_nodes WHERE depth = $1");
}

// A TRUNCATE table list that never names smt_nodes/smt_leaves must stay
// clean -- this is the negative case for the broadened multi-table regex
// (see ledger_delete_violations.rs's multi_table_truncate).
fn truncate_without_protected_tables_is_fine(pool: &sqlx::PgPool) {
    let _ = sqlx::query("TRUNCATE own_checkpoints, ingest_records CASCADE");
}
