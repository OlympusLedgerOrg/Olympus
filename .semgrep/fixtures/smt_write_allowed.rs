// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic non-violations for the `smt-write-outside-backend` rule -- must
// produce zero findings. Paired with smt_write_violations.rs; see that
// file's header for how these are run.

use sqlx::QueryBuilder;

fn read_is_fine(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT depth, path_bits, hash FROM smt_nodes WHERE depth <= $1");
}

fn other_table_insert_is_fine() {
    let _ = sqlx::query("INSERT INTO users (name) VALUES ($1)");
}

fn other_table_builder_is_fine() {
    let mut q = QueryBuilder::<sqlx::Postgres>::new("INSERT INTO users (name) ");
    q.push_values(std::iter::once("a"), |mut row, v| {
        row.push_bind(v);
    });
}
