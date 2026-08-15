// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic violations for the `smt-write-outside-backend` rule
// (../olympus-rules.yml). Not real application code, not compiled or
// `mod`-included anywhere -- excluded from the production Semgrep scan step
// in ci.yml (via --exclude .semgrep/fixtures) and scanned only by the
// "Validate custom rule fixtures" step, which asserts every DML form below
// is caught. Keep this in sync with the rule's `pattern-either` call shapes
// (see that rule's own comment for the shapes and why each is covered) -- a
// form added to the rule without a matching case here is exactly the kind
// of change this fixture exists to catch (see the rule file's own header
// comment on rules that look correct while matching nothing).

use sqlx::QueryBuilder;

async fn direct_insert(pool: &sqlx::PgPool) {
    sqlx::query("INSERT INTO smt_nodes (depth, path_bits, hash) VALUES ($1, $2, $3)")
        .execute(pool)
        .await
        .unwrap();
}

async fn direct_update(pool: &sqlx::PgPool) {
    sqlx::query("UPDATE smt_leaves SET value_hash = $1 WHERE key = $2")
        .execute(pool)
        .await
        .unwrap();
}

async fn macro_insert(pool: &sqlx::PgPool) {
    sqlx::query!("INSERT INTO smt_nodes (depth, path_bits, hash) VALUES ($1, $2, $3)", 1, 2, 3)
        .execute(pool)
        .await
        .unwrap();
}

async fn builder_constructor_only() {
    let _q = QueryBuilder::<sqlx::Postgres>::new("INSERT INTO smt_nodes (depth) VALUES (1)");
}

async fn builder_push_append() {
    let mut q = QueryBuilder::<sqlx::Postgres>::new("");
    q.push("INSERT INTO smt_nodes (depth) VALUES (1)");
}
