#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

# Canonical list of integration-test binaries that share the pg_embed harness.
EMBEDDED_POSTGRES_TESTS=(
    api_db
    e2e_http
    smt_pg_backend
    checkpoint_transition_attestation
    checkpoint_smt_root_attestation
    federation_equivocation
    db_init_embedded
)
readonly EMBEDDED_POSTGRES_TESTS

# The subset that must not share a *parallel* run with any other pg_embed
# binary, in any job.
#
# The binaries above are otherwise safe to interleave: the shared
# `tests/common` harness binds an ephemeral port and a unique data root, so
# several of them coexist in one `cargo nextest` invocation. `db_init_embedded`
# cannot. It drives `db::init_embedded`, which hardcodes port 5433 with no
# environment override, and it is the only binary that exercises the real
# cold-start path — including first population of the shared pg_embed binary
# cache under the user cache directory. Two pg_embed processes racing to
# populate that cache from cold make the loser fail
# `Invalid PostgreSQL binaries package`; once the cache is warm they interleave
# fine, and CI runners always start cold.
#
# `EMBEDDED_POSTGRES_NEXTEST_FILTER` only covers the lean job, which pairs with
# the serial `cargo test` job below. Jobs that legitimately run the harness
# binaries in parallel (e.g. the prover suite, which needs their `/zk/prove`
# coverage) must still exclude this one.
EXCLUSIVE_POSTGRES_TESTS=(
    db_init_embedded
)
readonly EXCLUSIVE_POSTGRES_TESTS

EMBEDDED_POSTGRES_NEXTEST_FILTER='not ('
EMBEDDED_POSTGRES_CARGO_TEST_ARGS=()
for embedded_postgres_test in "${EMBEDDED_POSTGRES_TESTS[@]}"; do
    if [ "${#EMBEDDED_POSTGRES_CARGO_TEST_ARGS[@]}" -gt 0 ]; then
        EMBEDDED_POSTGRES_NEXTEST_FILTER+=' or '
    fi
    EMBEDDED_POSTGRES_NEXTEST_FILTER+="binary(${embedded_postgres_test})"
    EMBEDDED_POSTGRES_CARGO_TEST_ARGS+=(--test "$embedded_postgres_test")
done
EMBEDDED_POSTGRES_NEXTEST_FILTER+=')'
readonly EMBEDDED_POSTGRES_NEXTEST_FILTER EMBEDDED_POSTGRES_CARGO_TEST_ARGS
unset embedded_postgres_test

EXCLUSIVE_POSTGRES_NEXTEST_FILTER='not ('
EXCLUSIVE_POSTGRES_CARGO_TEST_ARGS=()
for exclusive_postgres_test in "${EXCLUSIVE_POSTGRES_TESTS[@]}"; do
    if [ "${#EXCLUSIVE_POSTGRES_CARGO_TEST_ARGS[@]}" -gt 0 ]; then
        EXCLUSIVE_POSTGRES_NEXTEST_FILTER+=' or '
    fi
    EXCLUSIVE_POSTGRES_NEXTEST_FILTER+="binary(${exclusive_postgres_test})"
    EXCLUSIVE_POSTGRES_CARGO_TEST_ARGS+=(--test "$exclusive_postgres_test")
done
EXCLUSIVE_POSTGRES_NEXTEST_FILTER+=')'
readonly EXCLUSIVE_POSTGRES_NEXTEST_FILTER EXCLUSIVE_POSTGRES_CARGO_TEST_ARGS
unset exclusive_postgres_test
