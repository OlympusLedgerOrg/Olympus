#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

# Canonical list of integration-test binaries that share the pg_embed harness.
EMBEDDED_POSTGRES_TESTS=(
    api_db
    e2e_http
    smt_pg_backend
    checkpoint_transition_attestation
    federation_equivocation
)
readonly EMBEDDED_POSTGRES_TESTS

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
