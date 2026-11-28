#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

# PreToolUse hook (Bash, `if: Bash(git commit *)`): run the change-scoped fast
# gate before a commit and BLOCK on failure.
#
# Two bugs this replaces, both in the previous inline command:
#
#   1. `cargo check ... | tail -20` reports tail's exit status, so the hook
#      exited 0 whatever cargo said and could never block a commit. `set -e`
#      does not help: a pipeline's status is its last command.
#   2. It ran `cargo check --workspace` *and* `cargo clippy --workspace` on
#      every commit, duplicating `.githooks/pre-commit` and spending minutes
#      to produce 20 lines of output that were never read.
#
# Now it delegates to `tools/verify-gate/verify.mjs --fast`, which already
# scopes fmt/lint/typecheck to the files this diff touched. Exit 2 is what
# Claude Code treats as "block the tool call and show stderr to the model";
# anything else would be a warning the model never sees.

set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

out="$(node tools/verify-gate/verify.mjs --fast 2>&1)"
rc=$?

if [ "$rc" -ne 0 ]; then
    # Bounded output: the failing scope and its command, not a full log.
    printf '%s\n' "$out" | tail -40 >&2
    echo "verify-gate --fast failed (exit $rc). Fix the failure above before committing." >&2
    echo "Full gate: node tools/verify-gate/verify.mjs (see tools/verify-gate/README.md)." >&2
    exit 2
fi

# Success is three lines, not the whole run.
printf '%s\n' "$out" | tail -3
exit 0
