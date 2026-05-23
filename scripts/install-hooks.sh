#!/usr/bin/env bash
# Activate the shared git hooks in .githooks/ for this clone.
#
# Sets core.hooksPath so .githooks/pre-commit and .githooks/pre-push run
# automatically. Idempotent — safe to run repeatedly.
#
# Usage:
#   bash scripts/install-hooks.sh

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if [ ! -d .githooks ]; then
    echo "error: .githooks/ not found at repo root" >&2
    exit 1
fi

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push 2>/dev/null || true

echo "Git hooks activated."
echo "  pre-commit: cargo fmt + clippy + frontend lint/tsc on staged files"
echo "  pre-push:   full workspace clippy + tests + frontend build"
echo ""
echo "Bypass once with:  git commit --no-verify  /  git push --no-verify"
echo "Bypass always with: OLYMPUS_SKIP_PRECOMMIT=1 / OLYMPUS_SKIP_PREPUSH=1"
