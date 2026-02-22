#!/usr/bin/env bash
# -----------------------------------------------------------------------
# tools/groth16_setup.sh — Repo-root entry point for Groth16 ceremony
#
# Wrapper around proofs/setup_circuits.sh that can be invoked from the
# repository root without having to cd into proofs/ first.
#
# Usage:
#   ./tools/groth16_setup.sh [--compile-only]
#
# Options:
#   --compile-only  Compile circuits to R1CS/WASM only; skip key generation.
#
# Outputs (full run):
#   proofs/build/<circuit>.r1cs
#   proofs/build/<circuit>_js/          (WASM witness generator)
#   proofs/build/<circuit>_final.zkey
#   proofs/keys/verification_keys/<circuit>_vkey.json
#
# Requirements: Node.js ≥ 18, npm, circom compiler
# -----------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${REPO_ROOT}/proofs/setup_circuits.sh" "$@"
