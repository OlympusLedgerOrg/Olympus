#!/usr/bin/env bash
# -----------------------------------------------------------------------
# phase2_ceremony.sh — multi-contributor Groth16 Phase 2 orchestration
#
# Phase 1 (Powers of Tau, universal) is consumed unchanged: this script
# expects `proofs/keys/powersOfTau28_hez_final_20.ptau` to exist and to
# match the trusted Hermez ceremony checksum.
#
# Phase 2 is per-circuit; this script splits it into four subcommands so
# contributors who never share a filesystem can each take a turn:
#
#   prepare    <out-dir>
#       Coordinator step 0.  Compile circuits (if needed), run
#       `groth16 setup` for each circuit using the Phase 1 ptau, and
#       write <out-dir>/<circuit>_round0.zkey + MANIFEST.txt.  This is
#       round 0 — the unsafe initial state, must be followed by at
#       least one real contribution.
#
#   contribute <in-dir> <out-dir> --name "Alice <alice@example.com>"
#                                 [--entropy "<hex or passphrase>"]
#       Contributor step.  Reads every <in-dir>/<circuit>_roundN.zkey,
#       adds an independent random contribution, and writes
#       <out-dir>/<circuit>_roundN+1.zkey + MANIFEST.txt.
#       Without --entropy snarkjs prompts interactively for a phrase
#       and additionally mixes /dev/urandom — recommended for live
#       ceremonies.
#
#   verify     <dir>
#       Coordinator step.  For each <dir>/<circuit>_round*.zkey, run
#       `snarkjs zkey verify <r1cs> <ptau> <zkey>` to confirm every
#       contribution in the chain is internally consistent and rooted
#       at the trusted Phase 1 ptau.  Exits non-zero if any check fails.
#
#   finalize   <in-dir>  [--beacon <hex>] [--beacon-iter <N>]
#       Coordinator final step.  Takes the highest-round zkey for each
#       circuit, optionally applies a public-randomness beacon (so the
#       output is publicly auditable as final), exports the verification
#       key JSON, runs `export_ark_zkey` for the arkworks runtime, and
#       stages everything into proofs/keys/.  Appends a full provenance
#       record to proofs/keys/PROVENANCE.md including every contributor
#       name + zkey hash in chain order.
#
# Suggested workflow for a 3-contributor ceremony
# -----------------------------------------------
#   coordinator$  bash proofs/phase2_ceremony.sh prepare    ceremony/round0
#   coordinator$  mail ceremony/round0 → alice
#   alice$        bash proofs/phase2_ceremony.sh contribute ceremony/round0 ceremony/round1 --name "Alice"
#   alice$        mail ceremony/round1 → bob
#   bob$          bash proofs/phase2_ceremony.sh contribute ceremony/round1 ceremony/round2 --name "Bob"
#   bob$          mail ceremony/round2 → carol
#   carol$        bash proofs/phase2_ceremony.sh contribute ceremony/round2 ceremony/round3 --name "Carol"
#   carol$        mail ceremony/round3 → coordinator
#   coordinator$  bash proofs/phase2_ceremony.sh verify     ceremony/round3
#   coordinator$  bash proofs/phase2_ceremony.sh finalize   ceremony/round3 \
#                       --beacon 0deadbeef…  --beacon-iter 10
#
# The contribute and verify steps work on any directory layout — only
# prepare and finalize touch the repo's proofs/keys/ tree.
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${SCRIPT_DIR}/keys"
VKEYS_DIR="${KEYS_DIR}/verification_keys"
BUILD_DIR="${SCRIPT_DIR}/build"
PTAU_FILE="powersOfTau28_hez_final_20.ptau"
PTAU_PATH="${KEYS_DIR}/${PTAU_FILE}"

CIRCUITS=(
  "document_existence"
  "non_existence"
  "unified_canonicalization_inclusion_root_sign"
)

SNARKJS="npx --prefix ${SCRIPT_DIR} snarkjs"

die() { echo "ERROR: $*" >&2; exit 1; }

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not in PATH"
}

require_ptau() {
  [ -f "${PTAU_PATH}" ] || die "Phase 1 ptau missing at ${PTAU_PATH}.  Drop yours there or run proofs/setup_circuits.sh first."
}

require_circom_artifacts() {
  for c in "${CIRCUITS[@]}"; do
    [ -f "${BUILD_DIR}/${c}.r1cs" ] || die "missing ${BUILD_DIR}/${c}.r1cs — run proofs/setup_circuits.sh --compile-only first"
  done
}

# Pull the highest-numbered round from a directory: <circuit>_round<N>.zkey → N
# Echoes "<N>" or empty if no rounds present.
highest_round() {
  local dir="$1" circuit="$2"
  ls "${dir}" 2>/dev/null \
    | sed -n "s/^${circuit}_round\([0-9]\+\)\.zkey$/\1/p" \
    | sort -n | tail -1
}

# ── prepare ────────────────────────────────────────────────────────────
cmd_prepare() {
  local OUT_DIR="${1:-}"
  [ -n "${OUT_DIR}" ] || die "usage: prepare <out-dir>"
  require_tool node
  require_tool npx
  require_ptau
  require_circom_artifacts

  mkdir -p "${OUT_DIR}"

  echo "==> Phase 2 prepare: ${OUT_DIR}/ (round 0 — UNSAFE, must be followed by ≥ 1 contribution)"
  for circuit in "${CIRCUITS[@]}"; do
    local r1cs="${BUILD_DIR}/${circuit}.r1cs"
    local zkey="${OUT_DIR}/${circuit}_round0.zkey"
    echo "  [setup] ${circuit}"
    ${SNARKJS} groth16 setup "${r1cs}" "${PTAU_PATH}" "${zkey}"
  done

  write_manifest "${OUT_DIR}" "0" "phase2-coordinator" "groth16 setup (round 0)"
  echo "==> round 0 prepared.  Pass ${OUT_DIR}/ to the first contributor."
  echo "    Each contribution adds independent entropy; ≥ 3 from different parties"
  echo "    is the production-recommended minimum."
}

# ── contribute ─────────────────────────────────────────────────────────
cmd_contribute() {
  local IN_DIR="${1:-}" OUT_DIR="${2:-}"
  shift 2 2>/dev/null || true
  [ -n "${IN_DIR}" ] && [ -n "${OUT_DIR}" ] || \
    die "usage: contribute <in-dir> <out-dir> --name <contributor> [--entropy <phrase>]"

  local NAME="" ENTROPY=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --name) NAME="${2:-}"; shift 2 ;;
      --entropy) ENTROPY="${2:-}"; shift 2 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
  [ -n "${NAME}" ] || die "--name <contributor> is required (printed into the zkey + PROVENANCE.md)"

  require_tool node
  require_tool npx
  mkdir -p "${OUT_DIR}"

  echo "==> Phase 2 contribution by '${NAME}'"
  for circuit in "${CIRCUITS[@]}"; do
    local round
    round="$(highest_round "${IN_DIR}" "${circuit}")"
    [ -n "${round}" ] || die "no ${circuit}_round*.zkey in ${IN_DIR}"
    local in_zkey="${IN_DIR}/${circuit}_round${round}.zkey"
    local next=$((round + 1))
    local out_zkey="${OUT_DIR}/${circuit}_round${next}.zkey"
    echo "  [contribute] ${circuit}: round ${round} → ${next}"
    if [ -n "${ENTROPY}" ]; then
      ${SNARKJS} zkey contribute "${in_zkey}" "${out_zkey}" \
        --name="${NAME}" -e="${ENTROPY}"
    else
      # Interactive: snarkjs prompts for additional entropy and mixes
      # /dev/urandom.  Best for real ceremonies.
      ${SNARKJS} zkey contribute "${in_zkey}" "${out_zkey}" --name="${NAME}"
    fi
  done

  write_manifest "${OUT_DIR}" "$((round + 1))" "${NAME}" "zkey contribute"
  echo "==> contribution recorded.  Forward ${OUT_DIR}/ to the next contributor."
  echo "    Securely destroy your local entropy: shred -u any scratch files you used."
}

# ── verify ─────────────────────────────────────────────────────────────
cmd_verify() {
  local DIR="${1:-}"
  [ -n "${DIR}" ] || die "usage: verify <dir>"
  require_tool node
  require_tool npx
  require_ptau
  require_circom_artifacts

  local FAILED=0
  echo "==> Phase 2 verify: ${DIR}/"
  for circuit in "${CIRCUITS[@]}"; do
    local r1cs="${BUILD_DIR}/${circuit}.r1cs"
    # snarkjs zkey verify validates the *chain* of contributions inside
    # the zkey it's given, so checking only the latest round is sufficient.
    local round
    round="$(highest_round "${DIR}" "${circuit}")"
    [ -n "${round}" ] || { echo "  [MISSING] ${circuit}"; FAILED=1; continue; }
    local zkey="${DIR}/${circuit}_round${round}.zkey"
    echo "  [verify ] ${circuit} (round ${round})"
    if ! ${SNARKJS} zkey verify "${r1cs}" "${PTAU_PATH}" "${zkey}"; then
      echo "  [FAIL   ] ${circuit}"
      FAILED=1
    fi
  done
  if [ "${FAILED}" -ne 0 ]; then
    die "ceremony verify FAILED — do not proceed to finalize."
  fi
  echo "==> all circuits verified against the Phase 1 ptau and the in-zkey contribution chain."
}

# ── finalize ───────────────────────────────────────────────────────────
cmd_finalize() {
  local IN_DIR="${1:-}"
  shift 1 2>/dev/null || true
  [ -n "${IN_DIR}" ] || die "usage: finalize <in-dir> [--beacon <hex>] [--beacon-iter <N>]"

  local BEACON="" BEACON_ITER="10"
  while [ $# -gt 0 ]; do
    case "$1" in
      --beacon) BEACON="${2:-}"; shift 2 ;;
      --beacon-iter) BEACON_ITER="${2:-}"; shift 2 ;;
      *) die "unknown flag: $1" ;;
    esac
  done

  require_tool node
  require_tool npx
  require_ptau
  require_circom_artifacts

  # Re-verify before finalizing — finalize is one-way and stages into the
  # tracked proofs/keys/ tree.
  cmd_verify "${IN_DIR}"

  # Locate or build the arkworks zkey exporter.
  local EXPORT_BIN="${REPO_ROOT}/target/release/export_ark_zkey"
  if [ ! -x "${EXPORT_BIN}" ]; then
    EXPORT_BIN="${REPO_ROOT}/target/debug/export_ark_zkey"
  fi
  if [ ! -x "${EXPORT_BIN}" ]; then
    echo "==> building export_ark_zkey (release)…"
    (cd "${REPO_ROOT}/src-tauri" && cargo build --release --bin export_ark_zkey)
    EXPORT_BIN="${REPO_ROOT}/target/release/export_ark_zkey"
  fi

  mkdir -p "${KEYS_DIR}" "${VKEYS_DIR}"

  # Per-circuit finalize: optional beacon, export vkey, build .ark.zkey,
  # stage .r1cs and .wasm alongside.
  for circuit in "${CIRCUITS[@]}"; do
    local round
    round="$(highest_round "${IN_DIR}" "${circuit}")"
    local input_zkey="${IN_DIR}/${circuit}_round${round}.zkey"
    local final_zkey="${BUILD_DIR}/${circuit}_final.zkey"

    if [ -n "${BEACON}" ]; then
      echo "  [beacon ] ${circuit}: ${BEACON} × ${BEACON_ITER} iter"
      ${SNARKJS} zkey beacon "${input_zkey}" "${final_zkey}" \
        "${BEACON}" "${BEACON_ITER}" \
        --name="Olympus Phase 2 beacon"
    else
      echo "  [final  ] ${circuit}: round ${round} adopted as final (no beacon)"
      cp -f "${input_zkey}" "${final_zkey}"
    fi

    echo "  [vkey   ] ${circuit}"
    ${SNARKJS} zkey export verificationkey "${final_zkey}" \
      "${VKEYS_DIR}/${circuit}_vkey.json"

    # Stage runtime artifacts: copy .r1cs and the WASM witness generator
    # into proofs/keys/, then produce the arkworks .ark.zkey the in-process
    # prover loads.
    cp -f "${BUILD_DIR}/${circuit}.r1cs" "${KEYS_DIR}/${circuit}.r1cs"
    cp -f "${BUILD_DIR}/${circuit}_js/${circuit}.wasm" "${KEYS_DIR}/${circuit}.wasm"
    echo "  [ark.zkey] ${circuit}"
    "${EXPORT_BIN}" "${final_zkey}" "${KEYS_DIR}/${circuit}.ark.zkey"
  done

  # Provenance: append to PROVENANCE.md with the full contribution chain
  # for each circuit (extracted from the zkey itself via `zkey export json`).
  write_provenance "${IN_DIR}" "${BEACON}" "${BEACON_ITER}"

  echo "==> Phase 2 finalized.  Production-ready artifacts staged under proofs/keys/."
  echo "    Commit the new vkey JSON files and the updated PROVENANCE.md."
  echo "    The .wasm/.r1cs/.ark.zkey files remain gitignored — they're bundled"
  echo "    into the Tauri release via tauri.conf.json's bundle.resources."
}

# ── helpers ────────────────────────────────────────────────────────────

write_manifest() {
  local DIR="$1" ROUND="$2" NAME="$3" ACTION="$4"
  local manifest="${DIR}/MANIFEST.txt"
  {
    echo "ceremony: olympus phase 2"
    echo "round:    ${ROUND}"
    echo "action:   ${ACTION}"
    echo "by:       ${NAME}"
    echo "host:     $(uname -n)"
    echo "timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "ptau:     ${PTAU_FILE}"
    echo "circuits:"
    for c in "${CIRCUITS[@]}"; do
      local zkey="${DIR}/${c}_round${ROUND}.zkey"
      if [ -f "${zkey}" ]; then
        echo "  - ${c}: $(sha256sum "${zkey}" | awk '{print $1}')"
      fi
    done
  } > "${manifest}"
}

write_provenance() {
  local IN_DIR="$1" BEACON="$2" BEACON_ITER="$3"
  local provenance="${KEYS_DIR}/PROVENANCE.md"
  {
    echo "# Groth16 Setup Provenance"
    echo ""
    echo "Finalized: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Ceremony:  Phase 2 multi-contributor (phase2_ceremony.sh finalize)"
    echo ""
    echo "PTAU_SOURCE: https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"
    echo "PTAU_FILE:   ${PTAU_FILE}"
    echo "PTAU_B2:     $(b2sum "${PTAU_PATH}" | awk '{print $1}')"
    if [ -n "${BEACON}" ]; then
      echo ""
      echo "Final beacon: ${BEACON} (${BEACON_ITER} iter)"
    fi
    echo ""
    echo "Verification key fingerprints (SHA-256):"
    for c in "${CIRCUITS[@]}"; do
      local vkey="${VKEYS_DIR}/${c}_vkey.json"
      [ -f "${vkey}" ] && echo "- ${c}_vkey.json: $(sha256sum "${vkey}" | awk '{print $1}')"
    done
    echo ""
    echo "Contribution chain (extracted from final zkey):"
    for c in "${CIRCUITS[@]}"; do
      echo ""
      echo "### ${c}"
      local final="${BUILD_DIR}/${c}_final.zkey"
      if [ -f "${final}" ]; then
        # snarkjs zkey export json dumps the contribution metadata
        local meta="${BUILD_DIR}/${c}_contributions.json"
        ${SNARKJS} zkey export json "${final}" "${meta}" >/dev/null 2>&1 || true
        if [ -f "${meta}" ] && command -v node >/dev/null 2>&1; then
          node -e "
            const j = require('${meta}');
            (j.contributions || []).forEach((c, i) => {
              console.log('  ' + (i+1) + '. ' + (c.name || '(unnamed)'));
              if (c.contributionHash) {
                const hex = Buffer.from(c.contributionHash).toString('hex');
                console.log('     contribution-hash: ' + hex.slice(0, 32) + '…');
              }
            });
          " || echo "  (contributor list unavailable — snarkjs export failed)"
          rm -f "${meta}"
        fi
      fi
    done
  } > "${provenance}"
}

# ── entrypoint ─────────────────────────────────────────────────────────
case "${1:-}" in
  prepare)    shift; cmd_prepare    "$@" ;;
  contribute) shift; cmd_contribute "$@" ;;
  verify)     shift; cmd_verify     "$@" ;;
  finalize)   shift; cmd_finalize   "$@" ;;
  ""|-h|--help|help)
    sed -n '2,/^# ----/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown subcommand: $1 (try: prepare | contribute | verify | finalize)"
    ;;
esac
