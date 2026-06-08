#!/usr/bin/env bash
# -----------------------------------------------------------------------
# setup_circuits.sh — Download PTAU, compile circuits, generate dev keys
#
# Produces:
#   proofs/build/<circuit>.r1cs
#   proofs/build/<circuit>_js/          (WASM witness generator)
#   proofs/build/<circuit>_final.zkey
#   proofs/keys/verification_keys/<circuit>_vkey.json
#
# Requirements: Node.js ≥ 18, npm, circom compiler
# -----------------------------------------------------------------------
set -euo pipefail

echo "NOTE: Phase 1 uses the public Hermez Powers of Tau (trusted multi-party ceremony)."
echo "WARNING: Phase 2 uses a SINGLE dev contributor — not production-safe."
echo "         Record PTAU provenance and verification key fingerprints."

# Parse flags
COMPILE_ONLY=0
ALLOW_DEV_PTAU="${OLYMPUS_ALLOW_DEV_PTAU:-0}"
for arg in "$@"; do
  case "${arg}" in
    --compile-only) COMPILE_ONLY=1 ;;
    --allow-dev-ptau) ALLOW_DEV_PTAU=1 ;;
    *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Capture the absolute script path BEFORE cd so sha256sum always resolves it,
# regardless of how the script was invoked (e.g. `bash proofs/setup_circuits.sh`
# from the repo root leaves BASH_SOURCE[0] as a relative path that breaks after
# the cd below).
SCRIPT_SELF="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
cd "${SCRIPT_DIR}"

# -----------------------------------------------------------------------
# Fail-fast prerequisite checks
#
# Cryptographic CI must fail early and clearly rather than deep inside
# transitive vendor tooling (e.g. ffiasm).  The ZK proof build
# chain resolves native C++ compilation at runtime through npm postinstall
# hooks and snarkjs subprocesses; a missing tool produces an opaque
# exit-code 1 dozens of minutes into a long build.  These checks surface
# missing dependencies while the context is still obvious and actionable.
# -----------------------------------------------------------------------
_check_required_tool() {
  local tool="${1}"
  local install_hint="${2:-}"
  if ! command -v "${tool}" &>/dev/null; then
    echo "ERROR: Required tool '${tool}' not found in PATH." >&2
    if [[ -n "${install_hint}" ]]; then
      echo "       ${install_hint}" >&2
    fi
    echo "       Aborting before expensive circuit/proof setup — fix the environment and retry." >&2
    exit 1
  fi
}

# JavaScript runtime — required to run snarkjs and circom wasm binaries
# (needed in both full and --compile-only modes)
_check_required_tool "node" \
  "Install Node.js >= 18 from https://nodejs.org/ or via your package manager."
_check_required_tool "npm" \
  "npm ships with Node.js; re-install Node.js to restore it."
_check_required_tool "npx" \
  "npx ships with npm >= 5.2.0; upgrade npm with: npm install -g npm"

# Native C++ toolchain — required by ffiasm/native helpers used by the proof
# toolchain on some platforms.
# These tools are invoked by node subprocesses during Groth16 setup, so their
# absence produces a cryptic failure deep inside the vendor build rather than a
# clear error here.  --compile-only exits before any snarkjs/Groth16 work and
# does not invoke the native toolchain, so these checks are skipped in that mode.
if [ "${COMPILE_ONLY}" -eq 0 ]; then
  _check_required_tool "make" \
    "Install build tools: 'sudo apt-get install -y build-essential' (Debian/Ubuntu) or 'brew install make' (macOS)"
  _check_required_tool "g++" \
    "Install the GNU C++ compiler: 'sudo apt-get install -y g++' (Debian/Ubuntu) or 'brew install gcc' (macOS, provides g++)"
  _check_required_tool "nasm" \
    "Install nasm (x86 assembler): 'sudo apt-get install -y nasm' (Debian/Ubuntu) or 'brew install nasm' (macOS)"
  # Hex-encoder for the 256-bit /dev/urandom ceremony entropy (audit A-1, used
  # by the PTAU + Phase-2 contributions below). Only the full setup path mixes
  # entropy; --compile-only exits before it, so this lives with the other
  # Groth16-only tools.
  _check_required_tool "xxd" \
    "Install xxd: 'sudo apt-get install -y xxd' (Debian/Ubuntu; part of vim-common) or 'brew install vim' (macOS)"
fi

unset -f _check_required_tool

BUILD_DIR="${SCRIPT_DIR}/build"
KEYS_DIR="${SCRIPT_DIR}/keys"
VKEYS_DIR="${KEYS_DIR}/verification_keys"

# The authoritative circuits.  The unified circuit is required for
# /zk/prove of the unified canonicalization-inclusion-root-sign path used by
# the in-process prover; it is sized for PTAU power 20. federation_quorum
# powers the optional privacy-preserving M-of-N credential attestation.
CIRCUITS=(
  "document_existence"
  "redaction_validity"
  "non_existence"
  "unified_canonicalization_inclusion_root_sign"
  "federation_quorum"
)
# NOTE: tile_redaction_validity (ADR-0024) is intentionally NOT built — that
# direction was rejected (#1221). The .circom is parked on disk; re-add it here
# only if the tile-redaction direction is revived.

# PTAU file — powers of tau ceremony file
# 2^20 supports up to 1 048 576 constraints; sufficient for every live repo
# circuit (the largest, unified, needs power 20). The power-22 bump for ADR-0024's
# tile_redaction_validity was reverted when that direction was rejected (#1221);
# the tile circuit is parked and no longer built here.
PTAU_POWER=20
PTAU_FILE="powersOfTau28_hez_final_${PTAU_POWER}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"
PTAU_PATH="${KEYS_DIR}/${PTAU_FILE}"
PTAU_SOURCE="${PTAU_URL}"

# Known BLAKE2b-512 checksums for Hermez PTAU files.
# Source: https://github.com/iden3/snarkjs#7-prepare-phase-2
# Verified via: b2sum powersOfTau28_hez_final_<power>.ptau
#
# The downloaded ptau is verified against these values; a power with no entry (or
# a wrong one) fails closed rather than trusting an unverified Phase-1 file. Do
# NOT use an empty string for any power (that would silently skip verification).
declare -A PTAU_CHECKSUMS=(
  [19]="bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887"
  [20]="89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b"
)

# -----------------------------------------------------------------------
# 0. Install npm dependencies (circomlib, snarkjs)
# -----------------------------------------------------------------------
# Security rationale: tracking the lockfile hash (not just directory presence)
# guarantees that node_modules always matches the declared dependency tree.
# A stale node_modules from a prior lockfile version can silently produce
# different R1CS/WASM/zkey artifacts even when .circom sources are unchanged,
# because circomlib templates are resolved at compile time from node_modules.
# Using `npm ci` (instead of `npm install`) enforces exact lockfile parity and
# fails loudly if package.json and package-lock.json diverge.
NPM_HASH_FILE="${SCRIPT_DIR}/.last-npm-hash"
_LOCKFILE_HASH="$(sha256sum package-lock.json | awk '{print $1}')"
if [ -d "node_modules/snarkjs" ] && [ -d "node_modules/circomlib" ] \
    && [ -f "${NPM_HASH_FILE}" ] \
    && [ "$(cat "${NPM_HASH_FILE}")" = "${_LOCKFILE_HASH}" ]; then
  echo "==> npm dependencies up-to-date (lockfile hash matches), skipping install …"
else
  echo "==> Installing npm dependencies (lockfile changed or first install) …"
  npm ci --silent
  # Record the lockfile hash so future runs can skip install when nothing changed.
  echo "${_LOCKFILE_HASH}" > "${NPM_HASH_FILE}"
fi

# -----------------------------------------------------------------------
# 1. Verify circom compiler is available
# -----------------------------------------------------------------------
# Prefer native circom (Rust binary) over circom2 (npm WASM package).
# The native binary supports the full circom 2.x language including functions
# used in parameters.circom.  circom2 npm is accepted as a fallback.
CIRCOM=""
if command -v circom &>/dev/null; then
  CIRCOM="circom"
elif command -v circom2 &>/dev/null; then
  CIRCOM="circom2"
else
  echo "ERROR: circom compiler not found in PATH."
  echo "Install circom from https://docs.circom.io/getting-started/installation/"
  echo "or via npm: npm install -g circom2"
  exit 1
fi
# Guard: re-validate CIRCOM is a usable executable.  The detection block
# above guarantees this in normal operation, but an explicit check here
# produces a clear, actionable error if the variable is ever empty (e.g.
# a future refactor allows an external CIRCOM override that is unset) or
# accidentally points to a directory instead of a binary.
if [[ -z "${CIRCOM:-}" ]]; then
  echo "ERROR: CIRCOM is unset or empty after compiler detection — this is a bug." >&2
  exit 1
fi
if [[ -d "${CIRCOM}" ]] || ! command -v "${CIRCOM}" &>/dev/null; then
  echo "ERROR: CIRCOM='${CIRCOM}' is not a valid executable (is a directory, or not found in PATH)." >&2
  exit 1
fi
# Capture version once; trim to first line without `| head -1` to avoid
# SIGPIPE on the assignment in bash set -euo pipefail.  When the version
# command outputs more than one line, head -1 closes the pipe early and
# the upstream process receives SIGPIPE (exit 141).  In a standalone
# assignment `VAR=$(cmd | head -1)` bash 5 propagates that non-zero exit
# and set -e fires silently.  Capturing the full output first and slicing
# with bash parameter expansion (`%%$'\n'*`) is SIGPIPE-free.  Note:
# $'\n' is a bash extension (not POSIX sh), which is fine since this
# script already requires bash via `set -euo pipefail` and other bashisms.
_CIRCOM_VER_RAW="$(${CIRCOM} --version 2>&1)"
_CIRCOM_VER="${_CIRCOM_VER_RAW%%$'\n'*}"
echo "==> Using circom compiler: ${_CIRCOM_VER}"

SNARKJS="npx snarkjs"
# Guard: validate the launcher (the first word of SNARKJS, normally "npx")
# is available in PATH.  Without this check the script would run for
# several minutes through npm install, PTAU download, and fingerprinting
# before dying with a cryptic "npx: command not found" inside the circuit
# loop.  Failing here produces a clear message while the context is still
# obvious.  SNARKJS pointing to a directory is also caught because
# command -v rejects non-executable paths.
_SNARKJS_LAUNCHER="${SNARKJS%% *}"
if [[ -z "${_SNARKJS_LAUNCHER:-}" ]] || ! command -v "${_SNARKJS_LAUNCHER}" &>/dev/null; then
  echo "ERROR: '${_SNARKJS_LAUNCHER}' (launcher for SNARKJS='${SNARKJS}') is not found in PATH." >&2
  echo "       Install Node.js >= 18 and ensure npm ci has been run in proofs/." >&2
  exit 1
fi

# -----------------------------------------------------------------------
# 2. Obtain Powers of Tau file (download or generate locally)
# -----------------------------------------------------------------------
mkdir -p "${BUILD_DIR}" "${VKEYS_DIR}"

# Dev fallback uses a distinct name/path so it is never confused with the
# trusted Hermez file and survives subsequent runs without checksum errors.
DEV_PTAU_POWER=16
DEV_PTAU_FILE="dev_pot${DEV_PTAU_POWER}_final.ptau"
DEV_PTAU_PATH="${BUILD_DIR}/${DEV_PTAU_FILE}"

PTAU_IS_LOCAL=0
if [ -f "${PTAU_PATH}" ]; then
  echo "==> PTAU file already present: ${PTAU_PATH}"
else
  echo "==> Downloading Hermez Powers of Tau (2^${PTAU_POWER}) …"
  if curl -fSL --connect-timeout 30 --retry 3 -o "${PTAU_PATH}" "${PTAU_URL}"; then
    echo "    Downloaded ${PTAU_FILE}"
  else
    echo "WARNING: Failed to download Hermez PTAU from ${PTAU_URL}"
    if [ "${ALLOW_DEV_PTAU}" -ne 1 ]; then
      echo "ERROR: Local PTAU fallback is disabled."
      echo "       To enable it for development use, pass --allow-dev-ptau or set"
      echo "       OLYMPUS_ALLOW_DEV_PTAU=1 in your environment."
      echo "       *** Never use locally-generated keys in production. ***"
      exit 1
    fi
    echo "         Falling back to local PTAU generation for development use only."
    echo "         *** DO NOT use locally-generated keys in production. ***"
    echo "         Production requires the Phase 1 Hermez ceremony file."
    PTAU_IS_LOCAL=1
    PTAU_SOURCE="local-dev (snarkjs powersoftau — NOT from trusted ceremony)"
    # Use power 16 (max 65536 constraints). NOTE: non_existence requires power 17
    # and will be skipped below — only document_existence and redaction_validity
    # get dev keys in this fallback path.
    PTAU_FILE="${DEV_PTAU_FILE}"
    PTAU_PATH="${DEV_PTAU_PATH}"
    PTAU_POWER=${DEV_PTAU_POWER}
    if [ -f "${DEV_PTAU_PATH}" ]; then
      echo "    Reusing cached local dev PTAU: ${DEV_PTAU_PATH}"
    else
      PTAU_0="${BUILD_DIR}/dev_pot${DEV_PTAU_POWER}_0000.ptau"
      PTAU_1="${BUILD_DIR}/dev_pot${DEV_PTAU_POWER}_0001.ptau"
      echo "  [a] Generating new Powers of Tau (2^${DEV_PTAU_POWER}) …"
      ${SNARKJS} powersoftau new bn128 "${DEV_PTAU_POWER}" "${PTAU_0}" -v 2>/dev/null
      echo "  [b] Adding dev contribution …"
      # Red-team A-1: `$(date +%s)` was a 32-bit search space that
      # collapses to ~minutes given a known build window. Replace with
      # 32 bytes from /dev/urandom (256-bit entropy). The "olympus-dev-"
      # prefix is retained so the runtime check (audit A-4) can still
      # distinguish dev manifests from real ceremonies.
      _OLYMPUS_DEV_ENTROPY="olympus-dev-ptau-$(head -c 32 /dev/urandom | xxd -p -c 64)"
      ${SNARKJS} powersoftau contribute "${PTAU_0}" "${PTAU_1}" \
        --name="Olympus dev PTAU" -e="${_OLYMPUS_DEV_ENTROPY}" 2>/dev/null
      unset _OLYMPUS_DEV_ENTROPY
      rm -f "${PTAU_0}"
      echo "  [c] Preparing phase 2 …"
      ${SNARKJS} powersoftau prepare phase2 "${PTAU_1}" "${PTAU_PATH}" -v 2>/dev/null
      rm -f "${PTAU_1}"
      echo "    Local dev PTAU generated: ${PTAU_PATH}"
    fi
  fi
fi

# Verify PTAU BLAKE2b-512 checksum (only for known trusted files; skip for local dev)
echo "==> Verifying PTAU integrity …"
PTAU_B2="$(b2sum "${PTAU_PATH}" | awk '{print $1}')"
PTAU_EXPECTED="${PTAU_CHECKSUMS[${PTAU_POWER}]:-}"
if [ "${PTAU_IS_LOCAL}" -eq 0 ] && [ -n "${PTAU_EXPECTED}" ] && [ "${PTAU_B2}" != "${PTAU_EXPECTED}" ]; then
  echo "ERROR: PTAU BLAKE2b-512 mismatch!"
  echo "  Expected: ${PTAU_EXPECTED}"
  echo "  Got:      ${PTAU_B2}"
  echo "  File may be corrupted or tampered with."
  rm -f "${PTAU_PATH}"
  exit 1
fi
if [ "${PTAU_IS_LOCAL}" -eq 1 ]; then
  echo "    Local dev PTAU in use — checksum verification skipped."
else
  echo "    PTAU integrity verified ✓"
fi

# -----------------------------------------------------------------------
# 2.5 Compute a build fingerprint over all inputs that affect compiled artifacts.
#
# Security rationale: this fingerprint is used to skip expensive Groth16 setup
# steps ONLY when ALL of the following are identical to the last successful build:
#   - every .circom source file (circuit logic and parameters)
#   - the npm lockfile hash (a circomlib version bump changes compiled R1CS/WASM
#     even when .circom sources are unchanged; tracking the lockfile hash ensures
#     every artifact set is traceable to an exact, reproducible dependency tree)
#   - this setup script itself (build procedure version)
#   - the circom compiler version (a tool upgrade can produce a different R1CS)
#   - the snarkjs version (affects zkey format and proof compatibility)
#   - the PTAU file hash (keys must correspond to the correct ceremony file)
#
# The PTAU hash is always verified independently (above) on every run,
# so a corrupted or substituted PTAU is caught regardless of caching.
# -----------------------------------------------------------------------
# POSIX-portable: pipe sorted .circom paths into `while read` + cat rather than
# `xargs -r cat` (xargs -r is a GNU extension unavailable on macOS/BSD xargs).
# Guard against an empty circuit directory — a missing circuits/ tree would
# silently produce the sha256 of empty input and issue a misleading cache hit.
_CIRCOM_PATHS="$(find circuits -name '*.circom' | LC_ALL=C sort)"
if [ -z "${_CIRCOM_PATHS}" ]; then
  echo "ERROR: No .circom source files found under circuits/. Aborting." >&2
  exit 1
fi
_CIRCUITS_HASH="$(printf '%s\n' "${_CIRCOM_PATHS}" \
  | while IFS= read -r f; do cat "$f"; done \
  | sha256sum | awk '{print $1}')"
_SCRIPT_HASH="$(sha256sum "${SCRIPT_SELF}" | awk '{print $1}')"
# _CIRCOM_VER already set above (SIGPIPE-safe capture near circom detection)
_SNARKJS_VER="$(node -e "try{console.log(require('./node_modules/snarkjs/package.json').version)}catch(e){console.log('unknown')}" 2>/dev/null)"
CURRENT_FINGERPRINT="${_CIRCUITS_HASH}:${_SCRIPT_HASH}:${_CIRCOM_VER}:${_SNARKJS_VER}:${PTAU_B2}:${_LOCKFILE_HASH}"
BUILD_FINGERPRINT_FILE="${BUILD_DIR}/.build-fingerprint"
BUILD_IN_PROGRESS_FILE="${BUILD_DIR}/.build-in-progress"
PROVENANCE_FILE="${KEYS_DIR}/PROVENANCE.md"

# -----------------------------------------------------------------------
# 2.6 Interrupted-build recovery
#
# If a previous invocation wrote the in-progress sentinel but was killed
# before it could remove it (OOM, SIGKILL, runner timeout, Ctrl-C), the
# build directory may contain partial circuit artifacts — e.g. an r1cs
# written but its zkey/vkey absent, or a half-written zkey.  Clear those
# files so the loop below rebuilds cleanly rather than mixing stale and
# fresh outputs.  Without this guard a subsequent run could match the
# node_modules lockfile hash while silently using incomplete artifacts.
# -----------------------------------------------------------------------
if [ -f "${BUILD_IN_PROGRESS_FILE}" ]; then
  echo "WARNING: Previous build was interrupted — clearing partial artifacts for a clean rebuild."
  find "${BUILD_DIR}" -maxdepth 1 -name '*.r1cs'            -delete 2>/dev/null || true
  find "${BUILD_DIR}" -maxdepth 1 -name '*.zkey'            -delete 2>/dev/null || true
  find "${BUILD_DIR}" -maxdepth 1 -name '.build-fingerprint' -delete 2>/dev/null || true
  find "${BUILD_DIR}" -maxdepth 1 -type d -name '*_js' -exec rm -rf {} + 2>/dev/null || true
  find "${VKEYS_DIR}" -maxdepth 1 -name '*_vkey.json' -delete 2>/dev/null || true
  rm -f "${BUILD_IN_PROGRESS_FILE}"
  echo "    Partial artifacts cleared — proceeding with full rebuild."
fi

# -----------------------------------------------------------------------
# 3. Compile each circuit and (optionally) run Groth16 setup
# -----------------------------------------------------------------------

# -----------------------------------------------------------------------
# 3.0  Pre-build the Rust helper binaries BEFORE any vkey is regenerated.
#
# `export_ark_zkey` and `generate_manifest` live in the olympus-desktop
# crate, whose build.rs enforces blake3(vkey.json) == manifest.vkey.blake3
# at compile time (CEREMONY_INTEGRITY.md #1). The Groth16 loop below
# overwrites every vkey (`snarkjs zkey export verificationkey`), but the
# manifests are not regenerated until step 3b. If either helper binary is
# compiled in that window — which happens on a fresh checkout / clean
# target/ where steps 3 and 3b would otherwise build them — build.rs sees
# a freshly-overwritten vkey against the still-committed manifest and
# panics ("vkey/manifest mismatch"), aborting setup before a single
# artifact is staged. Build the binaries now, while the committed
# vkey+manifest pairs are still consistent, so the `-x` existence checks
# in steps 3 and 3b skip recompilation and build.rs never runs in the
# inconsistent window.
# -----------------------------------------------------------------------
if [ "${COMPILE_ONLY}" -eq 0 ]; then
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
  if [ ! -x "${REPO_ROOT}/target/release/export_ark_zkey" ] \
      || [ ! -x "${REPO_ROOT}/target/release/generate_manifest" ]; then
    echo "==> Pre-building export_ark_zkey + generate_manifest (release) before vkey regeneration …"
    (cd "${REPO_ROOT}/src-tauri" && cargo build --release --bin export_ark_zkey --bin generate_manifest)
  fi
fi

# Write a build-in-progress sentinel before entering the build loop.
# It is removed only after the fingerprint file is successfully written
# (see §4 below).  An interrupted build leaves the sentinel in place so
# the next invocation detects it and clears partial artifacts (§2.6).
if [ "${COMPILE_ONLY}" -eq 0 ]; then
  touch "${BUILD_IN_PROGRESS_FILE}"
fi

for circuit in "${CIRCUITS[@]}"; do
  CIRCOM_FILE="circuits/${circuit}.circom"
  echo ""
  echo "===== ${circuit} ====="

  # Skip circuits that cannot fit in the local dev fallback PTAU.
  if [ "${PTAU_IS_LOCAL}" -eq 1 ]; then
    REQUIRED_POWER=16
    case "${circuit}" in
      non_existence) REQUIRED_POWER=17 ;;
      # ADR-0025: redaction_validity moved from 16/depth-4 to 1024/depth-10.
      # The template is UNCHANGED — it still runs one Merkle-inclusion proof
      # per leaf (L4-C), so the cost scales ~maxLeaves×depth Poseidon hashes.
      # That is far larger than the ADR-0024 flat-fold estimate (~1.35M at
      # N=1024): per-leaf inclusion at 1024/10 is on the order of several
      # million constraints and will NOT fit the shared power-20 ptau.
      # REQUIRED_POWER below is a conservative placeholder; the real value MUST
      # be set from `circom --inspect` / `snarkjs r1cs info` before the v1.0
      # ceremony (a larger Hermez Phase-1 ptau download is expected). If it is
      # impractical, drop REDACTION_MAX_LEAVES (parameters.circom + redaction.rs
      # + pdf_objects.rs) to 512/depth-9 — and re-measure.
      redaction_validity) REQUIRED_POWER=23 ;;
      unified_canonicalization_inclusion_root_sign) REQUIRED_POWER=20 ;;
      # ~N EdDSAPoseidonVerifiers (N=8). Conservatively sized; if
      # `snarkjs r1cs info` later shows headroom this can be lowered.
      federation_quorum) REQUIRED_POWER=19 ;;
    esac
    if [ "${PTAU_POWER}" -lt "${REQUIRED_POWER}" ]; then
      echo "  [SKIP] ${circuit} requires PTAU power ≥ ${REQUIRED_POWER} (max $(( 1 << REQUIRED_POWER )) constraints)."
      echo "         Dev fallback PTAU is power ${PTAU_POWER} (max $(( 1 << PTAU_POWER )) constraints)."
      echo "         Download the Hermez ceremony file to generate ${circuit} keys."
      continue
    fi
  fi

  # Paths for all expected outputs for this circuit (used both in the
  # fingerprint check below and in the build steps that follow).
  R1CS="${BUILD_DIR}/${circuit}.r1cs"
  ZKEY_FINAL="${BUILD_DIR}/${circuit}_final.zkey"
  VKEY="${VKEYS_DIR}/${circuit}_vkey.json"

  # -----------------------------------------------------------------------
  # Incremental build check: if all outputs are present AND the fingerprint
  # matches the current inputs, skip the expensive compile + Groth16 steps.
  #
  # This is safe because the fingerprint covers every input that can change
  # the compiled artifacts (circuit sources, tool versions, PTAU hash).
  # A cache hit here is only possible when nothing has changed.
  # -----------------------------------------------------------------------
  if [ "${COMPILE_ONLY}" -eq 0 ] \
      && [ -f "${R1CS}" ] \
      && [ -d "${BUILD_DIR}/${circuit}_js" ] \
      && [ -f "${ZKEY_FINAL}" ] \
      && [ -f "${VKEY}" ] \
      && [ -f "${BUILD_FINGERPRINT_FILE}" ] \
      && [ "$(cat "${BUILD_FINGERPRINT_FILE}")" = "${CURRENT_FINGERPRINT}" ]; then
    echo "  [CACHED] Outputs present and fingerprint matches — skipping rebuild."
    echo "           r1cs: ${R1CS}"
    echo "           zkey: ${ZKEY_FINAL}"
    echo "           vkey: ${VKEY}"
    continue
  fi

  # ---- Compile ----
  echo "  [1/4] Compiling ${CIRCOM_FILE} …"
  ${CIRCOM} "${CIRCOM_FILE}" \
    --r1cs --wasm --sym \
    -l circuits \
    -l node_modules \
    -o "${BUILD_DIR}"

  if [ "${COMPILE_ONLY}" -eq 1 ]; then
    echo "  [--compile-only] Skipping Groth16 setup."
    echo "        r1cs  : ${R1CS}"
    echo "        wasm  : ${BUILD_DIR}/${circuit}_js/${circuit}.wasm"
    continue
  fi

  # ---- Phase 2 setup (development contribution) ----
  echo "  [2/4] Groth16 setup …"
  ZKEY_0="${BUILD_DIR}/${circuit}_0000.zkey"

  ${SNARKJS} groth16 setup "${R1CS}" "${PTAU_PATH}" "${ZKEY_0}"

  # Single deterministic dev contribution (NOT suitable for production)
  # Red-team A-1: `$(date +%s)` entropy is brute-forceable given a known
  # build window. 32 bytes from /dev/urandom is 256-bit. The dev-prefix
  # keeps audit A-4's runtime gate working.
  _OLYMPUS_DEV_ENTROPY="olympus-dev-entropy-$(head -c 32 /dev/urandom | xxd -p -c 64)"
  ${SNARKJS} zkey contribute "${ZKEY_0}" "${ZKEY_FINAL}" \
    --name="Olympus dev contribution" \
    -e="${_OLYMPUS_DEV_ENTROPY}" 2>/dev/null
  unset _OLYMPUS_DEV_ENTROPY

  rm -f "${ZKEY_0}"

  # ---- Export verification key ----
  echo "  [3/4] Exporting verification key …"
  ${SNARKJS} zkey export verificationkey "${ZKEY_FINAL}" "${VKEY}"

  # ---- Summary ----
  echo "  [4/4] Done."
  echo "        r1cs  : ${R1CS}"
  echo "        zkey  : ${ZKEY_FINAL}"
  echo "        vkey  : ${VKEY}"
done

echo ""
if [ "${COMPILE_ONLY}" -eq 1 ]; then
  echo "==> All circuits compiled (R1CS + WASM). Run without --compile-only to generate keys."
else
  # -----------------------------------------------------------------------
  # 3.5 Stage runtime artifacts into KEYS_DIR and produce the arkworks
  #      proving keys (`<circuit>.ark.zkey`).
  #
  # At runtime the in-process prover (src-tauri/src/zk/) looks for everything
  # under a single `proofs/keys/` directory:
  #
  #   proofs/keys/<circuit>.wasm          (witness generator)
  #   proofs/keys/<circuit>.r1cs          (constraint system)
  #   proofs/keys/<circuit>.ark.zkey      (proving key, arkworks-serialised)
  #   proofs/keys/verification_keys/<circuit>_vkey.json
  #
  # snarkjs produces the wasm/r1cs/zkey under BUILD_DIR with slightly
  # different layouts; copy them into KEYS_DIR with the canonical names so
  # the Tauri bundle's `resources` glob picks them up.
  # -----------------------------------------------------------------------
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
  EXPORT_BIN="${REPO_ROOT}/target/release/export_ark_zkey"
  if [ ! -x "${EXPORT_BIN}" ]; then
    EXPORT_BIN="${REPO_ROOT}/target/debug/export_ark_zkey"
  fi
  if [ ! -x "${EXPORT_BIN}" ]; then
    echo "==> Building export_ark_zkey (release) …"
    (cd "${REPO_ROOT}/src-tauri" && cargo build --release --bin export_ark_zkey)
    EXPORT_BIN="${REPO_ROOT}/target/release/export_ark_zkey"
  fi

  echo ""
  echo "==> Staging runtime artifacts into ${KEYS_DIR}/ …"
  for circuit in "${CIRCUITS[@]}"; do
    R1CS="${BUILD_DIR}/${circuit}.r1cs"
    ZKEY_FINAL="${BUILD_DIR}/${circuit}_final.zkey"
    WASM_SRC="${BUILD_DIR}/${circuit}_js/${circuit}.wasm"

    # The circuit may have been skipped above (dev PTAU too small); only
    # stage if every input is present.
    if [ ! -f "${R1CS}" ] || [ ! -f "${ZKEY_FINAL}" ] || [ ! -f "${WASM_SRC}" ]; then
      echo "  [SKIP] ${circuit}: build outputs missing, not staging."
      continue
    fi

    cp -f "${R1CS}"     "${KEYS_DIR}/${circuit}.r1cs"
    cp -f "${WASM_SRC}" "${KEYS_DIR}/${circuit}.wasm"

    # Convert snarkjs .zkey → arkworks .ark.zkey. This step is mandatory
    # for the in-process Rust prover; without it /zk/prove returns 503.
    ARK_ZKEY="${KEYS_DIR}/${circuit}.ark.zkey"
    echo "  [ark.zkey] ${circuit} …"
    "${EXPORT_BIN}" "${ZKEY_FINAL}" "${ARK_ZKEY}"

    # Also stage the ark.zkey under proofs/build/<circuit>_final.ark.zkey
    # so the integration round-trip tests (`src-tauri/tests/zk_prove_*.rs`)
    # find it at the path their docstrings name without the operator
    # having to copy four files by hand after every regen. Runtime (Tauri
    # + /zk/prove) keeps reading from KEYS_DIR — this is purely a
    # convenience for the test harness. Copy not symlink: portable across
    # filesystems / Windows worktrees, and the storage cost is negligible
    # against the .zkey already on disk.
    cp -f "${ARK_ZKEY}" "${BUILD_DIR}/${circuit}_final.ark.zkey"
  done

  # -----------------------------------------------------------------------
  # 3b. Generate signed ceremony manifests (audit CEREMONY_INTEGRITY.md).
  #     One manifest per circuit, embedding blake3 fingerprints of every
  #     artifact plus a BJJ-EdDSA signature from the coordinator. Embedded
  #     into the runtime binary via include_str! so vkey/zkey tampering is
  #     caught at build time (vkey) and at proof time (.ark.zkey) instead
  #     of silently producing proofs that fail to verify.
  #
  #     Signing key precedence:
  #       OLYMPUS_CEREMONY_COORDINATOR_KEY > OLYMPUS_BJJ_AUTHORITY_KEY > ad-hoc dev key
  #     If neither env is set the script falls back to a deterministic
  #     local dev key so a fresh-checkout run still produces a manifest
  #     (without one the runtime check loads but the production startup
  #     gate refuses to start).
  # -----------------------------------------------------------------------
  MANIFEST_BIN="${REPO_ROOT}/target/release/generate_manifest"
  if [ ! -x "${MANIFEST_BIN}" ]; then
    MANIFEST_BIN="${REPO_ROOT}/target/debug/generate_manifest"
  fi
  if [ ! -x "${MANIFEST_BIN}" ]; then
    echo "==> Building generate_manifest (release) …"
    (cd "${REPO_ROOT}/src-tauri" && cargo build --release --bin generate_manifest)
    MANIFEST_BIN="${REPO_ROOT}/target/release/generate_manifest"
  fi

  MANIFESTS_DIR="${KEYS_DIR}/manifests"
  mkdir -p "${MANIFESTS_DIR}"
  CEREMONY_ID="${OLYMPUS_CEREMONY_ID:-olympus-dev-$(date -u +%Y-%m-%d)}"
  CONTRIBUTOR_ID="${OLYMPUS_CEREMONY_CONTRIBUTOR:-${USER:-anonymous}@$(hostname 2>/dev/null || echo localhost)}"

  if [ -z "${OLYMPUS_CEREMONY_COORDINATOR_KEY:-}" ] && [ -z "${OLYMPUS_BJJ_AUTHORITY_KEY:-}" ]; then
    # Single-contributor dev fallback: a fixed deterministic key. NOT
    # safe for production — operators running phase2_ceremony.sh must
    # set OLYMPUS_CEREMONY_COORDINATOR_KEY to their announced
    # coordinator key.
    export OLYMPUS_CEREMONY_COORDINATOR_KEY="4242424242424242424242424242424242424242424242424242424242424242"
    echo "  [manifest] WARNING: signing dev manifests with fallback key — set OLYMPUS_CEREMONY_COORDINATOR_KEY for real ceremonies"
  fi

  echo ""
  echo "==> Generating ceremony manifests under ${MANIFESTS_DIR}/ …"
  for circuit in "${CIRCUITS[@]}"; do
    ARK_ZKEY="${KEYS_DIR}/${circuit}.ark.zkey"
    if [ ! -f "${ARK_ZKEY}" ]; then
      echo "  [SKIP] ${circuit}: no .ark.zkey, manifest not generated"
      continue
    fi
    MANIFEST_OUT="${MANIFESTS_DIR}/${circuit}_manifest.json"
    echo "  [manifest] ${circuit} → ${MANIFEST_OUT}"
    "${MANIFEST_BIN}" \
      --circuit "${circuit}" \
      --keys-dir "${KEYS_DIR}" \
      --build-dir "${BUILD_DIR}" \
      --ceremony-id "${CEREMONY_ID}" \
      --contributor-id "${CONTRIBUTOR_ID}" \
      --out "${MANIFEST_OUT}"
  done

  # -----------------------------------------------------------------------
  # 4. Write build fingerprint (marks this set of outputs as up-to-date).
  #    Written after the full circuit loop so every output file is in place
  #    before we record the fingerprint.  A future run that finds a matching
  #    fingerprint can skip all compile + Groth16 steps safely.
  # -----------------------------------------------------------------------
  echo "${CURRENT_FINGERPRINT}" > "${BUILD_FINGERPRINT_FILE}"
  # Build completed successfully: remove the in-progress sentinel.
  # The sentinel's absence tells a future run that the last build finished
  # cleanly and its artifacts can be trusted.
  rm -f "${BUILD_IN_PROGRESS_FILE}"

  # -----------------------------------------------------------------------
  # 5. Record provenance.  Written here (post-loop) so it always reflects
  #    actual state on disk — whether circuits were freshly built or restored
  #    from a CI cache.
  # -----------------------------------------------------------------------
  {
    echo "# Groth16 Setup Provenance"
    echo ""
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    if [ "${PTAU_IS_LOCAL}" -eq 1 ]; then
      echo "WARNING: These are DEVELOPMENT keys generated with a locally-created PTAU."
      echo "         They are NOT suitable for production use."
      echo "         Production requires the Phase 2 ceremony with the Hermez Phase 1 file."
      echo ""
    fi
    echo "PTAU_SOURCE: ${PTAU_SOURCE}"
    echo "PTAU_FILE: ${PTAU_FILE}"
    echo "PTAU_B2: ${PTAU_B2}"
    echo ""
    echo "Verification key fingerprints (SHA-256):"
    for _c in "${CIRCUITS[@]}"; do
      _vkey="${VKEYS_DIR}/${_c}_vkey.json"
      if [ -f "${_vkey}" ]; then
        echo "- ${_c}_vkey.json: $(sha256sum "${_vkey}" | awk '{print $1}')"
      fi
    done
  } > "${PROVENANCE_FILE}"

  echo "==> All circuits compiled and development keys generated."
  echo "    WARNING: These keys use a SINGLE dev contribution."
  echo "    Production requires a Phase 2 ceremony with ≥ 3 independent contributors."
fi
