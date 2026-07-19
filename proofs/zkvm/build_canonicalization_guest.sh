#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GUEST_MANIFEST="${SCRIPT_DIR}/canonicalization/guest/Cargo.toml"
# cargo-risczero 3.0.5 appends `.bin` after combining the user ELF with the
# pinned zkVM kernel. Its printed ImageID is computed from these combined bytes,
# so the host must embed this file rather than the intermediate user ELF.
GUEST_BIN="${SCRIPT_DIR}/canonicalization/guest/target/riscv32im-risc0-zkvm-elf/docker/olympus-canonicalization-guest.bin"
OUT_ELF="${SCRIPT_DIR}/canonicalization/olympus_canonicalization_guest.elf"
OUT_IMAGE_ID="${SCRIPT_DIR}/canonicalization/olympus_canonicalization_guest.id"
PINNED_DOCKER_TAG="r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3"

# risc0-build 3.0.5 otherwise resolves the mutable r0.1.88.0 tag. Pin the
# application-program compiler image by registry digest and reject ambient
# attempts to select a different image.
if [[ -n "${RISC0_DOCKER_CONTAINER_TAG:-}" && "${RISC0_DOCKER_CONTAINER_TAG}" != "${PINNED_DOCKER_TAG}" ]]; then
  echo "RISC0_DOCKER_CONTAINER_TAG must equal the Olympus release pin" >&2
  exit 1
fi
export RISC0_DOCKER_CONTAINER_TAG="${PINNED_DOCKER_TAG}"

# Refuse dependency resolution drift inside the builder. risc0-build forwards
# this flag as Cargo's `--locked`, so the image is built from the reviewed guest
# lockfile as well as the digest-pinned compiler container.
export RISC0_BUILD_LOCKED=1

# cargo-risczero uses the current directory as its Docker context. The repo
# root is required so the guest's path dependency on crates/olympus-crypto is
# present in that context even when this script is invoked from elsewhere.
cd "${ROOT_DIR}"

if ! command -v cargo-risczero >/dev/null 2>&1 && ! cargo risczero --version >/dev/null 2>&1; then
  echo "cargo-risczero 3.0.5 is required (install with pinned rzup tooling)" >&2
  exit 1
fi

VERSION="$(cargo risczero --version)"
if [[ "${VERSION}" != "cargo-risczero 3.0.5" ]]; then
  echo "cargo-risczero 3.0.5 required, found: ${VERSION}" >&2
  exit 1
fi

BUILD_OUTPUT="$(cargo risczero build --manifest-path "${GUEST_MANIFEST}")"
printf '%s\n' "${BUILD_OUTPUT}"
if [[ ! -f "${GUEST_BIN}" ]]; then
  echo "expected guest ELF not found at ${GUEST_BIN}" >&2
  exit 1
fi

cp "${GUEST_BIN}" "${OUT_ELF}"
mapfile -t IMAGE_IDS < <(printf '%s\n' "${BUILD_OUTPUT}" | awk '/^ImageID: / { print $2 }')
if [[ "${#IMAGE_IDS[@]}" -ne 1 || ! "${IMAGE_IDS[0]}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected exactly one canonical 64-hex ImageID in cargo-risczero output" >&2
  exit 1
fi
printf '%s\n' "${IMAGE_IDS[0]}" > "${OUT_IMAGE_ID}"
echo "staged ${OUT_ELF}"
echo "staged ${OUT_IMAGE_ID}"

# The host computes and pins the image ID from these exact bytes. Printing the
# BLAKE3 digest makes build logs and artifact reviews reproducible.
if command -v b3sum >/dev/null 2>&1; then
  b3sum "${OUT_ELF}"
fi
