#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo 'Usage: bash build.sh OUTPUT_DIR' >&2
    exit 2
fi

sdk=${LIGETRON_CPP_SDK:?Set LIGETRON_CPP_SDK to the built Ligetron sdk/cpp directory}
b3=${BLAKE3_C_SRC:?Set BLAKE3_C_SRC to the BLAKE3 1.8.7 C source directory}
src=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$1" && pwd)

for unit in blake3 blake3_portable blake3_dispatch; do
    emcc -O2 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 \
        -I"$b3" -c "$b3/$unit.c" -o "$out/$unit.o"
done

em++ -O2 -std=c++20 -I"$sdk/include" -I"$b3" -I"$out" "$src/relation.cpp" \
    "$out/blake3.o" "$out/blake3_portable.o" "$out/blake3_dispatch.o" \
    "$sdk/build/libligetron.a" -o "$out/relation.wasm"
