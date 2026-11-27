# Ligetron BLAKE3 path benchmark

A depth-50 hardware run used the native Windows Ligetron prover with
Intel Arc 140V and Vulkan, at packing 4096. Times are single
wall-clock samples including process startup.

| Proof | Compressed bytes | Prove | Verify |
| --- | ---: | ---: | ---: |
| Exact membership | 6,780,487 | 20.476 s | 9.684 s |
| Exact absence, neighboring leaf | 6,457,739 | 17.163 s | 9.155 s |
| Exact absence, empty branch | 6,564,619 | 18.568 s | 2.794 s |

All three proofs verified with private inputs zeroed at the verifier.
Changing the public query key caused the membership proof to fail
verification.

The fixture generator builds synthetic long-prefix keys with Olympus's
Rust item tree and checks each answer with the Rust verifier. The guest
folds 46 sparse levels and four top-tree levels, including the partition
binding. Membership uses the pinned `bytes/raw` v1 profile and opens the
private item commitment. Absence checks one path. A neighboring key and
commitment stay private. The path depth and terminal case are public.
The caller authenticates the item root and profile outside this guest.
The fixture does not load a production dataset.

## Reproduce on Windows

The build uses the Ligetron 1.7.0 C++ guest library, Emscripten in WSL,
and the C sources from BLAKE3 1.8.7. The runner uses the native Windows
Ligetron prover and verifier executables and their shader directory.
It requires a hardware Vulkan adapter.

From the repository root, generate fixtures to a directory accessible
to both Windows and WSL. Use the same directory in the build and run
commands below, with each shell's path syntax.

```powershell
cargo run --locked -p olympus-manifest --example ligetron_blake3_fixtures -- C:/temp/olympus-ligetron-bench
```

```bash
# In WSL, from the repository root.
export LIGETRON_CPP_SDK=/path/to/ligetron/sdk/cpp
export BLAKE3_C_SRC=/path/to/blake3-1.8.7/c
bash tools/ligetron-bench/build.sh /mnt/c/temp/olympus-ligetron-bench
```

```powershell
$env:LIGETRON_BUILD = 'C:/path/to/native-ligetron-build'
node tools/ligetron-bench/run.mjs C:/temp/olympus-ligetron-bench membership-50 absence-neighbor-50 absence-empty-50
```

Each run creates a fresh directory with the compressed proofs, prover and
verifier logs, and `results.json`.
