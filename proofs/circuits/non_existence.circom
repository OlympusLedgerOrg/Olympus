pragma circom 2.0.0;

/*
 * Sparse Merkle Tree keyed non-membership proof.
 *
 * Statement proved:
 *   Given a public Poseidon SMT root `root` and a public `keyHash`, the
 *   prover knows a 32-byte `key` and a 256-level Merkle authentication
 *   path such that:
 *     1. The path indices are the MSB-first bit decomposition of key
 *        (matching protocol/ssmf.py::_key_to_path_bits exactly).
 *     2. The leaf at that path is the empty sentinel value 0.
 *     3. `keyHash == Poseidon(key_lo, key_hi)` where `key_lo`/`key_hi` are
 *        the two halves of `key` packed as field elements.
 *
 * Why `keyHash` is public (audit M-1):
 *   Without exposing any commitment to `key`, a third-party verifier
 *   learns only "the prover knows *some* 32-byte value whose slot is
 *   empty," which is true for ≈ all 32-byte values in a 2^256-leaf tree
 *   with ≤ 2^64 actual leaves. Exposing `keyHash` lets a relying party
 *   bind the proof to a key they care about: they compute
 *   `Poseidon(pack(key))` for their candidate key and reject the proof
 *   unless it matches. The key itself stays private (preimage-resistant
 *   under Poseidon).
 *
 * Public inputs:  root, keyHash
 * Private inputs: key[32], pathElements[256]
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template NonExistence(depth) {
    // ---- Public inputs ----
    signal input root;
    signal input keyHash;                // Audit M-1: Poseidon(key_lo, key_hi)

    // ---- Private inputs (L4-B: key is now private) ----
    signal input key[32];                // 32-byte key as field elements, each in [0, 255]
    signal input pathElements[depth];    // depth = 256 for sparse Merkle tree

    // ---- Internal signals ----
    signal pathIndices[depth];           // derived from key, not supplied by prover

    // --- Step 1: Constrain each key byte to [0, 255] ---
    // Num2Bits with n=8 enforces the range implicitly: if the value were
    // >= 256, the bit decomposition would require a 9th bit which doesn't
    // exist in the 8-bit output, and the reconstruction constraint would fail.
    component keyByteBits[32];
    for (var b = 0; b < 32; b++) {
        keyByteBits[b] = Num2Bits(8);
        keyByteBits[b].in <== key[b];
    }

    // --- Step 2: Derive pathIndices from key bytes ---
    // The Merkle proof template traverses from leaf (level 0) to root
    // (level depth-1), so pathIndices[0] must be the bit used at the leaf
    // level.  The Python SMT uses bit_pos = 255 - level, meaning the leaf
    // level uses the LAST bit of the key (bit 255) and the root level uses
    // the FIRST bit (bit 0).
    //
    // _key_to_path_bits produces MSB-first ordering: index k = byte k/8,
    // bit 7 - (k % 8).  To align with the bottom-up Merkle walk we reverse
    // the mapping: pathIndices[j] = key-bit (255 - j).
    for (var b = 0; b < 32; b++) {
        for (var i = 0; i < 8; i++) {
            // key-bit index k = b*8 + i  (MSB-first within each byte)
            // Merkle level that uses this bit = 255 - k  (leaf is level 0)
            pathIndices[255 - (b * 8 + i)] <== keyByteBits[b].out[7 - i];
        }
    }

    // --- Step 2b: Bind public keyHash to the private key ---
    // Audit M-1: pack 32 bytes into two 16-byte (128-bit) field elements
    // and Poseidon-hash them as a public commitment. Both halves comfortably
    // fit in BN254's ~254-bit Fr without modular reduction. The split is
    // domain-free because (key_lo, key_hi) ∈ [0, 2^128) × [0, 2^128) is
    // already an injective encoding of the 32-byte key — Poseidon over the
    // 2-tuple is what the off-circuit verifier reconstructs.
    signal keyLo;
    signal keyHi;
    var sumLo = 0;
    var sumHi = 0;
    var weight = 1;
    for (var k = 0; k < 16; k++) {
        sumLo += key[k] * weight;
        weight = weight * 256;
    }
    weight = 1;
    for (var k = 16; k < 32; k++) {
        sumHi += key[k] * weight;
        weight = weight * 256;
    }
    keyLo <== sumLo;
    keyHi <== sumHi;

    component keyHasher = Poseidon(2);
    keyHasher.inputs[0] <== keyLo;
    keyHasher.inputs[1] <== keyHi;
    keyHash === keyHasher.out;

    // --- Step 3: Prove that the empty leaf (sentinel = 0) exists at this path ---
    // (leafIndexAccum removed — at depth=256 it overflows BN128 and was
    //  never read.  pathIndices are already constrained to {0,1} by Step 1
    //  Num2Bits and bound to the key derivation in Step 2.)
    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== 0;   // empty sentinel: the leaf is zero iff the key was never stored
    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j]  <== pathIndices[j];
    }
}

component main { public [root, keyHash] } = NonExistence(NON_EXISTENCE_MERKLE_DEPTH());
