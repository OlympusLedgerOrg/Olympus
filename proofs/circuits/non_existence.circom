pragma circom 2.0.0;

/*
 * Sparse Merkle Tree keyed non-membership proof.
 *
 * Statement proved:
 *   Given a public Poseidon SMT root `root` and a public 32-byte `key`,
 *   the prover knows a 256-level Merkle authentication path such that:
 *     1. The path indices are the MSB-first bit decomposition of key
 *        (matching protocol/ssmf.py::_key_to_path_bits exactly).
 *     2. The leaf at that path is the empty sentinel value 0.
 *
 * This proves genuine keyed non-membership: the proof is cryptographically
 * bound to the specific key, not to a prover-chosen empty slot.
 *
 * Public inputs:  root, key[32]
 * Private inputs: pathElements[256]
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";
include "../../node_modules/circomlib/circuits/iszero.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

template NonExistence(depth) {
    // ---- Public inputs ----
    signal input root;
    signal input key[32];  // 32-byte key as field elements, each in [0, 255]

    // ---- Private inputs ----
    signal input pathElements[depth];   // depth = 256 for sparse Merkle tree

    // ---- Internal signals ----
    signal pathIndices[depth];          // derived from key, not supplied by prover

    // --- Step 1: Constrain each key byte to [0, 255] ---
    // Num2Bits with n=8 enforces the range implicitly: if the value were
    // >= 256, the bit decomposition would require a 9th bit which doesn't
    // exist in the 8-bit output, and the reconstruction constraint would fail.
    component keyByteBits[32];
    for (var b = 0; b < 32; b++) {
        keyByteBits[b] = Num2Bits(8);
        keyByteBits[b].in <== key[b];
    }

    // --- Step 2: Derive pathIndices from key bytes (MSB-first per byte) ---
    // This matches protocol/ssmf.py::_key_to_path_bits exactly:
    //   for byte in key:
    //       for i in range(8):
    //           bit = (byte >> (7 - i)) & 1
    //
    // circomlib Num2Bits outputs bits LSB-first: out[0] is bit 0 (LSB),
    // out[7] is bit 7 (MSB). MSB-first means we take out[7] first, then
    // out[6], ..., out[0].
    for (var b = 0; b < 32; b++) {
        for (var i = 0; i < 8; i++) {
            // Path position: byte b, MSB-first bit i = out[7 - i]
            pathIndices[b * 8 + i] <== keyByteBits[b].out[7 - i];
        }
    }

    // --- Step 3: Prove that the empty leaf (sentinel = 0) exists at this path ---
    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== 0;   // empty sentinel: the leaf is zero iff the key was never stored
    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j]  <== pathIndices[j];
    }
}

component main { public [root, key] } = NonExistence(NON_EXISTENCE_MERKLE_DEPTH);
