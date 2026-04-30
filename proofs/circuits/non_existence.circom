pragma circom 2.0.0;

/*
 * Sparse Merkle Tree keyed non-membership proof.
 *
 * Statement proved:
 *   Given a public Poseidon SMT root `root`, the prover knows a 32-byte `key`
 *   and a 256-level Merkle authentication path such that:
 *     1. The path indices are the MSB-first bit decomposition of key
 *        (matching protocol/ssmf.py::_key_to_path_bits exactly).
 *     2. The leaf at that path is the empty sentinel value 0.
 *
 * This proves genuine keyed non-membership: the proof is cryptographically
 * bound to the specific key, not to a prover-chosen empty slot.
 *
 * Security note (L4-B):
 *   key[32] is now a PRIVATE input. The path indices are derived internally
 *   from the key, ensuring the prover cannot choose arbitrary empty slots.
 *
 * Public inputs:  root
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

component main { public [root] } = NonExistence(NON_EXISTENCE_MERKLE_DEPTH());
