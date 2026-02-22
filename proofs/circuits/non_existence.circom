pragma circom 2.0.0;

/*
 * Indexed non-existence proof (empty leaf at a specific public index).
 *
 * Statement proved:
 *   Given a public Poseidon Merkle root `root` and a public `leafIndex`,
 *   the prover knows a Merkle authentication path such that the leaf at
 *   that index is the empty value 0.
 *
 * Notes:
 *   - This is an "absence-at-index" proof for an indexed Merkle tree.
 *   - It is NOT a full sparse-merkle keyed non-membership proof.
 *   - Index binding is LSB-first to match typical witness generators:
 *       leafIndex = Σ pathIndices[i] * 2^i
 */

include "./lib/merkleProof.circom";

template NonExistence(depth) {
    // ---- Public inputs ----
    signal input root;
    signal input leafIndex;

    // ---- Private inputs ----
    signal input pathElements[depth];
    signal input pathIndices[depth]; // LSB-first direction bits

    // Enforce pathIndices encode the provided leafIndex (LSB-first)
    signal indexAccum[depth + 1];
    indexAccum[0] <== 0;

    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        // Boolean constraint for path bit
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        indexAccum[i + 1] <== indexAccum[i] + pathIndices[i] * pow2;
        pow2 = pow2 * 2;
    }
    leafIndex === indexAccum[depth];

    // Prove inclusion of the empty leaf (0) at that index
    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== 0;

    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j] <== pathIndices[j];
    }
}

component main { public [root, leafIndex] } = NonExistence(20);
