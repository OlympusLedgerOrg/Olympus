pragma circom 2.0.0;

/*
 * Indexed non-existence proof (empty-leaf at a specific public index).
 *
 * Proves that the leaf at leafIndex is 0 in the Poseidon Merkle tree with root.
 * This is NOT a full sparse-merkle keyed non-membership proof, but it is a
 * coherent “absence at index” statement for indexed document trees.
 */

include "./lib/merkleProof.circom";

template NonExistence(depth) {
    // Public inputs
    signal input root;
    signal input leafIndex;

    // Private inputs
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Enforce pathIndices encode the provided leafIndex (LSB-first)
    signal indexAccum[depth + 1];
    indexAccum[0] <== 0;
    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
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

component main {public [root, leafIndex]} = NonExistence(20);
