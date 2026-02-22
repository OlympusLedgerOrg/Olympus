pragma circom 2.0.0;

/*
 * Document existence proof.
 *
 * Verifies a Poseidon Merkle path from a leaf to a public root. The leaf index
 * is exposed as a public input to anchor ledger position without revealing the
 * leaf value.
 */

include "./lib/merkleProof.circom";

template DocumentExistence(depth) {
    // Public inputs
    signal input root;
    signal input leafIndex;

    // Private inputs
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Ensure pathIndices encode the provided leafIndex
    signal indexAccum[depth + 1];
    indexAccum[0] <== 0;
    // OPTIMIZATION: Use a compile-time 'var' instead of an array of 'signal's
    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        // Boolean constraint for path index
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        indexAccum[i + 1] <== indexAccum[i] + pathIndices[i] * pow2;
        pow2 = pow2 * 2;
    }
    leafIndex === indexAccum[depth];

    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== leaf;
    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j] <== pathIndices[j];
    }

}

// Default depth 20 (sparse tree friendly)
component main {public [root, leafIndex]} = DocumentExistence(20);
