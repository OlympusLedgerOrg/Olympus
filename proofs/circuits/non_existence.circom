pragma circom 2.0.0;

/*
 * Sparse Merkle non-existence proof (simplified).
 *
 * Proves that a queried key is absent by showing the path terminates at an
 * empty leaf and that the provided sibling path reconstructs the claimed root.
 */

include "./lib/merkleProof.circom";

template NonExistence(depth) {
    // Public inputs
    signal input root;

    // Private inputs
    signal input emptyLeaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Reuse MerkleProof with an empty leaf
    component merkle = MerkleProof(depth);
    merkle.leaf <== emptyLeaf;
    merkle.pathElements <== pathElements;
    merkle.pathIndices <== pathIndices;

    // Enforce that the leaf is zero to model non-membership
    emptyLeaf === 0;
    root === merkle.root;
}

component main {public [root]} = NonExistence(20);
