pragma circom 2.0.0;

include "./poseidon.circom";

// Poseidon-based Merkle proof for a fixed depth binary tree.
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth]; // 0 = current node is left, 1 = right
    signal output root;

    signal levelHashes[depth + 1];
    signal diff[depth];
    signal mux[depth];
    component hashers[depth];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices must be boolean
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        hashers[i] = Poseidon(2);

        // OPTIMIZATION: Single-multiplication routing (Switcher logic)
        diff[i] <== pathElements[i] - levelHashes[i];
        mux[i] <== pathIndices[i] * diff[i];

        hashers[i].inputs[0] <== levelHashes[i] + mux[i];
        hashers[i].inputs[1] <== pathElements[i] - mux[i];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

/*
 * Merkle Tree Inclusion Proof Circuit
 *
 * This circuit proves that a leaf is included in a Merkle tree
 * without revealing the leaf's position or sibling values.
 */
template MerkleTreeInclusionProof(levels) {
    // Public inputs
    signal input root;

    // Private inputs
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Intermediate signals
    signal levelHashes[levels + 1];
    signal diff[levels];
    signal mux[levels];

    // Base case: start with leaf
    levelHashes[0] <== leaf;

    // Hash up the tree
    component hashers[levels];
    for (var i = 0; i < levels; i++) {
        // Defense in depth: Force path index to be strictly 0 or 1
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        hashers[i] = Poseidon(2);

        // OPTIMIZATION: Single-multiplication routing (Switcher logic)
        // If pathIndex is 0: inputs are (levelHashes, pathElements)
        // If pathIndex is 1: inputs are (pathElements, levelHashes)
        diff[i] <== pathElements[i] - levelHashes[i];
        mux[i] <== pathIndices[i] * diff[i];

        hashers[i].inputs[0] <== levelHashes[i] + mux[i];
        hashers[i].inputs[1] <== pathElements[i] - mux[i];

        levelHashes[i + 1] <== hashers[i].out;
    }

    // Constrain the computed root to match the public root
    root === levelHashes[levels];
}
