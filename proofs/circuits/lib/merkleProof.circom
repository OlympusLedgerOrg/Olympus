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

    // Reuse MerkleProof for hashing + path switching constraints.
    component proof = MerkleProof(levels);
    proof.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        proof.pathElements[i] <== pathElements[i];
        proof.pathIndices[i] <== pathIndices[i];
    }

    // Constrain the computed root to match the public root
    root === proof.root;
}
