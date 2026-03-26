pragma circom 2.0.0;

include "./poseidon.circom";

// Domain tag must match POSEIDON_DOMAIN_NODE in protocol/poseidon_smt.py
// Domain-separated node hash: Poseidon(Poseidon(DOMAIN_NODE, left), right)
template DomainPoseidonNode() {
    signal input left;
    signal input right;
    signal output out;

    component innerHash = Poseidon(2);
    innerHash.inputs[0] <== 1;  // POSEIDON_DOMAIN_NODE = 1
    innerHash.inputs[1] <== left;

    component outerHash = Poseidon(2);
    outerHash.inputs[0] <== innerHash.out;
    outerHash.inputs[1] <== right;

    out <== outerHash.out;
}

// Poseidon-based Merkle proof for a fixed depth binary tree.
// Uses domain-separated node hashing to prevent second-preimage attacks.
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

        hashers[i] = DomainPoseidonNode();

        // OPTIMIZATION: Single-multiplication routing (Switcher logic)
        diff[i] <== pathElements[i] - levelHashes[i];
        mux[i] <== pathIndices[i] * diff[i];

        hashers[i].left <== levelHashes[i] + mux[i];
        hashers[i].right <== pathElements[i] - mux[i];

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
