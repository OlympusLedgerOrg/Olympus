pragma circom 2.0.0;

/*
 * Merkle Tree Inclusion Proof Circuit
 *
 * This circuit proves that a leaf is included in a Merkle tree
 * without revealing the leaf's position or sibling values.
 */

include "../node_modules/circomlib/circuits/poseidon.circom";

template MerkleTreeInclusionProof(levels) {
    // Public inputs
    signal input root;
    
    // Private inputs
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Intermediate signals
    signal levelHashes[levels + 1];
    
    // Base case: start with leaf
    levelHashes[0] <== leaf;
    
    // Hash up the tree
    component hashers[levels];
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // If pathIndex is 0, leaf is on left
        // If pathIndex is 1, leaf is on right
        hashers[i].inputs[0] <== (1 - pathIndices[i]) * levelHashes[i] + pathIndices[i] * pathElements[i];
        hashers[i].inputs[1] <== pathIndices[i] * levelHashes[i] + (1 - pathIndices[i]) * pathElements[i];
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    // Constrain the computed root to match the public root
    root === levelHashes[levels];
}

component main {public [root]} = MerkleTreeInclusionProof(20);
