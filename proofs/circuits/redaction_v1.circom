pragma circom 2.0.0;

/*
 * Redaction Proof Circuit (Version 1)
 *
 * This circuit proves that a redacted document is a valid subset
 * of an original committed document without revealing what was redacted.
 *
 * It proves:
 * 1. The revealed leaves are valid members of the original Merkle tree
 * 2. The revealed leaves are at the claimed positions
 * 3. The original root matches the public commitment
 */

include "../node_modules/circomlib/circuits/poseidon.circom";

template RedactionProofV1(maxLeaves, treeDepth) {
    // Public inputs
    signal input originalRoot;
    signal input revealedRoot;  // Root of tree containing only revealed leaves
    
    // Private inputs
    signal input originalLeaves[maxLeaves];
    signal input revealMask[maxLeaves];  // 1 if revealed, 0 if redacted
    signal input pathElements[maxLeaves][treeDepth];
    signal input pathIndices[maxLeaves][treeDepth];
    
    // Verify each revealed leaf is in the original tree
    component inclusionProofs[maxLeaves];
    component revealedHashers[maxLeaves];
    
    signal revealedLeaves[maxLeaves];
    
    for (var i = 0; i < maxLeaves; i++) {
        // If mask is 1, include in revealed tree
        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
        
        // Verify inclusion in original tree for revealed leaves
        inclusionProofs[i] = MerkleTreeInclusionProof(treeDepth);
        inclusionProofs[i].root <== originalRoot;
        inclusionProofs[i].leaf <== originalLeaves[i];
        
        for (var j = 0; j < treeDepth; j++) {
            inclusionProofs[i].pathElements[j] <== pathElements[i][j];
            inclusionProofs[i].pathIndices[j] <== pathIndices[i][j];
        }
    }
    
    // Build revealed tree root
    component revealedTreeBuilder = MerkleTreeBuilder(maxLeaves);
    for (var i = 0; i < maxLeaves; i++) {
        revealedTreeBuilder.leaves[i] <== revealedLeaves[i];
    }
    
    // Constrain revealed root
    revealedRoot === revealedTreeBuilder.root;
}

template MerkleTreeInclusionProof(levels) {
    signal input root;
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;
    
    component hashers[levels];
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== (1 - pathIndices[i]) * levelHashes[i] + pathIndices[i] * pathElements[i];
        hashers[i].inputs[1] <== pathIndices[i] * levelHashes[i] + (1 - pathIndices[i]) * pathElements[i];
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    root === levelHashes[levels];
}

template MerkleTreeBuilder(numLeaves) {
    signal input leaves[numLeaves];
    signal output root;
    
    // NOTE: This is a simplified reference implementation for demonstration.
    // Production version should build a proper Merkle tree structure
    // matching the Python implementation's bottom-up construction.
    component hasher = Poseidon(numLeaves);
    for (var i = 0; i < numLeaves; i++) {
        hasher.inputs[i] <== leaves[i];
    }
    root <== hasher.out;
}

component main {public [originalRoot, revealedRoot]} = RedactionProofV1(16, 4);
