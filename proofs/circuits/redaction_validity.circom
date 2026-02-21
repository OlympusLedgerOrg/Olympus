pragma circom 2.0.0;

/*
 * Redaction validity proof (Poseidon-based).
 *
 * Demonstrates that a revealed subset of leaves belongs to an original Merkle
 * root and that the redacted commitment is derived only from the revealed
 * leaves (no additions).
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";

template RedactionValidity(maxLeaves, depth) {
    // Public inputs
    signal input originalRoot;
    signal input redactedCommitment;
    signal input revealedCount;

    // Private inputs
    signal input originalLeaves[maxLeaves];
    signal input revealMask[maxLeaves]; // 1 = revealed, 0 = redacted
    signal input pathElements[maxLeaves][depth];
    signal input pathIndices[maxLeaves][depth];

    // Verify each revealed leaf is in the original tree
    component inclusionProofs[maxLeaves];
    signal revealedLeaves[maxLeaves];
    for (var i = 0; i < maxLeaves; i++) {
        inclusionProofs[i] = MerkleProof(depth);
        inclusionProofs[i].leaf <== originalLeaves[i];
        for (var j = 0; j < depth; j++) {
            inclusionProofs[i].pathElements[j] <== pathElements[i][j];
            inclusionProofs[i].pathIndices[j] <== pathIndices[i][j];
        }

        // Only constrain the root when revealMask is 1 (conditional constraint):
        // if revealMask[i] == 0 the product is 0 and the constraint is vacuous;
        // if revealMask[i] == 1 it enforces originalRoot == inclusionProofs[i].root.
        revealMask[i] * (originalRoot - inclusionProofs[i].root) === 0;

        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
    }

    // Aggregate revealed leaves into a Poseidon commitment
    signal acc[maxLeaves];
    component initHash = Poseidon(2);
    initHash.inputs[0] <== revealedCount;
    initHash.inputs[1] <== revealedLeaves[0];
    acc[0] <== initHash.out;

    component hashers[maxLeaves - 1];
    for (var k = 1; k < maxLeaves; k++) {
        hashers[k - 1] = Poseidon(2);
        hashers[k - 1].inputs[0] <== acc[k - 1];
        hashers[k - 1].inputs[1] <== revealedLeaves[k];
        acc[k] <== hashers[k - 1].out;
    }

    redactedCommitment === acc[maxLeaves - 1];
}

// Default parameters: 16 leaves, depth 4
component main {public [originalRoot, redactedCommitment, revealedCount]} = RedactionValidity(16, 4);
