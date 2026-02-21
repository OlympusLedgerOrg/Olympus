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
        inclusionProofs[i].pathElements <== pathElements[i];
        inclusionProofs[i].pathIndices <== pathIndices[i];

        // Only constrain the root when revealMask is 1
        revealMask[i] * (originalRoot - inclusionProofs[i].root) === 0;

        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
    }

    // Aggregate revealed leaves into a Poseidon commitment
    component aggregator = Poseidon(maxLeaves + 1);
    aggregator.inputs[0] <== revealedCount;
    for (var j = 0; j < maxLeaves; j++) {
        aggregator.inputs[j + 1] <== revealedLeaves[j];
    }

    redactedCommitment === aggregator.out;
}

// Default parameters: 16 leaves, depth 4
component main {public [originalRoot, redactedCommitment, revealedCount]} = RedactionValidity(16, 4);
