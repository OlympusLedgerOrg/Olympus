pragma circom 2.0.0;

/*
 * Redaction validity proof (Poseidon-based).
 *
 * Proves:
 *   1) For each i where revealMask[i] == 1, the leaf at *position i* is included
 *      in the original Merkle tree with root originalRoot.
 *   2) revealedCount equals the number of revealed leaves (sum of revealMask).
 *   3) redactedCommitment is Poseidon-chained over (revealedCount, revealedLeaves[]),
 *      where revealedLeaves[i] = originalLeaves[i] if revealed, else 0.
 *
 * NOTE: This proves “subset authenticity + position binding + commitment”.
 * It does NOT prove anything about formatting of a redacted document string.
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

    // -------------------------
    // 1) Enforce revealedCount = sum(revealMask)
    // -------------------------
    signal maskSum[maxLeaves + 1];
    maskSum[0] <== 0;

    // -------------------------
    // 2) Verify revealed leaves are included at the correct *index i*
    // -------------------------
    component inclusionProofs[maxLeaves];
    signal revealedLeaves[maxLeaves];

    for (var i = 0; i < maxLeaves; i++) {
        // Force revealMask to be strictly binary (0 or 1)
        revealMask[i] * (revealMask[i] - 1) === 0;

        // Accumulate sum of mask bits
        maskSum[i + 1] <== maskSum[i] + revealMask[i];

        // Bind pathIndices to index i (LSB-first), so this proof is about position i.
        // Since maxLeaves = 2^depth, i fits in 'depth' bits.
        // The bit-weight accumulator is compile-time: weights[b] = 2^b.
        signal idxAccum[depth + 1];
        idxAccum[0] <== 0;
        for (var b = 0; b < depth; b++) {
            var bitWeight = 1 << b;
            // Path bits are boolean (defense in depth; Merkle gadget also enforces this)
            pathIndices[i][b] * (pathIndices[i][b] - 1) === 0;
            idxAccum[b + 1] <== idxAccum[b] + pathIndices[i][b] * bitWeight;
        }
        idxAccum[depth] === i;

        // Inclusion proof (computed regardless; enforced only when revealed)
        inclusionProofs[i] = MerkleTreeInclusionProof(depth);
        inclusionProofs[i].leaf <== originalLeaves[i];
        for (var j = 0; j < depth; j++) {
            inclusionProofs[i].pathElements[j] <== pathElements[i][j];
            inclusionProofs[i].pathIndices[j] <== pathIndices[i][j];
        }

        // Only constrain root when revealed
        revealMask[i] * (originalRoot - inclusionProofs[i].root) === 0;

        // Masked reveal vector:
        // - revealed leaves keep their original value
        // - unrevealed leaves are forced to 0 and therefore zero-pad the commitment chain
        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
    }

    // Sum constraint
    revealedCount === maskSum[maxLeaves];

    // -------------------------
    // 3) Commit to revealedLeaves + revealedCount.
    // Unrevealed entries contribute zeros because revealedLeaves[i] is masked above.
    // -------------------------
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
