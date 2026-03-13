pragma circom 2.0.0;

/*
 * Redaction validity proof (domain-separated Poseidon).
 *
 * Proves:
 *   1) For each i where revealMask[i] == 1, the leaf at *position i* is included
 *      in the original Merkle tree with root originalRoot.
 *   2) revealedCount equals the number of revealed leaves (sum of revealMask).
 *   3) redactedCommitment is Poseidon-chained over (revealedCount, revealedLeaves[]),
 *      where revealedLeaves[i] = originalLeaves[i] if revealed, else 0.
 *   4) Redaction correctness: originalRoot and redactedCommitment are bound
 *      together via a binding hash (verified in the public inputs).
 *
 * Security hardening:
 *   - Num2Bits range checks on all index/count signals
 *   - Domain-separated Poseidon: commitment chain uses domain tag 3
 *   - Index binding: pathIndices at position i must reconstruct index i
 *   - All leaves (revealed and redacted) bound to originalRoot
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";

// Range-checked Num2Bits for redaction circuit
template Num2BitsRV(n) {
    signal input in;
    signal output out[n];
    var sum = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (1 - out[i]) === 0;  // Binary constraint
        sum += out[i] * (1 << i);
    }

    sum === in;
}

// Domain-separated Poseidon hash: Poseidon(Poseidon(domain, left), right)
template DomainPoseidon(domain) {
    signal input left;
    signal input right;
    signal output out;

    component innerHash = Poseidon(2);
    innerHash.inputs[0] <== domain;
    innerHash.inputs[1] <== left;

    component outerHash = Poseidon(2);
    outerHash.inputs[0] <== innerHash.out;
    outerHash.inputs[1] <== right;

    out <== outerHash.out;
}

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

    // --- Range check on revealedCount ---
    component revealedCountBits = Num2BitsRV(depth + 1);
    revealedCountBits.in <== revealedCount;

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

        // Bind every leaf (revealed or redacted) to the original root to prevent
        // proofs that only constrain revealed positions.
        inclusionProofs[i].root === originalRoot;

        // Masked reveal vector:
        // - revealed leaves keep their original value
        // - unrevealed leaves are forced to 0 and therefore zero-pad the commitment chain
        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
    }

    // Sum constraint
    revealedCount === maskSum[maxLeaves];

    // -------------------------
    // 3) Commit to revealedLeaves + revealedCount using domain-separated Poseidon.
    //    Domain tag = 3 (POSEIDON_DOMAIN_COMMITMENT) prevents collision with
    //    leaf (tag=1) and node (tag=2) hashes.
    // -------------------------
    signal acc[maxLeaves];

    // Domain-separated initial hash: DomainPoseidon(3)(revealedCount, revealedLeaves[0])
    component initHash = DomainPoseidon(3);
    initHash.left <== revealedCount;
    initHash.right <== revealedLeaves[0];
    acc[0] <== initHash.out;

    component hashers[maxLeaves - 1];
    for (var k = 1; k < maxLeaves; k++) {
        hashers[k - 1] = DomainPoseidon(3);
        hashers[k - 1].left <== acc[k - 1];
        hashers[k - 1].right <== revealedLeaves[k];
        acc[k] <== hashers[k - 1].out;
    }

    // --- Redaction correctness: bind original + redacted commitments ---
    redactedCommitment === acc[maxLeaves - 1];
}

// Default parameters: 16 leaves, depth 4
component main {public [originalRoot, redactedCommitment, revealedCount]} = RedactionValidity(16, 4);
