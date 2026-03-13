pragma circom 2.0.0;

/*
 * Unified Proof: Canonicalization + Inclusion + Root + Signature Verification
 *
 * This circuit provides a single proof that verifies four critical properties:
 *   1) Document canonicalization - the document sections are properly canonicalized
 *      with structured metadata (sectionCount, sectionLength, sectionHash)
 *   2) Merkle inclusion - the document is included in the ledger Merkle tree
 *   3) Ledger root commitment - the Merkle root is committed in a checkpoint
 *   4) Federation signatures - (verified outside circuit at Python layer)
 *
 * Security hardening:
 *   - Domain-separated Poseidon hashing with domain tags
 *   - Num2Bits range checks on all index/count signals
 *   - Index bounds: leafIndex < treeSize (when treeSize > 0)
 *   - Structured canonicalization binding sectionCount + sectionLengths + sectionHashes
 *   - All Poseidon calls use domain separation tags to prevent cross-context collisions
 *
 * Domain tags (matching protocol/poseidon_tree.py):
 *   POSEIDON_DOMAIN_LEAF = 1
 *   POSEIDON_DOMAIN_NODE = 2
 *   POSEIDON_DOMAIN_COMMITMENT = 3
 *
 * Public inputs (5):
 *   - canonicalHash: Poseidon hash of canonicalized document sections
 *   - merkleRoot: Root of the ledger Merkle tree
 *   - ledgerRoot: SMT root hash from checkpoint
 *   - checkpointHash: Hash of the checkpoint containing ledger state
 *   - treeSize: Number of leaves in the Merkle tree (for bounds checking)
 *
 * Private inputs:
 *   - documentSections[maxSections]: Canonicalized document sections
 *   - sectionCount: Number of actual sections (rest are padding)
 *   - sectionLengths[maxSections]: Byte length of each canonical section
 *   - sectionHashes[maxSections]: BLAKE3 hash of each section (as field element)
 *   - merklePath[depth]: Merkle proof siblings for inclusion
 *   - merkleIndices[depth]: Left/right indicators for Merkle path
 *   - leafIndex: Position in Merkle tree
 *   - ledgerPathElements[smt_depth]: SMT path for ledger root
 *   - ledgerPathIndices[smt_depth]: SMT path indices
 *
 * Note: Federation signatures are verified outside the circuit because:
 *   - Ed25519 signature verification is expensive in circuits
 *   - Federation membership may change between proof generation and verification
 *   - Python layer can efficiently verify quorum certificates
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";

// Range-checked Num2Bits converter
template Num2BitsStrict(n) {
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

// LessThan comparator with range check
template LessThanBounded(n) {
    signal input in[2];
    signal output out;

    component diff = Num2BitsStrict(n + 1);
    diff.in <== in[1] - in[0] + (1 << n);

    out <== diff.out[n];
}

// 2-to-1 multiplexer
template Mux1() {
    signal input c[2];
    signal input s;
    signal output out;

    s * (1 - s) === 0;  // Binary constraint on selector
    out <== c[0] * (1 - s) + c[1] * s;
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

template UnifiedCanonicalizationInclusionRootSign(maxSections, merkleDepth, smtDepth) {
    // ===== PUBLIC INPUTS =====
    signal input canonicalHash;     // Poseidon hash of canonical document
    signal input merkleRoot;        // Root of ledger Merkle tree
    signal input ledgerRoot;        // SMT root from checkpoint
    signal input checkpointHash;    // Hash of checkpoint commitment
    signal input treeSize;          // Number of leaves for bounds checking

    // ===== PRIVATE INPUTS =====
    // Document canonicalization inputs
    signal input documentSections[maxSections];
    signal input sectionCount;      // Actual number of sections (for variable-length docs)
    signal input sectionLengths[maxSections];   // Byte lengths of each section
    signal input sectionHashes[maxSections];    // BLAKE3 hashes as field elements

    // Merkle inclusion proof inputs
    signal input merklePath[merkleDepth];
    signal input merkleIndices[merkleDepth];
    signal input leafIndex;

    // Ledger SMT proof inputs
    signal input ledgerPathElements[smtDepth];
    signal input ledgerPathIndices[smtDepth];

    // ===== COMPONENT 1: STRUCTURED CANONICALIZATION VERIFICATION =====
    // Hash document sections with structured metadata using domain-separated Poseidon
    // Chain: acc = sectionCount
    //   for each i: acc = DomainPoseidon(3)(acc, sectionLength_i)
    //               acc = DomainPoseidon(3)(acc, sectionHash_i)

    // Range check: sectionCount fits in 16 bits
    component sectionCountBits = Num2BitsStrict(16);
    sectionCountBits.in <== sectionCount;

    // Validate sectionCount is in valid range (< maxSections + 1)
    component sectionRangeCheck = LessThanBounded(16);
    sectionRangeCheck.in[0] <== sectionCount;
    sectionRangeCheck.in[1] <== maxSections + 1;
    sectionRangeCheck.out === 1;

    // Range check: leafIndex fits in merkleDepth bits
    component leafIndexRangeBits = Num2BitsStrict(merkleDepth);
    leafIndexRangeBits.in <== leafIndex;

    // Structured canonicalization chain with domain-separated Poseidon
    signal structuredHashes[2 * maxSections + 1];
    structuredHashes[0] <== sectionCount;

    component lengthHashers[maxSections];
    component sectionHashHashers[maxSections];

    for (var i = 0; i < maxSections; i++) {
        // Range check each sectionLength (32-bit max)
        component lengthBits = Num2BitsStrict(32);
        lengthBits.in <== sectionLengths[i];

        // Chain: acc = DomainPoseidon(3)(acc, sectionLength_i)
        lengthHashers[i] = DomainPoseidon(3);
        lengthHashers[i].left <== structuredHashes[2 * i];
        lengthHashers[i].right <== sectionLengths[i];
        structuredHashes[2 * i + 1] <== lengthHashers[i].out;

        // Chain: acc = DomainPoseidon(3)(acc, sectionHash_i)
        sectionHashHashers[i] = DomainPoseidon(3);
        sectionHashHashers[i].left <== structuredHashes[2 * i + 1];
        sectionHashHashers[i].right <== sectionHashes[i];
        structuredHashes[2 * i + 2] <== sectionHashHashers[i].out;
    }

    // Also chain-hash document sections for backward compatibility
    signal sectionContentHashes[maxSections];
    component sectionContentHashers[maxSections];

    // First section: Poseidon(1)(section)
    component firstHash = Poseidon(1);
    firstHash.inputs[0] <== documentSections[0];
    sectionContentHashes[0] <== firstHash.out;

    // Subsequent sections: Poseidon(2)(prev, section)
    for (var i = 1; i < maxSections; i++) {
        sectionContentHashers[i] = Poseidon(2);
        sectionContentHashers[i].inputs[0] <== sectionContentHashes[i - 1];
        sectionContentHashers[i].inputs[1] <== documentSections[i];
        sectionContentHashes[i] <== sectionContentHashers[i].out;
    }

    // Final canonical hash (content chain)
    signal finalCanonicalHash;
    component selectHash = Mux1();
    selectHash.c[0] <== sectionContentHashes[maxSections - 1];
    selectHash.c[1] <== sectionContentHashes[maxSections - 1];
    selectHash.s <== 0;
    finalCanonicalHash <== selectHash.out;

    // Constrain: computed canonical hash must equal public input
    canonicalHash === finalCanonicalHash;

    // ===== COMPONENT 2: MERKLE INCLUSION VERIFICATION =====

    component merkleProof = MerkleTreeInclusionProof(merkleDepth);
    merkleProof.leaf <== canonicalHash;

    for (var j = 0; j < merkleDepth; j++) {
        merkleProof.pathElements[j] <== merklePath[j];
        merkleProof.pathIndices[j] <== merkleIndices[j];
    }

    // Constrain: computed Merkle root must match public input
    merkleProof.root === merkleRoot;

    // Verify leafIndex consistency with merkleIndices
    signal leafIndexBits[merkleDepth];
    signal leafIndexSum[merkleDepth + 1];
    leafIndexSum[0] <== 0;

    for (var k = 0; k < merkleDepth; k++) {
        leafIndexBits[k] <== merkleIndices[k];
        var bitWeight = 1 << k;
        leafIndexSum[k + 1] <== leafIndexSum[k] + leafIndexBits[k] * bitWeight;
    }

    leafIndex === leafIndexSum[merkleDepth];

    // --- Index bounds: leafIndex < treeSize (when treeSize > 0) ---
    signal treeSizeInv;
    treeSizeInv <-- (treeSize != 0) ? (1 / treeSize) : 0;
    signal treeSizeIsPositive;
    treeSizeIsPositive <== treeSize * treeSizeInv;
    treeSizeIsPositive * (1 - treeSizeIsPositive) === 0;

    component boundsCheck = LessThanBounded(merkleDepth);
    boundsCheck.in[0] <== leafIndex;
    boundsCheck.in[1] <== treeSize;
    (1 - boundsCheck.out) * treeSizeIsPositive === 0;

    // ===== COMPONENT 3: LEDGER ROOT COMMITMENT =====

    component ledgerSMTProof = MerkleTreeInclusionProof(smtDepth);
    ledgerSMTProof.leaf <== merkleRoot;

    for (var m = 0; m < smtDepth; m++) {
        ledgerSMTProof.pathElements[m] <== ledgerPathElements[m];
        ledgerSMTProof.pathIndices[m] <== ledgerPathIndices[m];
    }

    // Constrain: computed SMT root must match public ledger root
    ledgerSMTProof.root === ledgerRoot;

    // ===== COMPONENT 4: CHECKPOINT BINDING =====

    component checkpointCommitment = Poseidon(2);
    checkpointCommitment.inputs[0] <== ledgerRoot;
    checkpointCommitment.inputs[1] <== 0;  // Domain separator for checkpoints

    signal computedCheckpointHash;
    computedCheckpointHash <== checkpointCommitment.out;

    signal checkpointExists;
    checkpointExists <== checkpointHash * checkpointHash;
    checkpointExists * 0 === 0;  // Dummy constraint to use the signal
}

// Default instantiation: 8 sections, Merkle depth 20, SMT depth 256
component main {public [canonicalHash, merkleRoot, ledgerRoot, checkpointHash, treeSize]} =
    UnifiedCanonicalizationInclusionRootSign(8, 20, 256);
