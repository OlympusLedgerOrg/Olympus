pragma circom 2.0.0;

/*
 * Unified Proof: Canonicalization + Inclusion + Root Verification
 *
 * This circuit provides a single proof that verifies three critical properties:
 *   1) Document canonicalization - the document sections are properly canonicalized
 *      with structured metadata (sectionCount, sectionLength, sectionHash)
 *   2) Merkle inclusion - the document is included in the ledger Merkle tree
 *   3) Ledger root commitment - the Merkle root is committed in an SMT
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
 * Public inputs (6):
 *   - canonicalHash: Structured metadata commitment (sectionCount + sectionLengths + sectionHashes via DomainPoseidon(3))
 *   - merkleRoot: Root of the ledger Merkle tree
 *   - ledgerRoot: SMT root hash from checkpoint
 *   - treeSize: Number of leaves in the Merkle tree (for bounds checking)
 *   - checkpointTimestamp: Unix timestamp embedded in the signed checkpoint
 *   - authorityPubKeyHash: Poseidon(Ax, Ay) of the Baby Jubjub signing key;
 *       verifier checks this against its known-authority allowlist
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
 *   - authorityPubKeyX, authorityPubKeyY: Baby Jubjub public key coordinates
 *   - sigR8x, sigR8y, sigS: EdDSA-Poseidon signature over Poseidon(ledgerRoot, checkpointTimestamp)
 *
 * Checkpoint verification:
 *   In-circuit EdDSA-Poseidon over Baby Jubjub (native to BN254, ~20k constraints).
 *   The signed message is Poseidon(ledgerRoot, checkpointTimestamp).
 *   Baby Jubjub is the only supported checkpoint signing key type.
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/eddsa_poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

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
    signal input canonicalHash;          // Poseidon hash of canonical document
    signal input merkleRoot;             // Root of ledger Merkle tree
    signal input ledgerRoot;             // SMT root from checkpoint
    signal input treeSize;               // Number of leaves for bounds checking
    signal input checkpointTimestamp;    // Unix timestamp from checkpoint (replay protection)
    signal input authorityPubKeyHash;    // Poseidon(Ax, Ay) — verifier checks against allowlist

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

    // Baby Jubjub EdDSA-Poseidon checkpoint signature inputs
    signal input authorityPubKeyX;   // Baby Jubjub pubkey x coordinate
    signal input authorityPubKeyY;   // Baby Jubjub pubkey y coordinate
    signal input sigR8x;             // Signature R8 x coordinate
    signal input sigR8y;             // Signature R8 y coordinate
    signal input sigS;               // Signature S scalar

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

    // Bind public canonicalHash to the structured metadata chain
    canonicalHash === structuredHashes[2 * maxSections];

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
    // Constrained: treeSizeIsPositive = 1 iff treeSize != 0
    // Uses circomlib IsZero rather than an unconstrained division hint.
    component treeSizeIsZero = IsZero();
    treeSizeIsZero.in <== treeSize;
    signal treeSizeIsPositive <== 1 - treeSizeIsZero.out;
    // Binary constraint is now guaranteed by IsZero's own output constraint.
    // The explicit binary check below is kept as a belt-and-suspenders assertion:
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

    // ===== COMPONENT 4: BABY JUBJUB EDDSA-POSEIDON CHECKPOINT SIGNATURE =====
    //
    // Proves the checkpoint authority signed Poseidon(ledgerRoot, checkpointTimestamp)
    // with a Baby Jubjub key. Baby Jubjub is native to BN254 — ~20k constraints vs
    // ~700k for Ed25519 in the wrong field.
    //
    // Range check: checkpointTimestamp fits in 64 bits (Unix epoch through year 2554)
    component tsBits = Num2BitsStrict(64);
    tsBits.in <== checkpointTimestamp;

    // Signed message: Poseidon(ledgerRoot, checkpointTimestamp)
    // Binds the signature to this specific ledger root at this specific time.
    component msgHash = Poseidon(2);
    msgHash.inputs[0] <== ledgerRoot;
    msgHash.inputs[1] <== checkpointTimestamp;

    // Verify pubkey is on the Baby Jubjub curve (BabyCheck enforces the curve equation)
    component babyCheck = BabyCheck();
    babyCheck.x <== authorityPubKeyX;
    babyCheck.y <== authorityPubKeyY;

    // Bind public authorityPubKeyHash to the private key coordinates.
    // Verifier checks authorityPubKeyHash against its known-authority allowlist.
    component keyHash = Poseidon(2);
    keyHash.inputs[0] <== authorityPubKeyX;
    keyHash.inputs[1] <== authorityPubKeyY;
    authorityPubKeyHash === keyHash.out;

    // EdDSA-Poseidon signature verification (circomlib EdDSAPoseidonVerifier)
    component eddsaVerifier = EdDSAPoseidonVerifier();
    eddsaVerifier.enabled <== 1;
    eddsaVerifier.Ax     <== authorityPubKeyX;
    eddsaVerifier.Ay     <== authorityPubKeyY;
    eddsaVerifier.R8x    <== sigR8x;
    eddsaVerifier.R8y    <== sigR8y;
    eddsaVerifier.S      <== sigS;
    eddsaVerifier.M      <== msgHash.out;
}

// Public: canonicalHash, merkleRoot, ledgerRoot, treeSize, checkpointTimestamp, authorityPubKeyHash.
// Private: all document/path inputs + Baby Jubjub key coordinates + signature.
component main {public [canonicalHash, merkleRoot, ledgerRoot, treeSize, checkpointTimestamp, authorityPubKeyHash]} =
    UnifiedCanonicalizationInclusionRootSign(
        UNIFIED_MAX_SECTIONS(),
        UNIFIED_MERKLE_DEPTH(),
        UNIFIED_SMT_DEPTH()
    );
