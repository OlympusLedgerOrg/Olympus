pragma circom 2.0.0;

/*
 * Document existence proof with Poseidon Merkle inclusion.
 *
 * Verifies a Poseidon Merkle path from a leaf to a public root.
 * The leaf index is exposed as a public input to anchor ledger position
 * without revealing the leaf value.
 *
 * Security hardening:
 *   - Num2Bits range check on leafIndex
 *   - Index bounds: leafIndex < treeSize (when treeSize > 0)
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

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

template DocumentExistence(depth) {
    // Public inputs
    signal input root;
    signal input leafIndex;
    signal input treeSize;   // Number of leaves; when > 0 enforces leafIndex < treeSize

    // Private inputs
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // --- Range check: leafIndex fits in `depth` bits ---
    component leafIndexBits = Num2BitsStrict(depth);
    leafIndexBits.in <== leafIndex;

    // Ensure pathIndices encode the provided leafIndex
    signal indexAccum[depth + 1];
    indexAccum[0] <== 0;
    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        // Boolean constraint for path index
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        indexAccum[i + 1] <== indexAccum[i] + pathIndices[i] * pow2;
        pow2 = pow2 * 2;
    }
    // NOTE: For depth=256, indexAccum overflows the BN128 field and this
    // constraint is vacuous (both sides reduce to the same field element).
    // Soundness is guaranteed by the Merkle root check alone, not this constraint.
    // This constraint is retained for clarity at smaller tree depths where it is meaningful.
    leafIndex === indexAccum[depth];

    // --- Index bounds: leafIndex < treeSize (when treeSize > 0) ---
    // VERIFIER RESPONSIBILITY: When treeSize=0, the bounds check below is
    // disabled (correct for an empty tree). Off-chain verifiers MUST reject
    // proofs where treeSize=0 but the supplied root is not the known empty-tree
    // root. The circuit cannot enforce this because the empty-tree root is not
    // a circuit parameter.
    // Constrained: treeSizeIsPositive = 1 iff treeSize != 0
    // Uses circomlib IsZero rather than an unconstrained division hint.
    component treeSizeIsZero = IsZero();
    treeSizeIsZero.in <== treeSize;
    signal treeSizeIsPositive <== 1 - treeSizeIsZero.out;
    // Binary constraint is now guaranteed by IsZero's own output constraint.
    // The explicit binary check below is kept as a belt-and-suspenders assertion:
    treeSizeIsPositive * (1 - treeSizeIsPositive) === 0;

    // When treeSize > 0, enforce leafIndex < treeSize
    component boundsCheck = LessThanBounded(depth);
    boundsCheck.in[0] <== leafIndex;
    boundsCheck.in[1] <== treeSize;
    // boundsCheck.out is 1 if leafIndex < treeSize
    // Enforce: if treeSizeIsPositive then boundsCheck.out must be 1
    (1 - boundsCheck.out) * treeSizeIsPositive === 0;

    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== leaf;
    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j] <== pathIndices[j];
    }

}

// Default depth from parameters.circom (sparse tree friendly)
component main {public [root, leafIndex, treeSize]} = DocumentExistence(DOCUMENT_MERKLE_DEPTH());
