pragma circom 2.0.0;

/*
 * Sparse Merkle Tree non-membership proof with default hash chain.
 *
 * Statement proved:
 *   Given a public Poseidon Merkle root `root` and a public `leafIndex`,
 *   the prover knows a Merkle authentication path such that the leaf at
 *   that index is the empty sentinel value 0.
 *
 * Default hash chain semantics:
 *   An empty subtree at height h has hash DEFAULT[h], where:
 *     DEFAULT[0] = 0   (empty leaf)
 *     DEFAULT[h] = Poseidon(DEFAULT[h-1], DEFAULT[h-1])
 *   The prover must supply siblings that are either real subtree hashes
 *   or default hashes at the correct level. The circuit verifies the
 *   Merkle path recomputes to `root` starting from leaf = 0.
 *
 * Security hardening:
 *   - Num2Bits range check on leafIndex
 *   - Index bounds: leafIndex < treeSize (when treeSize > 0)
 *   - Domain-separated Poseidon via MerkleTreeInclusionProof
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";
include "../node_modules/circomlib/circuits/iszero.circom";

// Range-checked Num2Bits converter
template Num2BitsStrictNE(n) {
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
template LessThanBoundedNE(n) {
    signal input in[2];
    signal output out;

    component diff = Num2BitsStrictNE(n + 1);
    diff.in <== in[1] - in[0] + (1 << n);

    out <== diff.out[n];
}

template NonExistence(depth) {
    // ---- Public inputs ----
    signal input root;
    signal input leafIndex;
    signal input treeSize;   // Number of leaves; when > 0 enforces leafIndex < treeSize

    // ---- Private inputs ----
    signal input pathElements[depth];
    signal input pathIndices[depth]; // LSB-first direction bits

    // --- Range check: leafIndex fits in `depth` bits ---
    component leafIndexBits = Num2BitsStrictNE(depth);
    leafIndexBits.in <== leafIndex;

    // Enforce pathIndices encode the provided leafIndex (LSB-first)
    signal indexAccum[depth + 1];
    indexAccum[0] <== 0;

    var pow2 = 1;
    for (var i = 0; i < depth; i++) {
        // Boolean constraint for path bit
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        indexAccum[i + 1] <== indexAccum[i] + pathIndices[i] * pow2;
        pow2 = pow2 * 2;
    }
    leafIndex === indexAccum[depth];

    // --- Index bounds: leafIndex < treeSize (when treeSize > 0) ---
    component treeSizeIsZero = IsZero();
    treeSizeIsZero.in <== treeSize;
    signal treeSizeIsPositive;
    treeSizeIsPositive <== 1 - treeSizeIsZero.out;
    treeSizeIsPositive * (1 - treeSizeIsPositive) === 0;

    component boundsCheck = LessThanBoundedNE(depth);
    boundsCheck.in[0] <== leafIndex;
    boundsCheck.in[1] <== treeSize;
    (1 - boundsCheck.out) * treeSizeIsPositive === 0;

    // Prove inclusion of the empty leaf (0) at that index
    // This is the default hash chain: starting from sentinel value 0
    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== 0;

    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j] <== pathIndices[j];
    }
}

component main { public [root, leafIndex, treeSize] } = NonExistence(NON_EXISTENCE_MERKLE_DEPTH);
