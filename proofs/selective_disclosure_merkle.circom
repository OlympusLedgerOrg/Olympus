pragma circom 2.1.6;

include "circomlib/poseidon.circom";
include "./circuits/parameters.circom";

/*
 * MerkleVerify — verify a single leaf against a Poseidon Merkle root.
 *
 * Parameters:
 *   depth  — tree depth (number of path elements)
 *
 * Inputs:
 *   root             — public Merkle root
 *   leafHash         — hash of the leaf being proven
 *   pathElements[depth] — sibling hashes along the path
 *   pathIndices[depth]  — 0 = current node is left child, 1 = right child
 */
template MerkleVerify(depth) {
    signal input root;
    signal input leafHash;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal levelHashes[depth + 1];
    signal diff[depth];
    signal mux[depth];
    component hashers[depth];

    levelHashes[0] <== leafHash;

    for (var i = 0; i < depth; i++) {
        // Enforce path index is boolean (0 or 1)
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        hashers[i] = Poseidon(2);

        // Single-multiplication routing:
        //   pathIndex == 0 → inputs: (levelHash, sibling)
        //   pathIndex == 1 → inputs: (sibling,    levelHash)
        diff[i] <== pathElements[i] - levelHashes[i];
        mux[i]  <== pathIndices[i] * diff[i];

        hashers[i].inputs[0] <== levelHashes[i] + mux[i];
        hashers[i].inputs[1] <== pathElements[i] - mux[i];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[depth];
}

/*
 * SelectiveDisclosure — prove k leaves against a shared Poseidon Merkle root.
 *
 * Each revealed leaf is represented by a preimage of length `preimageLen`
 * field elements.  The circuit:
 *   1. Hashes each preimage with Poseidon to produce the leaf hash.
 *   2. Verifies each leaf hash is included in the tree at the supplied path.
 *
 * Parameters:
 *   depth       — tree depth (supports 2^depth leaves)
 *   k           — number of disclosed leaves per proof bundle
 *   preimageLen — number of field elements per leaf preimage
 *
 * Public inputs:
 *   root                        — Merkle root of the original document
 *   leafHashes[k]               — Poseidon hashes of the revealed preimages
 *   indices[k]                  — leaf indices (for auditability; not used in path computation)
 *   pathElements[k][depth]      — sibling hashes for each leaf proof
 *   pathIndices[k][depth]       — path direction bits for each leaf proof
 *
 * Private inputs:
 *   preimages[k][preimageLen]   — plaintext field elements for each revealed leaf
 *                                 For Phase 0.2 these are:
 *                                   [doc_id_fe, idx, type, page,
 *                                    text_hash_hi, text_hash_lo]
 */
template SelectiveDisclosure(depth, k, preimageLen) {
    // ---- Public inputs ----
    signal input root;
    signal input leafHashes[k];
    signal input indices[k];
    signal input pathElements[k][depth];
    signal input pathIndices[k][depth];

    // ---- Private inputs ----
    signal input preimages[k][preimageLen];

    // ---- Per-leaf components ----
    component hashers[k];
    component verifiers[k];

    for (var i = 0; i < k; i++) {
        // 1. Hash the preimage to reproduce the leaf hash
        hashers[i] = Poseidon(preimageLen);
        for (var j = 0; j < preimageLen; j++) {
            hashers[i].inputs[j] <== preimages[i][j];
        }

        // 2. Bind the computed hash to the public leafHash
        leafHashes[i] === hashers[i].out;

        // 3. Verify Merkle inclusion for this leaf
        verifiers[i] = MerkleVerify(depth);
        verifiers[i].root         <== root;
        verifiers[i].leafHash     <== hashers[i].out;
        for (var d = 0; d < depth; d++) {
            verifiers[i].pathElements[d] <== pathElements[i][d];
            verifiers[i].pathIndices[d]  <== pathIndices[i][d];
        }

        // indices are public for auditability; no additional constraint needed
        _ <== indices[i];
    }
}

// ---------------------------------------------------------------------------
// Defaults (configured via proofs/circuits/parameters.circom):
//   SELECTIVE_DISCLOSURE_DEPTH       = 20
//   SELECTIVE_DISCLOSURE_K           = 8
//   SELECTIVE_DISCLOSURE_PREIMAGE_LEN = 6
// ---------------------------------------------------------------------------

component main {
    public [
        root,
        leafHashes,
        indices,
        pathElements,
        pathIndices
    ]
} = SelectiveDisclosure(
    SELECTIVE_DISCLOSURE_DEPTH,
    SELECTIVE_DISCLOSURE_K,
    SELECTIVE_DISCLOSURE_PREIMAGE_LEN
);
