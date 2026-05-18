pragma circom 2.0.0;

/*
 * Selective Disclosure: proves K specific fields from a document field Merkle tree.
 *
 * Each document field is committed as a Merkle leaf:
 *   leaf[i] = Poseidon(POSEIDON_DOMAIN_LEAF, fieldTag[i], fieldPreimage[i][0..preimageLen-1])
 *
 * The circuit proves:
 *   1) Each of the K selected fields is authentically included in the document
 *      Merkle tree at its declared position (Merkle inclusion proof per field).
 *   2) The disclosure commitment binds the revealed field hashes to the document
 *      root: commitment = DomainPoseidon chain over (documentRoot, fieldHash[0..K-1]).
 *   3) A nullifier prevents the same (document, field set, recipient) triple from
 *      being presented as a different disclosure to the same recipient.
 *
 * Public inputs (4):
 *   - documentRoot: Merkle root of the full document field tree
 *   - disclosureCommitment: Poseidon chain over (documentRoot, fieldHashes[0..K-1])
 *   - recipientId: arbitrary identifier for the disclosure recipient (nullifier input)
 *   - nullifier: Poseidon(documentRoot, disclosureCommitment, recipientId)
 *
 * Private inputs:
 *   - fieldPreimages[K][preimageLen]: raw field values (field elements)
 *   - fieldTags[K]: domain tag per field (encodes field type/name as field element)
 *   - fieldIndices[K]: leaf positions in the document Merkle tree
 *   - fieldPaths[K][depth]: Merkle proof sibling hashes
 *   - fieldPathIndices[K][depth]: left/right indicators for Merkle path
 *
 * Domain tags (matching protocol layer):
 *   POSEIDON_DOMAIN_LEAF       = 1  (field leaf hash)
 *   POSEIDON_DOMAIN_NODE       = 2  (Merkle node)
 *   POSEIDON_DOMAIN_COMMITMENT = 3  (disclosure commitment chain)
 *
 * eIDAS 2.0 / W3C VC alignment:
 *   fieldTag encodes the field name/type as a field element (e.g., hash of "given_name").
 *   disclosureCommitment is the verifiable presentation binding — present this + proof
 *   to a relying party; they verify the proof and check the commitment.
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";

// Domain-separated Poseidon: Poseidon(Poseidon(domain, left), right)
template DomainPoseidonSD(domain) {
    signal input left;
    signal input right;
    signal output out;

    component inner = Poseidon(2);
    inner.inputs[0] <== domain;
    inner.inputs[1] <== left;

    component outer = Poseidon(2);
    outer.inputs[0] <== inner.out;
    outer.inputs[1] <== right;

    out <== outer.out;
}

// Range-checked Num2Bits
template Num2BitsSD(n) {
    signal input in;
    signal output out[n];
    var sum = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (1 - out[i]) === 0;
        sum += out[i] * (1 << i);
    }

    sum === in;
}

template SelectiveDisclosure(K, depth, preimageLen) {
    // ===== PUBLIC INPUTS =====
    signal input documentRoot;          // Merkle root of the full document field tree
    signal input disclosureCommitment;  // Poseidon chain binding revealed fields to documentRoot
    signal input recipientId;           // Recipient identity (also a public input for nullifier)
    signal output nullifier;            // Poseidon(documentRoot, disclosureCommitment, recipientId)

    // ===== PRIVATE INPUTS =====
    signal input fieldPreimages[K][preimageLen]; // Raw field values (field elements)
    signal input fieldTags[K];                   // Domain tag per field (field name hash)
    signal input fieldIndices[K];                // Leaf positions in document Merkle tree
    signal input fieldPaths[K][depth];           // Merkle proof siblings
    signal input fieldPathIndices[K][depth];     // Left/right path indicators

    // ===== COMPONENT 1: FIELD LEAF HASHING AND MERKLE INCLUSION =====
    //
    // For each field i:
    //   leafHash[i] = Poseidon(DOMAIN_LEAF=1, fieldTag[i], fieldPreimage[i][0..preimageLen-1])
    //   MerkleProof: leafHash[i] at fieldIndices[i] in tree with root documentRoot

    // Poseidon(1 + 1 + preimageLen) inputs: domain, fieldTag, preimage[0..preimageLen-1]
    component leafHashers[K];
    signal leafHashes[K];
    component inclusionProofs[K];
    signal idxAccum[K][depth + 1];

    for (var i = 0; i < K; i++) {
        // Range check: fieldIndex fits in depth bits
        component idxBits = Num2BitsSD(depth);
        idxBits.in <== fieldIndices[i];

        // Leaf hash: Poseidon(domain=1, fieldTag, preimage[0], ..., preimage[preimageLen-1])
        leafHashers[i] = Poseidon(preimageLen + 2);
        leafHashers[i].inputs[0] <== 1;             // POSEIDON_DOMAIN_LEAF
        leafHashers[i].inputs[1] <== fieldTags[i];
        for (var p = 0; p < preimageLen; p++) {
            leafHashers[i].inputs[p + 2] <== fieldPreimages[i][p];
        }
        leafHashes[i] <== leafHashers[i].out;

        // Index binding: pathIndices must reconstruct fieldIndices[i]
        idxAccum[i][0] <== 0;
        for (var b = 0; b < depth; b++) {
            fieldPathIndices[i][b] * (fieldPathIndices[i][b] - 1) === 0;
            idxAccum[i][b + 1] <== idxAccum[i][b] + fieldPathIndices[i][b] * (1 << b);
        }
        idxAccum[i][depth] === fieldIndices[i];

        // Merkle inclusion proof
        inclusionProofs[i] = MerkleTreeInclusionProof(depth);
        inclusionProofs[i].leaf <== leafHashes[i];
        for (var j = 0; j < depth; j++) {
            inclusionProofs[i].pathElements[j] <== fieldPaths[i][j];
            inclusionProofs[i].pathIndices[j]  <== fieldPathIndices[i][j];
        }
        inclusionProofs[i].root === documentRoot;
    }

    // ===== COMPONENT 2: DISCLOSURE COMMITMENT =====
    //
    // commitment = DomainPoseidon(3) chain seeded with documentRoot, then
    // each revealed fieldHash in order. This binds the disclosure to the
    // specific document and specific set of revealed fields.
    //
    // acc[0] = DomainPoseidon(3)(documentRoot, leafHashes[0])
    // acc[i] = DomainPoseidon(3)(acc[i-1], leafHashes[i])

    signal commitAcc[K];

    component initCommit = DomainPoseidonSD(3);
    initCommit.left  <== documentRoot;
    initCommit.right <== leafHashes[0];
    commitAcc[0] <== initCommit.out;

    component commitHashers[K - 1];
    for (var k = 1; k < K; k++) {
        commitHashers[k - 1] = DomainPoseidonSD(3);
        commitHashers[k - 1].left  <== commitAcc[k - 1];
        commitHashers[k - 1].right <== leafHashes[k];
        commitAcc[k] <== commitHashers[k - 1].out;
    }

    disclosureCommitment === commitAcc[K - 1];

    // ===== COMPONENT 3: NULLIFIER =====
    //
    // Prevents replaying the same disclosure to a different verifier, and
    // detects if the same recipient received inconsistent disclosures of
    // the same document. Verifiers maintain a nullifier registry.
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== documentRoot;
    nullifierHash.inputs[1] <== disclosureCommitment;
    nullifierHash.inputs[2] <== recipientId;
    nullifier <== nullifierHash.out;
}

// Public: documentRoot, disclosureCommitment, recipientId, nullifier (output).
// Private: fieldPreimages, fieldTags, fieldIndices, fieldPaths, fieldPathIndices.
component main {public [documentRoot, disclosureCommitment, recipientId]} =
    SelectiveDisclosure(
        SELECTIVE_DISCLOSURE_K(),
        SELECTIVE_DISCLOSURE_DEPTH(),
        SELECTIVE_DISCLOSURE_PREIMAGE_LEN()
    );
