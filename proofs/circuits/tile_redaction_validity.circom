pragma circom 2.0.0;

/*
 * Tile redaction validity proof (ADR-0024) — hybrid rasterized ZK redaction.
 *
 * Replaces the chunk-based redaction_validity scheme. Leaves are Poseidon
 * field elements derived from per-tile Pedersen commitments
 * (`leaf_i = Poseidon(C_i.x, C_i.y)`, computed off-circuit); this circuit only
 * folds and commits over the leaf field elements.
 *
 * Proves:
 *   1) The N tile leaves fold to the public `originalRoot` (depth-`depth`
 *      Poseidon Merkle tree, domain-1 node hash). This is the ledger leaf the
 *      companion document_existence proof anchors — they share `originalRoot`.
 *   2) revealedCount = sum(revealMask).
 *   3) redactedCommitment is the domain-3 Poseidon chain over
 *      (revealedCount, revealedLeaves[]) where revealedLeaves[i] = leaf[i] if
 *      revealed, else 0. Redacted leaves zero-pad the chain, so the recipient
 *      recomputes it from the revealed tiles alone.
 *   4) nullifier = Poseidon(originalRoot, redactedCommitment, recipientId),
 *      and the issuer's BabyJubjub EdDSA-Poseidon signature over `nullifier`
 *      verifies against the public issuer key (Ax, Ay) — only the authority
 *      can mint a redaction for a given recipient (audit M-2, carried forward).
 *
 * Difference from redaction_validity: this circuit recomputes `originalRoot`
 * from ALL leaves with a single flat fold (maxLeaves - 1 node hashes) instead
 * of running maxLeaves per-leaf Merkle-inclusion proofs. The leaves are already
 * private circuit inputs, so the fold proves inclusion directly.
 *
 * Both the fold node hash and the redacted-commitment chain use a SINGLE 3-input
 * Poseidon (domain tag in slot 0), not the nested Poseidon(Poseidon(domain,l),r)
 * form — ~⅓ fewer constraints, which keeps N = 1024 (~1.35M R1CS) inside the
 * power-22 ceremony (snarkjs needs 2^power >= 2*constraints).
 */

include "./lib/poseidon.circom";
include "./parameters.circom";
include "../vendor/circomlib/circuits/eddsaposeidon.circom";

// Range-checked Num2Bits (binary-constrained), local to this circuit.
template Num2BitsTR(n) {
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

// Domain-separated Poseidon node/chain hash: a SINGLE 3-input Poseidon with the
// domain tag in slot 0 — Poseidon(domain, left, right). This is the standard,
// cheaper domain-separation construction (~⅓ fewer constraints than the nested
// Poseidon(Poseidon(domain,left),right) form), used for BOTH the Merkle fold
// (domain 1) and the redacted-commitment chain (domain 3). The Rust witness
// (crate::zk::tile) MUST mirror this exact construction.
template DomainPoseidonTR(domain) {
    signal input left;
    signal input right;
    signal output out;

    component h = Poseidon(3);
    h.inputs[0] <== domain;
    h.inputs[1] <== left;
    h.inputs[2] <== right;

    out <== h.out;
}

// Flat Poseidon Merkle fold over `maxLeaves` (= 2^depth) leaves, domain-1 node
// hashing — the SNARK-side mirror of crate::zk::tile::tiles_poseidon_root.
//
// Binary-heap layout: leaf i sits at heap index maxLeaves + i; internal node i
// (1 <= i < maxLeaves) hashes children (2i, 2i+1); the root is index 1. Nodes
// are computed from maxLeaves-1 down to 1 so every child is set before its
// parent. The fold reproduces the standard left-to-right pairwise tree
// (root = N(N(l0,l1), N(l2,l3)), ...).
template TilesRoot(maxLeaves, depth) {
    // Compile-time invariant: the binary-heap fold below assumes a full tree.
    assert((1 << depth) == maxLeaves);
    signal input leaves[maxLeaves];
    signal output root;

    var totalNodes = maxLeaves - 1;
    component hashers[totalNodes];
    signal heap[2 * maxLeaves];

    for (var i = 0; i < maxLeaves; i++) {
        heap[maxLeaves + i] <== leaves[i];
    }

    var h = 0;
    for (var i = maxLeaves - 1; i >= 1; i--) {
        hashers[h] = DomainPoseidonTR(1);
        hashers[h].left <== heap[2 * i];
        hashers[h].right <== heap[2 * i + 1];
        heap[i] <== hashers[h].out;
        h++;
    }

    root <== heap[1];
}

template TileRedactionValidity(maxLeaves, depth) {
    // Compile-time invariant: maxLeaves must be a full binary tree of `depth`
    // (the index range check on revealedCount and the fold both depend on it).
    assert((1 << depth) == maxLeaves);

    // Public inputs.
    signal input originalRoot;
    signal input redactedCommitment;
    signal input revealedCount;
    // Public issuer pubkey (Ax, Ay) the in-circuit EdDSA verifier checks against.
    signal input issuerAx;
    signal input issuerAy;

    // Private inputs.
    signal input leaves[maxLeaves];      // Poseidon(C_i.x, C_i.y) for every tile slot
    signal input revealMask[maxLeaves];  // 1 = revealed, 0 = redacted

    // Recipient-bound nullifier (anti-replay): recipientId private, nullifier
    // is a circuit output (hence public) binding this disclosure to one recipient.
    signal input recipientId;
    signal output nullifier;

    // Issuer EdDSA-Poseidon signature components (private).
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // --- Range check on revealedCount (fits in depth+1 bits: 0..=maxLeaves) ---
    component revealedCountBits = Num2BitsTR(depth + 1);
    revealedCountBits.in <== revealedCount;

    // --- 1) Fold ALL leaves to originalRoot ---
    component tree = TilesRoot(maxLeaves, depth);
    for (var i = 0; i < maxLeaves; i++) {
        tree.leaves[i] <== leaves[i];
    }
    tree.root === originalRoot;

    // --- 2) revealedCount = sum(revealMask); build masked reveal vector ---
    signal maskSum[maxLeaves + 1];
    maskSum[0] <== 0;
    signal revealedLeaves[maxLeaves];
    for (var i = 0; i < maxLeaves; i++) {
        revealMask[i] * (revealMask[i] - 1) === 0;       // strictly binary
        maskSum[i + 1] <== maskSum[i] + revealMask[i];
        revealedLeaves[i] <== revealMask[i] * leaves[i]; // 0 for redacted tiles
    }
    revealedCount === maskSum[maxLeaves];

    // --- 3) redactedCommitment = domain-3 Poseidon chain ---
    signal acc[maxLeaves];
    component initHash = DomainPoseidonTR(3);
    initHash.left <== revealedCount;
    initHash.right <== revealedLeaves[0];
    acc[0] <== initHash.out;

    component hashers[maxLeaves - 1];
    for (var k = 1; k < maxLeaves; k++) {
        hashers[k - 1] = DomainPoseidonTR(3);
        hashers[k - 1].left <== acc[k - 1];
        hashers[k - 1].right <== revealedLeaves[k];
        acc[k] <== hashers[k - 1].out;
    }
    redactedCommitment === acc[maxLeaves - 1];

    // --- 4) Recipient-bound nullifier = Poseidon(originalRoot, redactedCommitment, recipientId) ---
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== originalRoot;
    nullifierHash.inputs[1] <== redactedCommitment;
    nullifierHash.inputs[2] <== recipientId;
    nullifier <== nullifierHash.out;

    // --- Issuer EdDSA-Poseidon signature over `nullifier` ---
    component sigVerify = EdDSAPoseidonVerifier();
    sigVerify.enabled <== 1;
    sigVerify.Ax <== issuerAx;
    sigVerify.Ay <== issuerAy;
    sigVerify.R8x <== issuerSigR8x;
    sigVerify.R8y <== issuerSigR8y;
    sigVerify.S <== issuerSigS;
    sigVerify.M <== nullifier;
}

component main {public [originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]} =
    TileRedactionValidity(TILE_REDACTION_MAX_LEAVES(), TILE_REDACTION_MERKLE_DEPTH());
