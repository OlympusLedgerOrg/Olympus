pragma circom 2.0.0;

/*
 * Redaction validity proof (domain-separated Poseidon).
 *
 * ADR-0025: this circuit moved from 16/depth-4 to 1024/depth-10 (one leaf per
 * PDF object). To keep N=1024 inside a practical ceremony, the inclusion check
 * was changed from per-leaf Merkle proofs to a single **flat fold**: all leaves
 * are already private inputs, so the circuit recomputes `originalRoot` once
 * (maxLeaves-1 node hashes) and asserts equality, instead of running maxLeaves
 * depth-deep MerkleProof instances (~depth× more constraints). The public-
 * signal surface, domain tags, commitment chain, nullifier, and in-circuit
 * EdDSA-Poseidon issuer signature are UNCHANGED.
 *
 * Proves:
 *   1) originalRoot == flat Poseidon fold over originalLeaves[] (node domain 1).
 *      Because leaf i is fed at heap position maxLeaves+i, leaf i is bound to
 *      tree index i structurally — no separate index binding is needed.
 *   2) revealedCount equals the number of revealed leaves (sum of revealMask).
 *   3) redactedCommitment is Poseidon-chained over (revealedCount, revealedLeaves[]),
 *      where revealedLeaves[i] = originalLeaves[i] if revealed, else 0 (domain 3).
 *   4) nullifier = Poseidon(originalRoot, redactedCommitment, recipientId), and
 *      the issuer EdDSA-Poseidon signature verifies over that nullifier (M-2).
 *
 * Security hardening retained:
 *   - Num2Bits range check on revealedCount
 *   - Strictly binary revealMask
 *   - Domain-separated Poseidon: node domain 1, commitment chain domain 3
 *   - ALL leaves bound into originalRoot via the fold (a prover cannot claim
 *     arbitrary values for redacted leaves — they still enter the root).
 */

include "./lib/poseidon.circom";
include "./parameters.circom";
include "../vendor/circomlib/circuits/eddsaposeidon.circom";

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

// Domain-separated Poseidon hash: Poseidon(Poseidon(domain, left), right).
// Matches `olympus_crypto::poseidon::domain_node` and the Rust witness path,
// so node (domain 1) and commitment-chain (domain 3) hashes are byte-identical
// across the circuit, the desktop crate, and both offline verifiers.
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
    // Audit M-2: trusted-issuer pubkey (Ax, Ay) is a public input so verifiers
    // can pin the proof to a known issuer.
    signal input issuerAx;
    signal input issuerAy;

    // Private inputs
    signal input originalLeaves[maxLeaves];   // ALL leaf values (including redacted ones)
    signal input revealMask[maxLeaves];       // 1 = revealed, 0 = redacted

    // Recipient-bound nullifier (anti-replay): recipientId is private; nullifier
    // is a circuit output (hence public) binding this disclosure to one recipient.
    signal input recipientId;
    signal output nullifier;

    // Audit M-2: EdDSA-Poseidon signature components (private) — the issuer
    // signs Poseidon(originalRoot, redactedCommitment, recipientId) with their
    // BabyJubjub authority key.
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // --- Range check on revealedCount (≤ maxLeaves = 2^depth ⇒ depth+1 bits) ---
    component revealedCountBits = Num2BitsRV(depth + 1);
    revealedCountBits.in <== revealedCount;

    // -------------------------
    // 1) Enforce revealedCount = sum(revealMask); build the masked reveal vector.
    // -------------------------
    signal maskSum[maxLeaves + 1];
    maskSum[0] <== 0;
    signal revealedLeaves[maxLeaves];

    for (var i = 0; i < maxLeaves; i++) {
        // Force revealMask to be strictly binary (0 or 1)
        revealMask[i] * (revealMask[i] - 1) === 0;
        maskSum[i + 1] <== maskSum[i] + revealMask[i];
        // revealed leaves keep their value; redacted leaves zero-pad the chain.
        revealedLeaves[i] <== revealMask[i] * originalLeaves[i];
    }
    revealedCount === maskSum[maxLeaves];

    // -------------------------
    // 2) ADR-0025 flat fold: recompute originalRoot from ALL leaves.
    //    Complete binary heap layout: leaf i at index maxLeaves+i, internal
    //    node i (1..maxLeaves-1) = DomainPoseidon(1, child 2i, child 2i+1),
    //    root at index 1. Processing i descending guarantees children (2i,
    //    2i+1 > i) are already computed. (maxLeaves-1) node hashes total.
    // -------------------------
    signal tree[2 * maxLeaves];
    for (var i = 0; i < maxLeaves; i++) {
        tree[maxLeaves + i] <== originalLeaves[i];
    }
    component nodeHash[maxLeaves - 1];
    for (var i = maxLeaves - 1; i >= 1; i--) {
        nodeHash[i - 1] = DomainPoseidon(1);
        nodeHash[i - 1].left <== tree[2 * i];
        nodeHash[i - 1].right <== tree[2 * i + 1];
        tree[i] <== nodeHash[i - 1].out;
    }
    // Recomputed root must equal the public originalRoot.
    tree[1] === originalRoot;

    // -------------------------
    // 3) Commit to revealedLeaves + revealedCount using domain-separated
    //    Poseidon (domain tag 3 = commitment chain).
    // -------------------------
    signal acc[maxLeaves];

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

    // --- Recipient-bound nullifier ---
    // nullifier = Poseidon(originalRoot, redactedCommitment, recipientId).
    // Plain circomlib Poseidon(3), matching the Rust witness `hash_n`. As an
    // output it is automatically public and appears FIRST in the snarkjs
    // publicSignals vector, matching RedactionWitness::public_signals():
    //   [nullifier, originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy].
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== originalRoot;
    nullifierHash.inputs[1] <== redactedCommitment;
    nullifierHash.inputs[2] <== recipientId;
    nullifier <== nullifierHash.out;

    // --- Audit M-2: issuer EdDSA-Poseidon signature verification ---
    // Message digest M = nullifier (= Poseidon(originalRoot, redactedCommitment,
    // recipientId)). Reusing the nullifier saves one Poseidon(3).
    component sigVerify = EdDSAPoseidonVerifier();
    sigVerify.enabled <== 1;
    sigVerify.Ax <== issuerAx;
    sigVerify.Ay <== issuerAy;
    sigVerify.R8x <== issuerSigR8x;
    sigVerify.R8y <== issuerSigR8y;
    sigVerify.S <== issuerSigS;
    sigVerify.M <== nullifier;
}

// Default parameters: values loaded from parameters.circom
component main {public [originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]} =
    RedactionValidity(REDACTION_MAX_LEAVES(), REDACTION_MERKLE_DEPTH());
