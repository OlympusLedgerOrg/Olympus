pragma circom 2.0.0;

/*
 * Federation M-of-N quorum proof.
 *
 * Proves that AT LEAST `threshold` of a publicly-known set of `N` federation
 * signers produced a valid BabyJubjub EdDSA-Poseidon signature over a single
 * message `msg` — WITHOUT revealing WHICH subset signed.
 *
 * The pinned signer set (signerAx[i], signerAy[i]) and the threshold are
 * public: the federation's member nodes are not secret. What stays private is
 * the per-slot `enabled[i]` selector vector — i.e. which of the N members
 * actually co-signed. An observer learns "≥ M of these N signed", nothing more.
 *
 * Soundness sketch
 * ----------------
 *   - `enabled[i]` is constrained binary.
 *   - circomlib's EdDSAPoseidonVerifier multiplies its internal equality
 *     checks by `enabled`, so a slot with enabled=1 MUST carry a signature
 *     that verifies under (signerAx[i], signerAy[i]) over msg; enabled=0
 *     disables the check (padding / non-signing members).
 *   - The slots are bound 1:1 to the DISTINCT public pinned pubkeys, so the
 *     count of enabled slots is the count of distinct members who signed.
 *     (The host pins a deduplicated signer set — see crate::quorum.)
 *   - sum(enabled) >= threshold is enforced by an in-circuit comparator.
 *
 * Message domain
 * --------------
 * `msg` is the field element the host derives as
 *   Fr_le( BLAKE3("OLY:SBT:QUORUM:V1" | len(commit_id_hex) || commit_id_hex) )
 * (see crate::quorum::quorum_cosign_message). The circuit treats it as an
 * opaque field element; binding it to a specific credential is the verifier's
 * job (it supplies msg as a public input).
 *
 * Constraint budget
 * -----------------
 * One EdDSAPoseidonVerifier per slot (~4-6k constraints each). At N=8 the
 * total sits comfortably under the ptau20 ceiling (2^20). Raising
 * FEDERATION_QUORUM_N() scales this linearly — re-check against
 * PTAU20_MAX_CONSTRAINTS before bumping it.
 */

include "./parameters.circom";
include "../vendor/circomlib/circuits/eddsaposeidon.circom";
include "../vendor/circomlib/circuits/comparators.circom";

template FederationQuorum(N) {
    // --- Public inputs ---
    signal input msg;            // quorum co-sign message (field element)
    signal input signerAx[N];    // pinned signer set: BabyJubjub pubkey x
    signal input signerAy[N];    // pinned signer set: BabyJubjub pubkey y
    signal input threshold;      // M: minimum number of valid signatures

    // --- Private inputs ---
    signal input enabled[N];     // selector: 1 iff signer i co-signed
    signal input R8x[N];         // signature R8.x per slot
    signal input R8y[N];         // signature R8.y per slot
    signal input S[N];           // signature scalar S per slot

    // Per-slot signature verification, gated by the (private) selector bit.
    component verifiers[N];
    signal partial[N + 1];
    partial[0] <== 0;

    for (var i = 0; i < N; i++) {
        // enabled[i] must be a bit.
        enabled[i] * (enabled[i] - 1) === 0;

        verifiers[i] = EdDSAPoseidonVerifier();
        verifiers[i].enabled <== enabled[i];
        verifiers[i].Ax <== signerAx[i];
        verifiers[i].Ay <== signerAy[i];
        verifiers[i].R8x <== R8x[i];
        verifiers[i].R8y <== R8y[i];
        verifiers[i].S <== S[i];
        verifiers[i].M <== msg;

        // Running sum of enabled (= valid, since enabled implies verified) slots.
        partial[i + 1] <== partial[i] + enabled[i];
    }

    signal validCount;
    validCount <== partial[N];

    // Enforce validCount >= threshold. N is small (<= FEDERATION_QUORUM_N), so
    // an 8-bit comparator covers both operands without field wraparound.
    component geq = GreaterEqThan(8);
    geq.in[0] <== validCount;
    geq.in[1] <== threshold;
    geq.out === 1;
}

component main {public [msg, signerAx, signerAy, threshold]} =
    FederationQuorum(FEDERATION_QUORUM_N());
