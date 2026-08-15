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
 *
 *   - Every slot's pinned pubkey is constrained ON-CURVE by BabyCheck,
 *     UNGATED — including slots with enabled=0. circomlib's
 *     EdDSAPoseidonVerifier never instantiates BabyCheck, so without this an
 *     off-curve pinned key reached the verifier unchallenged (audit OLY-L12).
 *
 *   - circomlib's EdDSAPoseidonVerifier multiplies its internal equality
 *     checks by `enabled`, so a slot with enabled=1 MUST carry a signature
 *     that verifies under (signerAx[i], signerAy[i]) over msg; enabled=0
 *     disables the check (padding / non-signing members). For an enabled slot
 *     it ALSO clears the cofactor and rejects a small-order key
 *     (`isZero(8A.x) * enabled === 0`) and bounds `S < l`. Both of those are
 *     enabled-gated, which is sound here only because a disabled slot cannot
 *     contribute to validCount — see the distinctness rule below.
 *
 *   - DISTINCTNESS IS ENFORCED IN-CIRCUIT, NOT ASSUMED. For every pair i > j:
 *
 *         enabled[i] * (Ax_i == Ax_j  AND  Ay_i == Ay_j) === 0
 *
 *     Duplicate pinned pubkeys remain REPRESENTABLE — the host pads a signer
 *     set shorter than N by repeating the last real pubkey into the trailing
 *     slots (see crate::zk::witness::quorum), so a verifier cannot reject
 *     duplicates from the public inputs — but only the FIRST occurrence of a
 *     key may be enabled. Hence validCount counts DISTINCT signers.
 *
 *     Without this, a prover holding one signature could enable every padding
 *     slot repeating that signer and reach an inflated validCount from a
 *     single signature (audit OLY-M5). The host-side duplicate rejection in
 *     crate::zk::witness::quorum is defence in depth, not the enforcement: a
 *     malicious prover simply does not call the host witness builder.
 *
 *   - `threshold` is range-constrained to [1, 2^8) in-circuit. GreaterEqThan(8)
 *     expands to Num2Bits(9) over `in[0] + 256 - in[1]` and is sound only when
 *     both operands are < 2^8; validCount <= N = 8 structurally, but threshold
 *     is a public input that was previously unconstrained, so a large or
 *     near-field value could wrap the comparator and satisfy it vacuously.
 *     Rejecting threshold = 0 mirrors the host guard and stops a "quorum" that
 *     no signature at all satisfies.
 *
 *   - sum(enabled) >= threshold is enforced by an in-circuit comparator.
 *
 * Message domain
 * --------------
 * `msg` is the field element the host derives as
 *
 *   Fr_le( BLAKE3(
 *       "OLY:SBT:QUORUM:V2"
 *    || lp(commit_id_hex)
 *    || u32_be(threshold)
 *    || u32_be(signer_count)
 *    || for each signer, in canonical sorted order: lp(x_dec) || lp(y_dec)
 *   ) )
 *
 * where lp(·) is a u32 big-endian length prefix, the coordinates are canonical
 * in-field decimal strings, and the set is deduplicated and sorted by those
 * strings (a BTreeSet), so the digest depends on neither ordering nor encoding.
 * Binding `threshold` and the signer set is what stops either being altered
 * after issuance (audit R3-01). Do NOT derive `msg` from a shortened preimage —
 * omitting the threshold or the signer set yields a different field element and
 * rejects every valid signature.
 *
 * Source of truth: crate::quorum::quorum_cosign_message. The circuit treats
 * `msg` as an opaque field element; binding it to a specific credential is the
 * verifier's job (it supplies msg as a public input).
 *
 * Constraint budget
 * -----------------
 * One EdDSAPoseidonVerifier per slot (~4-6k constraints each) dominates. At
 * N=8 the total sits comfortably under the ptau20 ceiling (2^20); the on-curve,
 * distinctness and threshold-range constraints add well under 1% on top of it.
 * Raising FEDERATION_QUORUM_N() scales the verifiers linearly and the
 * distinctness ladder quadratically — re-check against PTAU20_MAX_CONSTRAINTS
 * before bumping it.
 */

include "./parameters.circom";
include "../vendor/circomlib/circuits/babyjub.circom";
include "../vendor/circomlib/circuits/bitify.circom";
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

    // Range-bind `threshold` to [1, 2^8) so GreaterEqThan(8) below is sound on
    // both operands, and a zero threshold cannot make the proof vacuous.
    component thresholdBits = Num2Bits(8);
    thresholdBits.in <== threshold;

    component thresholdIsZero = IsZero();
    thresholdIsZero.in <== threshold;
    thresholdIsZero.out === 0;

    // Per-slot signature verification, gated by the (private) selector bit.
    component onCurve[N];
    component verifiers[N];
    signal partial[N + 1];
    partial[0] <== 0;

    for (var i = 0; i < N; i++) {
        // enabled[i] must be a bit.
        enabled[i] * (enabled[i] - 1) === 0;

        // The pinned pubkey must be on the Baby Jubjub curve. Ungated: a
        // malformed key parked on a disabled slot is rejected too.
        onCurve[i] = BabyCheck();
        onCurve[i].x <== signerAx[i];
        onCurve[i].y <== signerAy[i];

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

    // Slot distinctness: a slot may be enabled only if its pinned pubkey
    // differs from every EARLIER slot's. One direction suffices and is in fact
    // stronger than "no duplicates among enabled slots" — the indicator does
    // not read enabled[j], so at most one slot per distinct key can ever be
    // enabled, and it must be the first occurrence.
    //
    // The two coordinates are compared as two IsEqual outputs AND-ed. Do NOT
    // collapse this into a single IsZero over a fixed linear combination of the
    // coordinate differences: the prover controls both coordinates and could
    // choose dx = -c*dy with both non-zero, making distinct points compare
    // equal-to-zero and defeating the check.
    var PAIRS = N * (N - 1) \ 2;
    component sameX[PAIRS];
    component sameY[PAIRS];
    signal samePoint[PAIRS];

    var p = 0;
    for (var i = 1; i < N; i++) {
        for (var j = 0; j < i; j++) {
            sameX[p] = IsEqual();
            sameX[p].in[0] <== signerAx[i];
            sameX[p].in[1] <== signerAx[j];

            sameY[p] = IsEqual();
            sameY[p].in[0] <== signerAy[i];
            sameY[p].in[1] <== signerAy[j];

            // Both IsEqual outputs are constrained boolean, so the product is
            // a sound AND.
            samePoint[p] <== sameX[p].out * sameY[p].out;

            // Slot i duplicates slot j => slot i must be disabled.
            enabled[i] * samePoint[p] === 0;

            p += 1;
        }
    }

    signal validCount;
    validCount <== partial[N];

    // Enforce validCount >= threshold. validCount <= N is structural (a sum of
    // N constrained bits) and threshold is range-bound above, so an 8-bit
    // comparator covers both operands without field wraparound.
    component geq = GreaterEqThan(8);
    geq.in[0] <== validCount;
    geq.in[1] <== threshold;
    geq.out === 1;
}

component main {public [msg, signerAx, signerAy, threshold]} =
    FederationQuorum(FEDERATION_QUORUM_N());
