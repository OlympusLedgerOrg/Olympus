/**
 * Cross-implementation EdDSA-Poseidon parity: circomlibjs ↔
 * babyjubjub-permissive (the new permissive Rust impl).
 *
 * This is the guardrail the replacement plan calls for. Phase 2 already
 * proved the Rust impl is byte-identical to `babyjubjub-rs`; this test
 * closes the loop against the *reference JS* implementation (circomlibjs),
 * so a subtle encoding drift that happened to match babyjubjub-rs but not
 * circomlib would still be caught.
 *
 * Fixture: `rust_eddsa_vectors.json`, emitted by
 * `cargo run -p babyjubjub-permissive --example gen_rust_eddsa_vectors`.
 * Each entry is babyjubjub-permissive's OWN output for a (sk, msg) pair.
 *
 * For every vector we assert:
 *   1. circomlibjs `prv2pub(sk)` == Rust pk (x, y)        — pubkey parity
 *   2. circomlibjs `signPoseidon(sk, msg)` == Rust (R8, s) — signature byte parity
 *      (circomlib's nonce is deterministic — BLAKE512(sk[32..]||msg) mod l —
 *       so the signature is reproducible and must match exactly)
 *   3. circomlibjs `verifyPoseidon` accepts the Rust-format signature
 *      reconstructed from the JSON                          — cross-verify
 *
 * Note on the GPL boundary: circomlibjs is GPL-3.0 and lives here as a
 * test-time devDependency only. It is never imported by the shipped
 * verifier (verifier.js / client.js) nor by any Olympus runtime artifact —
 * same build-time-only posture documented for circom/snarkjs in
 * THIRD_PARTY_LICENSES.md.
 */

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { buildEddsa } = require("circomlibjs");

async function main() {
  const eddsa = await buildEddsa();
  const F = eddsa.F; // BN254 scalar field = the curve's base field Fq

  const vectorsPath = path.join(__dirname, "rust_eddsa_vectors.json");
  if (!fs.existsSync(vectorsPath)) {
    throw new Error(
      `rust_eddsa_vectors.json missing. Regenerate with:\n` +
        `  cargo run -p babyjubjub-permissive --example gen_rust_eddsa_vectors`
    );
  }
  const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
  assert.ok(vectors.length > 0, "vector set must be non-empty");

  let checked = 0;
  for (let i = 0; i < vectors.length; i++) {
    const v = vectors[i];
    const prv = Buffer.from(v.sk_hex, "hex");
    assert.strictEqual(prv.length, 32, `vector ${i}: sk must be 32 bytes`);

    // (1) Pubkey derivation parity. F.toObject lifts a field element to a
    //     canonical BigInt for string comparison against the Rust decimal.
    const A = eddsa.prv2pub(prv);
    assert.strictEqual(
      F.toObject(A[0]).toString(),
      v.pk_x_dec,
      `vector ${i}: pk.x diverges (circomlibjs vs babyjubjub-permissive)`
    );
    assert.strictEqual(
      F.toObject(A[1]).toString(),
      v.pk_y_dec,
      `vector ${i}: pk.y diverges`
    );

    // (2) Signature byte parity. signPoseidon is deterministic.
    const msg = F.e(BigInt(v.msg_dec));
    const sig = eddsa.signPoseidon(prv, msg);
    assert.strictEqual(
      F.toObject(sig.R8[0]).toString(),
      v.r8x_dec,
      `vector ${i}: R8.x diverges`
    );
    assert.strictEqual(
      F.toObject(sig.R8[1]).toString(),
      v.r8y_dec,
      `vector ${i}: R8.y diverges`
    );
    assert.strictEqual(
      BigInt(sig.S).toString(),
      v.s_dec,
      `vector ${i}: S diverges`
    );

    // (3) Cross-verify: reconstruct the signature purely from the Rust
    //     JSON values and confirm circomlibjs's verifier accepts it. This
    //     is the direction that matters most — "does the reference impl
    //     accept what the new Rust signer produces?"
    const rustSig = {
      R8: [F.e(BigInt(v.r8x_dec)), F.e(BigInt(v.r8y_dec))],
      S: BigInt(v.s_dec),
    };
    assert.ok(
      eddsa.verifyPoseidon(msg, rustSig, A),
      `vector ${i}: circomlibjs must verify the Rust-emitted signature`
    );

    // (4) Negative control: a tampered message must NOT verify, so the
    //     check above is meaningful (not a verifier that always returns true).
    const badMsg = F.e(BigInt(v.msg_dec) + 1n);
    assert.ok(
      !eddsa.verifyPoseidon(badMsg, rustSig, A),
      `vector ${i}: tampered message must be rejected`
    );

    checked++;
  }

  console.log(
    `OK: ${checked} babyjubjub-permissive vectors match circomlibjs ` +
      `byte-for-byte (pubkey + R8 + S) and cross-verify`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
