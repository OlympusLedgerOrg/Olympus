/**
 * Baby Jubjub Pedersen commitments for the in-browser redaction auditor (ADR-0026).
 *
 * Browser-pure ESM port of the Pedersen subset of
 * `verifiers/javascript/verifier.js` (which is itself a port of the canonical
 * Rust `src-tauri/src/zk/pedersen.rs` built on the Apache-2.0
 * `babyjubjub-permissive` crate). Used to recompute hiding redaction leaves
 * `Poseidon(C.x, C.y)` where `C = m·G + r·H` on the Baby Jubjub prime-order
 * subgroup — the auditor-side half of the lockstep JS↔Rust conformance
 * fixture pinned in `verifiers/test_vectors/redaction_vectors.json` and the
 * Vitest `redactionBinding.conformance.test.ts`.
 *
 * Curve: twisted Edwards `a·x² + y² = 1 + d·x²·y²` over BN254 Fr.
 * Generators: `G` is the circomlib B8 base point; `H` is the NUMS generator
 * derived from `OLY:PEDERSEN:H:V1` (the H coordinates below are pinned
 * outputs of that derivation in `src-tauri/src/zk/pedersen.rs` — recomputing
 * them on every browser load would be 10⁵× slower for zero security benefit).
 *
 * Scalars `m`, `r` are reduced mod `l` (the subgroup order). The Rust API
 * rejects out-of-range instead, but a recompute-and-compare verifier with
 * already-canonical scalars (the bundle's `blindingDecimal`) is equivalent.
 */
/** BN254 base field modulus. */
export const BJJ_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Twisted-Edwards `a` coefficient. */
const BJJ_A = 168700n;
/** Twisted-Edwards `d` coefficient. */
const BJJ_D = 168696n;
/** Prime-order subgroup order — scalars live in `[0, BJJ_L)`. */
export const BJJ_L =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
/** circomlib B8 base point. */
const BJJ_G = {
  x: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
};
/** NUMS generator H, pinned from `OLY:PEDERSEN:H:V1` per ADR-0005. */
const BJJ_H = {
  x: 198588470289489729947397318629051280907399291050874530267072873208967148441n,
  y: 19238664506574355524861866424113858387196810277823508736174698680331927248315n,
};

export interface BjjPoint {
  x: bigint;
  y: bigint;
}

function modP(n: bigint): bigint {
  const r = n % BJJ_P;
  return r < 0n ? r + BJJ_P : r;
}

function powP(base: bigint, exp: bigint): bigint {
  let b = modP(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % BJJ_P;
    b = (b * b) % BJJ_P;
    e >>= 1n;
  }
  return r;
}

/** Modular inverse via Fermat (BJJ_P is prime). */
function invP(n: bigint): bigint {
  return powP(modP(n), BJJ_P - 2n);
}

/** Twisted-Edwards point addition (unified + complete on Baby Jubjub). */
export function bjjAdd(P: BjjPoint, Q: BjjPoint): BjjPoint {
  const x1y2 = (P.x * Q.y) % BJJ_P;
  const x2y1 = (Q.x * P.y) % BJJ_P;
  const y1y2 = (P.y * Q.y) % BJJ_P;
  const x1x2 = (P.x * Q.x) % BJJ_P;
  const dxy = modP(((BJJ_D * x1x2) % BJJ_P) * y1y2);
  const x3 = modP((x1y2 + x2y1) * invP(1n + dxy));
  const y3 = modP((y1y2 - BJJ_A * x1x2) * invP(1n - dxy));
  return { x: x3, y: y3 };
}

/** Scalar mul `k·P` via right-to-left double-and-add. Reduces `k` mod `BJJ_L`. */
export function bjjMul(P: BjjPoint, k: bigint): BjjPoint {
  let R: BjjPoint = { x: 0n, y: 1n }; // identity (twisted Edwards)
  let base = P;
  let e = ((k % BJJ_L) + BJJ_L) % BJJ_L;
  while (e > 0n) {
    if (e & 1n) R = bjjAdd(R, base);
    base = bjjAdd(base, base);
    e >>= 1n;
  }
  return R;
}

/**
 * Pedersen commitment `C = m·G + r·H` on Baby Jubjub. Both scalars are
 * reduced mod `BJJ_L`; the Rust auditor path rejects out-of-range scalars
 * but the auditor only sees already-canonical bundle blindings.
 */
export function pedersenCommit(m: bigint, r: bigint): BjjPoint {
  return bjjAdd(bjjMul(BJJ_G, m), bjjMul(BJJ_H, r));
}

/** Convert a big-endian byte slice into a BigInt. */
export function bytesBEToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}
