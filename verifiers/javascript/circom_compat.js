// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

"use strict";

const {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} = require("poseidon-lite");
const { blake512 } = require("@noble/hashes/blake1.js");

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BJJ_L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const BJJ_A = 168700n;
const BJJ_D = 168696n;
const BJJ_BASE8 = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];

const POSEIDON = [
  null,
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
];

const F = {
  e(v) {
    return modP(BigInt(v));
  },
  toObject(v) {
    return modP(BigInt(v));
  },
  toString(v) {
    return modP(BigInt(v)).toString();
  },
};

function modP(n) {
  const r = n % BN254_R;
  return r < 0n ? r + BN254_R : r;
}

function modL(n) {
  const r = n % BJJ_L;
  return r < 0n ? r + BJJ_L : r;
}

function invP(n) {
  return powP(modP(n), BN254_R - 2n);
}

function powP(base, exp) {
  let b = modP(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % BN254_R;
    b = (b * b) % BN254_R;
    e >>= 1n;
  }
  return r;
}

function bjjAdd(P, Q) {
  const x1 = modP(P[0]);
  const y1 = modP(P[1]);
  const x2 = modP(Q[0]);
  const y2 = modP(Q[1]);
  const beta = (x1 * y2) % BN254_R;
  const gamma = (y1 * x2) % BN254_R;
  const delta = modP((y1 - BJJ_A * x1) * (x2 + y2));
  const tau = (beta * gamma) % BN254_R;
  const dtau = (BJJ_D * tau) % BN254_R;
  const x3 = modP((beta + gamma) * invP(1n + dtau));
  const y3 = modP((delta + BJJ_A * beta - gamma) * invP(1n - dtau));
  return [x3, y3];
}

function bjjMulUnbounded(P, scalar) {
  let e = BigInt(scalar);
  if (e < 0n) throw new Error("negative Baby Jubjub scalar");
  let result = [0n, 1n];
  let base = [modP(P[0]), modP(P[1])];
  while (e > 0n) {
    if (e & 1n) result = bjjAdd(result, base);
    base = bjjAdd(base, base);
    e >>= 1n;
  }
  return result;
}

function bjjOnCurve(P) {
  if (!Array.isArray(P) || P.length !== 2) return false;
  const x = modP(P[0]);
  const y = modP(P[1]);
  const x2 = (x * x) % BN254_R;
  const y2 = (y * y) % BN254_R;
  return modP(BJJ_A * x2 + y2 - 1n - modP(BJJ_D * x2 * y2)) === 0n;
}

function poseidon(inputs) {
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length >= POSEIDON.length) {
    throw new Error(`Poseidon arity ${Array.isArray(inputs) ? inputs.length : "?"} is unsupported`);
  }
  return F.e(POSEIDON[inputs.length](inputs.map((v) => F.e(v))));
}

poseidon.F = F;

async function buildPoseidon() {
  return poseidon;
}

function pruneBuffer(hash) {
  const out = Uint8Array.from(hash);
  out[0] &= 0xf8;
  out[31] &= 0x7f;
  out[31] |= 0x40;
  return out;
}

function leBytesToBigInt(bytes) {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) acc = (acc << 8n) | BigInt(bytes[i]);
  return acc;
}

function fieldTo32LE(v) {
  let x = F.e(v);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

class Eddsa {
  constructor() {
    this.F = F;
  }

  prv2pub(prv) {
    if (!(prv instanceof Uint8Array || Buffer.isBuffer(prv)) || prv.length !== 32) {
      throw new Error("prv2pub expects a 32-byte private key");
    }
    const sBuff = pruneBuffer(blake512(prv));
    const scalarPre = leBytesToBigInt(sBuff.slice(0, 32));
    return bjjMulUnbounded(BJJ_BASE8, scalarPre >> 3n);
  }

  signPoseidon(prv, msg) {
    if (!(prv instanceof Uint8Array || Buffer.isBuffer(prv)) || prv.length !== 32) {
      throw new Error("signPoseidon expects a 32-byte private key");
    }
    const sBuff = pruneBuffer(blake512(prv));
    const scalarPre = leBytesToBigInt(sBuff.slice(0, 32));
    const A = bjjMulUnbounded(BJJ_BASE8, scalarPre >> 3n);
    const rInput = concatBytes(sBuff.slice(32, 64), fieldTo32LE(msg));
    const r = leBytesToBigInt(blake512(rInput)) % BJJ_L;
    const R8 = bjjMulUnbounded(BJJ_BASE8, r);
    const hm = poseidon([R8[0], R8[1], A[0], A[1], msg]);
    const S = modL(r + hm * scalarPre);
    return { R8, S };
  }

  verifyPoseidon(msg, sig, A) {
    if (typeof sig !== "object" || sig === null) return false;
    if (!Array.isArray(sig.R8) || sig.R8.length !== 2) return false;
    if (!bjjOnCurve(sig.R8)) return false;
    if (!Array.isArray(A) || A.length !== 2) return false;
    if (!bjjOnCurve(A)) return false;
    const S = BigInt(sig.S);
    if (S < 0n || S >= BJJ_L) return false;

    const hm = poseidon([sig.R8[0], sig.R8[1], A[0], A[1], msg]);
    const left = bjjMulUnbounded(BJJ_BASE8, S);
    const right = bjjAdd(sig.R8, bjjMulUnbounded(A, hm * 8n));
    return F.e(left[0]) === F.e(right[0]) && F.e(left[1]) === F.e(right[1]);
  }
}

async function buildEddsa() {
  return new Eddsa();
}

module.exports = {
  buildEddsa,
  buildPoseidon,
};
