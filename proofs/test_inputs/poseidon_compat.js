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

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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
    return modField(BigInt(v));
  },
  toObject(v) {
    return modField(BigInt(v));
  },
  toString(v) {
    return modField(BigInt(v)).toString();
  },
};

function modField(n) {
  const r = n % BN254_R;
  return r < 0n ? r + BN254_R : r;
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

module.exports = { buildPoseidon };
