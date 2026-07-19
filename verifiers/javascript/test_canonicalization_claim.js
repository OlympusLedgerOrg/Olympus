// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("./circom_compat.js");

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CLAIM_HEX = [
  "4f4c5943414e3031",
  "000000000000002d",
  "000000000000001f",
  "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354",
  "6711dafbab9471037d55b746ffc7c810af1d5d9f384972498431044f166ddfed",
  "0100000000000000",
].join("");
const EXPECTED_CANONICAL_HASH =
  16060508666336680773438919255447306219275442759648167530745041862815015424516n;

function u64be(bytes) {
  return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

function bigintBe(bytes) {
  return u64be(bytes);
}

function decodeClaim(bytes) {
  assert.strictEqual(bytes.length, 96, "OLYCAN01 claim width");
  assert.strictEqual(bytes.subarray(0, 8).toString("ascii"), "OLYCAN01", "claim magic");
  const sourceLen = u64be(bytes.subarray(8, 16));
  const canonicalLen = u64be(bytes.subarray(16, 24));
  assert(sourceLen > 0n && sourceLen <= 1024n * 1024n, "bounded non-empty source");
  assert(canonicalLen > 0n && canonicalLen <= 1024n * 1024n, "bounded canonical output");
  assert.strictEqual(bytes[88], 1, "one-section receipt recipe");
  assert(
    bytes.subarray(89).every((byte) => byte === 0),
    "reserved bytes are zero",
  );
  return {
    sourceLen,
    canonicalLen,
    sourceCommitment: bytes.subarray(24, 56),
    canonicalDigest: bytes.subarray(56, 88),
  };
}

async function main() {
  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(
        __dirname,
        "..",
        "..",
        "proofs",
        "zkvm",
        "canonicalization",
        "receipt-fixture.json",
      ),
      "utf8",
    ),
  );
  assert.strictEqual(fixture.format, "olympus-canonicalization-receipt-fixture");
  assert.strictEqual(fixture.version, 1);
  assert.strictEqual(
    fixture.image_id,
    "4e608b9342f69440047a12bfbf83e26ec9f7d5746dc17c16a58c247185a17b47",
  );
  assert.strictEqual(fixture.journal_hex, CLAIM_HEX);

  const claim = decodeClaim(Buffer.from(fixture.journal_hex, "hex"));
  assert.strictEqual(claim.sourceLen, 45n);
  assert.strictEqual(claim.canonicalLen, 31n);
  assert.strictEqual(
    claim.sourceCommitment.toString("hex"),
    "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354",
  );

  const poseidon = await buildPoseidon();
  const field = (value) => BigInt(poseidon.F.toObject(value));
  const hash = (inputs) => field(poseidon(inputs));
  const domainHash = (left, right) => hash([hash([3n, left]), right]);
  const section = bigintBe(claim.canonicalDigest) % BN254_R;
  const realSectionHash = hash([section]);
  const paddingSectionHash = hash([0n]);

  let commitment = 1n;
  for (let slot = 0; slot < 8; slot += 1) {
    commitment = domainHash(commitment, slot === 0 ? claim.canonicalLen : 0n);
    commitment = domainHash(commitment, slot === 0 ? realSectionHash : paddingSectionHash);
  }
  assert.strictEqual(commitment, EXPECTED_CANONICAL_HASH);

  const malformed = Buffer.from(CLAIM_HEX, "hex");
  malformed[95] = 1;
  assert.throws(() => decodeClaim(malformed), /reserved bytes/);

  console.log("PASS  OLYCAN01 journal -> unified canonicalHash cross-language vector");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
