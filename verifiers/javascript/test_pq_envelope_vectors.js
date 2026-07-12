// SPDX-License-Identifier: Apache-2.0

// ADR-0038 wire-format conformance test.  This deliberately verifies only
// framing and signed-byte construction: no experimental PQ primitive is
// linked into the verifier yet.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { blake3 } = require("@noble/hashes/blake3.js");

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../test_vectors/pq_envelope_v1.json"), "utf8"),
);
const utf8 = (value) => Buffer.from(value, "utf8");
const hex = (value) => Buffer.from(value, "hex");
const hash = (value) => Buffer.from(blake3(value)).toString("hex");

function lp(value) {
  const data = Buffer.from(value);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(data.length);
  return Buffer.concat([prefix, data]);
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function recipient(index, swappedKemKeyId) {
  const template = vectors.recipient_template;
  const substitute = (value) => value.replace("{index}", String(index));
  const fields = [
    utf8(substitute(template.identity_id)),
    utf8(swappedKemKeyId || substitute(template.kem_key_id)),
    Buffer.alloc(32, Number.parseInt(template.public_key_blake3_byte, 16)),
    Buffer.alloc(1088, Number.parseInt(template.kem_ciphertext_byte, 16)),
    Buffer.alloc(24, Number.parseInt(template.aead_nonce_byte, 16)),
  ];
  return Buffer.concat(fields.map(lp));
}

function encode(recipientCount, swappedKemKeyId) {
  const base = vectors.base;
  const global = [
    vectors.wire_schema,
    base.protocol_version,
    base.signature_suite_id,
    base.kem_algorithm_id,
    base.kem_parameter_set,
    base.kdf_algorithm_id,
    base.aead_algorithm_id,
    base.sender_identity_id,
    base.sender_ed25519_key_id,
    base.sender_ml_dsa_key_id,
    base.object_id,
  ].map((field) => lp(utf8(field)));
  const headers = [];
  const ciphertexts = [];
  for (let index = 0; index < recipientCount; index += 1) {
    headers.push(lp(recipient(index, swappedKemKeyId)));
    ciphertexts.push(
      lp(
        Buffer.alloc(
          48,
          Number.parseInt(vectors.recipient_template.aead_ciphertext_and_tag_byte, 16),
        ),
      ),
    );
  }
  return {
    unsignedHeader: Buffer.concat([...global, u16(recipientCount), ...headers]),
    ciphertextBody: Buffer.concat([u16(recipientCount), ...ciphertexts]),
  };
}

function signedDigest(unsignedHeader, ciphertextBody) {
  return hash(
    Buffer.concat([utf8(vectors.signature_prefix_utf8), lp(unsignedHeader), lp(ciphertextBody)]),
  );
}

function parseLp(input, offset) {
  if (offset + 4 > input.length) throw new Error("truncated-length-prefix");
  const length = input.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (end > input.length) throw new Error("length-prefix-overrun");
  return { value: input.subarray(start, end), next: end };
}

function validateRecipientCount(count) {
  if (count < 1 || count > 64) throw new Error("recipient-count-out-of-range");
}

function requireHybridSignatures(components) {
  for (const required of ["ed25519", "ml-dsa-65"]) {
    if (!components.includes(required)) throw new Error(`missing-required-signature:${required}`);
  }
}

function emitExpectedValues() {
  const single = encode(1);
  const maximum = encode(64);
  const swapped = encode(1, "ml-kem-768:recipient:other:2026-07");
  console.log(
    JSON.stringify(
      {
        single: {
          headerHash: hash(single.unsignedHeader),
          bodyHash: hash(single.ciphertextBody),
          digest: signedDigest(single.unsignedHeader, single.ciphertextBody),
        },
        maximum: {
          headerHash: hash(maximum.unsignedHeader),
          bodyHash: hash(maximum.ciphertextBody),
          digest: signedDigest(maximum.unsignedHeader, maximum.ciphertextBody),
        },
        swapped: {
          original: signedDigest(single.unsignedHeader, single.ciphertextBody),
          changed: signedDigest(swapped.unsignedHeader, swapped.ciphertextBody),
        },
      },
      null,
      2,
    ),
  );
}

if (process.argv.includes("--emit")) {
  emitExpectedValues();
  process.exit(0);
}

for (const vector of vectors.vectors) {
  if (vector.expected === "accept") {
    const encoded = encode(vector.recipient_count);
    assert.strictEqual(hash(encoded.unsignedHeader), vector.expected_unsigned_header_blake3_hex);
    assert.strictEqual(hash(encoded.ciphertextBody), vector.expected_ciphertext_body_blake3_hex);
    assert.strictEqual(
      signedDigest(encoded.unsignedHeader, encoded.ciphertextBody),
      vector.expected_signed_digest_hex,
    );
  } else if (vector.expected.includes("recipient-count-out-of-range")) {
    assert.throws(
      () => validateRecipientCount(vector.recipient_count),
      /recipient-count-out-of-range/,
    );
  } else if (vector.expected.includes("length-prefix")) {
    assert.throws(
      () => parseLp(hex(vector.raw_unsigned_header_hex), 0),
      new RegExp(vector.expected.slice(7)),
    );
  } else if (vector.expected === "reject:signature-digest-mismatch") {
    const original = encode(vector.recipient_count);
    const swapped = encode(vector.recipient_count, vector.swap_recipient_kem_key_id);
    assert.strictEqual(
      signedDigest(original.unsignedHeader, original.ciphertextBody),
      vector.expected_original_signed_digest_hex,
    );
    assert.strictEqual(
      signedDigest(swapped.unsignedHeader, swapped.ciphertextBody),
      vector.expected_swapped_signed_digest_hex,
    );
    assert.notStrictEqual(
      vector.expected_original_signed_digest_hex,
      vector.expected_swapped_signed_digest_hex,
    );
  } else if (vector.expected.includes("missing-required-signature")) {
    assert.throws(
      () => requireHybridSignatures(vector.signature_components),
      /missing-required-signature:ml-dsa-65/,
    );
  }
}

console.log(`PQ envelope vectors: ${vectors.vectors.length} cases passed`);
