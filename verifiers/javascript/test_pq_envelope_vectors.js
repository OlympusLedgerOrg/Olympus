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
const REQUIRED_SIGNATURE_COMPONENTS = ["ed25519", "ml-dsa-65"];

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
  if (!Array.isArray(components)) throw new Error("invalid-signature-components");

  const counts = new Map();
  for (const component of components) {
    if (!REQUIRED_SIGNATURE_COMPONENTS.includes(component)) {
      throw new Error(`unknown-signature-component:${component}`);
    }
    counts.set(component, (counts.get(component) || 0) + 1);
  }

  for (const required of REQUIRED_SIGNATURE_COMPONENTS) {
    const count = counts.get(required) || 0;
    if (count === 0) throw new Error(`missing-required-signature:${required}`);
    if (count > 1) throw new Error(`duplicate-signature-component:${required}`);
  }

  if (components.length !== REQUIRED_SIGNATURE_COMPONENTS.length) {
    throw new Error("invalid-signature-component-count");
  }
  if (components.some((component, index) => component !== REQUIRED_SIGNATURE_COMPONENTS[index])) {
    throw new Error("non-canonical-signature-component-order");
  }
}

function encodeSignatureComponent(name) {
  const template = vectors.signature_section.components[name];
  if (!template) throw new Error(`unknown-signature-component:${name}`);
  return Buffer.concat(
    [
      utf8(template.algorithm_id),
      utf8(template.parameter_set),
      utf8(vectors.base[template.sender_key_id_field]),
      Buffer.alloc(template.signature_length, Number.parseInt(template.signature_byte, 16)),
    ].map(lp),
  );
}

function encodeSignatureSection(components) {
  return Buffer.concat([
    u16(components.length),
    ...components.map((component) => lp(encodeSignatureComponent(component))),
  ]);
}

function parseSignatureComponent(input) {
  const fields = [];
  let offset = 0;
  for (let index = 0; index < 4; index += 1) {
    const parsed = parseLp(input, offset);
    fields.push(parsed.value);
    offset = parsed.next;
  }
  if (offset !== input.length) throw new Error("extra-signature-component-data");

  for (const [name, template] of Object.entries(vectors.signature_section.components)) {
    if (
      fields[0].equals(utf8(template.algorithm_id)) &&
      fields[1].equals(utf8(template.parameter_set)) &&
      fields[2].equals(utf8(vectors.base[template.sender_key_id_field])) &&
      fields[3].length === template.signature_length
    ) {
      return name;
    }
  }
  throw new Error("unknown-or-malformed-signature-component");
}

function parseSignatureSection(input) {
  if (input.length < 2) throw new Error("truncated-signature-component-count");
  const count = input.readUInt16BE(0);
  const components = [];
  let offset = 2;
  for (let index = 0; index < count; index += 1) {
    const parsed = parseLp(input, offset);
    components.push(parseSignatureComponent(parsed.value));
    offset = parsed.next;
  }
  if (offset !== input.length) throw new Error("extra-signature-section-data");
  requireHybridSignatures(components);
  return components;
}

function validateSuiteDefinitions() {
  const fields = [
    "signature_suite_id",
    "kem_algorithm_id",
    "kem_parameter_set",
    "kdf_algorithm_id",
    "aead_algorithm_id",
  ];
  for (const suite of Object.values(vectors.suites)) {
    for (const field of fields) {
      assert.strictEqual(lp(utf8(suite[field])).toString("hex"), suite.canonical_lp_hex[field]);
    }
  }
  for (const field of fields) {
    assert.strictEqual(vectors.base[field], vectors.suites.normal[field]);
  }
  assert.strictEqual(vectors.signature_section.component_count, 2);
  assert.deepStrictEqual(vectors.signature_section.component_order, REQUIRED_SIGNATURE_COMPONENTS);
}

function emitExpectedValues() {
  const single = encode(1);
  const maximum = encode(64);
  const swapped = encode(1, "ml-kem-768:recipient:other:2026-07");
  const signatureSection = encodeSignatureSection(REQUIRED_SIGNATURE_COMPONENTS);
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
        signatureSection: {
          hash: hash(signatureSection),
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

validateSuiteDefinitions();

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
  } else if (vector.raw_unsigned_header_hex) {
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
  } else if (vector.expected === "accept:signature-section-framing") {
    const signatureSection = encodeSignatureSection(vector.signature_components);
    assert.deepStrictEqual(parseSignatureSection(signatureSection), REQUIRED_SIGNATURE_COMPONENTS);
    assert.strictEqual(hash(signatureSection), vector.expected_signature_section_blake3_hex);
  } else if (vector.raw_signature_section_hex || vector.signature_section_mutation) {
    let signatureSection = vector.raw_signature_section_hex
      ? hex(vector.raw_signature_section_hex)
      : encodeSignatureSection(vector.signature_components);
    if (vector.signature_section_mutation === "declare-one-component") {
      signatureSection = Buffer.from(signatureSection);
      signatureSection.writeUInt16BE(1, 0);
    } else if (vector.signature_section_mutation === "append-trailing-byte") {
      signatureSection = Buffer.concat([signatureSection, Buffer.from([0])]);
    } else if (vector.signature_section_mutation === "truncate-last-byte") {
      signatureSection = signatureSection.subarray(0, signatureSection.length - 1);
    }
    assert.throws(
      () => parseSignatureSection(signatureSection),
      new RegExp(vector.expected.slice(7)),
    );
  } else if (vector.signature_components) {
    assert.throws(
      () => requireHybridSignatures(vector.signature_components),
      new RegExp(vector.expected.slice(7)),
    );
  } else {
    assert.fail(`unhandled PQ envelope vector: ${vector.id}`);
  }
}

console.log(`PQ envelope vectors: ${vectors.vectors.length} cases passed`);
