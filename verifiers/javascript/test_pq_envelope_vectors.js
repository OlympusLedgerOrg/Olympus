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
const REQUIRED_SIGNATURE_COMPONENTS = {
  normal: ["ed25519", "ml-dsa-65"],
  high_assurance: ["ed25519", "ml-dsa-87"],
};

function suiteDefinition(suiteName) {
  const suite = vectors.suites[suiteName];
  if (!suite) throw new Error(`unsupported-suite:${suiteName}`);
  return suite;
}

function requiredSignatureComponents(suiteName) {
  const components = REQUIRED_SIGNATURE_COMPONENTS[suiteName];
  if (!components) throw new Error(`unsupported-suite:${suiteName}`);
  return components;
}

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

function recipient(index, swappedKemKeyId, suiteName) {
  const template = vectors.recipient_template;
  const suite = suiteDefinition(suiteName);
  const substitute = (value) => value.replace("{index}", String(index));
  const fields = [
    utf8(substitute(template.identity_id)),
    utf8(swappedKemKeyId || substitute(suite.recipient_kem_key_id)),
    Buffer.alloc(32, Number.parseInt(template.public_key_blake3_byte, 16)),
    Buffer.alloc(suite.kem_ciphertext_length, Number.parseInt(template.kem_ciphertext_byte, 16)),
    Buffer.alloc(24, Number.parseInt(template.aead_nonce_byte, 16)),
  ];
  return Buffer.concat(fields.map(lp));
}

function encode(recipientCount, swappedKemKeyId, suiteName = "normal") {
  const base = vectors.base;
  const suite = suiteDefinition(suiteName);
  const global = [
    vectors.wire_schema,
    base.protocol_version,
    suite.signature_suite_id,
    suite.kem_algorithm_id,
    suite.kem_parameter_set,
    suite.kdf_algorithm_id,
    suite.aead_algorithm_id,
    base.sender_identity_id,
    base.sender_ed25519_key_id,
    suite.sender_ml_dsa_key_id,
    base.object_id,
  ].map((field) => lp(utf8(field)));
  const headers = [];
  const ciphertexts = [];
  for (let index = 0; index < recipientCount; index += 1) {
    headers.push(lp(recipient(index, swappedKemKeyId, suiteName)));
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

function requireHybridSignatures(components, suiteName = "normal") {
  if (!Array.isArray(components)) throw new Error("invalid-signature-components");

  const requiredComponents = requiredSignatureComponents(suiteName);
  const counts = new Map();
  for (const component of components) {
    if (!requiredComponents.includes(component)) {
      throw new Error(`unknown-signature-component:${component}`);
    }
    counts.set(component, (counts.get(component) || 0) + 1);
  }

  for (const required of requiredComponents) {
    const count = counts.get(required) || 0;
    if (count === 0) throw new Error(`missing-required-signature:${required}`);
    if (count > 1) throw new Error(`duplicate-signature-component:${required}`);
  }

  if (components.some((component, index) => component !== requiredComponents[index])) {
    throw new Error("non-canonical-signature-component-order");
  }
}

function senderKeyId(field, suiteName) {
  if (field === "sender_ml_dsa_key_id") return suiteDefinition(suiteName).sender_ml_dsa_key_id;
  const keyId = vectors.base[field];
  if (typeof keyId !== "string") throw new Error(`unknown-sender-key-id-field:${field}`);
  return keyId;
}

function encodeSignatureComponent(name, suiteName) {
  const template = vectors.signature_section.components[name];
  if (!template) throw new Error(`unknown-signature-component:${name}`);
  return Buffer.concat(
    [
      utf8(template.algorithm_id),
      utf8(template.parameter_set),
      utf8(senderKeyId(template.sender_key_id_field, suiteName)),
      Buffer.alloc(template.signature_length, Number.parseInt(template.signature_byte, 16)),
    ].map(lp),
  );
}

function encodeSignatureSection(components, suiteName = "normal") {
  return Buffer.concat([
    u16(components.length),
    ...components.map((component) => lp(encodeSignatureComponent(component, suiteName))),
  ]);
}

// Validates signature-component wire framing, metadata, and expected signature
// length only. Static vector signatures are framing fillers; this does not
// verify or imply Ed25519 or ML-DSA authenticity.
function parseSignatureComponent(input, suiteName) {
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
      fields[2].equals(utf8(senderKeyId(template.sender_key_id_field, suiteName))) &&
      fields[3].length === template.signature_length
    ) {
      return name;
    }
  }
  throw new Error("unknown-or-malformed-signature-component");
}

function parseSignatureSection(input, suiteName = "normal") {
  if (input.length < 2) throw new Error("truncated-signature-component-count");
  const count = input.readUInt16BE(0);
  const components = [];
  let offset = 2;
  for (let index = 0; index < count; index += 1) {
    const parsed = parseLp(input, offset);
    components.push(parseSignatureComponent(parsed.value, suiteName));
    offset = parsed.next;
  }
  if (offset !== input.length) throw new Error("extra-signature-section-data");
  requireHybridSignatures(components, suiteName);
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
  for (const [suiteName, suite] of Object.entries(vectors.suites)) {
    for (const field of fields) {
      assert.strictEqual(lp(utf8(suite[field])).toString("hex"), suite.canonical_lp_hex[field]);
    }
    assert.deepStrictEqual(
      vectors.signature_section.component_order[suiteName],
      requiredSignatureComponents(suiteName),
    );
  }
  for (const field of fields) {
    assert.strictEqual(vectors.base[field], vectors.suites.normal[field]);
  }
  assert.strictEqual(vectors.signature_section.component_count, 2);
  assert.strictEqual(vectors.base.sender_ml_dsa_key_id, vectors.suites.normal.sender_ml_dsa_key_id);
  assert.strictEqual(
    vectors.recipient_template.kem_key_id,
    vectors.suites.normal.recipient_kem_key_id,
  );
}

function emitExpectedValues() {
  const single = encode(1);
  const maximum = encode(64);
  const swapped = encode(1, "ml-kem-768:recipient:other:2026-07");
  const signatureSection = encodeSignatureSection(requiredSignatureComponents("normal"));
  const highSingle = encode(1, undefined, "high_assurance");
  const highMaximum = encode(64, undefined, "high_assurance");
  const highSignatureSection = encodeSignatureSection(
    requiredSignatureComponents("high_assurance"),
    "high_assurance",
  );
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
        highAssurance: {
          single: {
            headerHash: hash(highSingle.unsignedHeader),
            bodyHash: hash(highSingle.ciphertextBody),
            digest: signedDigest(highSingle.unsignedHeader, highSingle.ciphertextBody),
          },
          maximum: {
            headerHash: hash(highMaximum.unsignedHeader),
            bodyHash: hash(highMaximum.ciphertextBody),
            digest: signedDigest(highMaximum.unsignedHeader, highMaximum.ciphertextBody),
          },
          signatureSectionHash: hash(highSignatureSection),
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
  const suiteName = vector.suite || "normal";
  if (vector.expected === "accept") {
    const encoded = encode(vector.recipient_count, undefined, suiteName);
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
    const original = encode(vector.recipient_count, undefined, suiteName);
    const swapped = encode(vector.recipient_count, vector.swap_recipient_kem_key_id, suiteName);
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
    const signatureSection = encodeSignatureSection(vector.signature_components, suiteName);
    assert.deepStrictEqual(
      parseSignatureSection(signatureSection, suiteName),
      requiredSignatureComponents(suiteName),
    );
    assert.strictEqual(hash(signatureSection), vector.expected_signature_section_blake3_hex);
  } else if (vector.raw_signature_section_hex || vector.signature_section_mutation) {
    let signatureSection = vector.raw_signature_section_hex
      ? hex(vector.raw_signature_section_hex)
      : encodeSignatureSection(vector.signature_components, suiteName);
    if (vector.signature_section_mutation === "declare-one-component") {
      signatureSection = Buffer.from(signatureSection);
      signatureSection.writeUInt16BE(1, 0);
    } else if (vector.signature_section_mutation === "append-trailing-byte") {
      signatureSection = Buffer.concat([signatureSection, Buffer.from([0])]);
    } else if (vector.signature_section_mutation === "truncate-last-byte") {
      signatureSection = signatureSection.subarray(0, signatureSection.length - 1);
    }
    assert.throws(
      () => parseSignatureSection(signatureSection, suiteName),
      new RegExp(vector.expected.slice(7)),
    );
  } else if (vector.signature_components) {
    assert.throws(
      () => requireHybridSignatures(vector.signature_components, suiteName),
      new RegExp(vector.expected.slice(7)),
    );
  } else {
    assert.fail(`unhandled PQ envelope vector: ${vector.id}`);
  }
}

console.log(`PQ envelope vectors: ${vectors.vectors.length} cases passed`);
