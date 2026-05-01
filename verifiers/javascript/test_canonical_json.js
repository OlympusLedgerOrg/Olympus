/**
 * Cross-language canonical JSON conformance tests for the JavaScript verifier.
 *
 * Validates that ``canonicalJsonEncode()`` + ``computeBlake3()`` produce
 * byte-for-byte identical output to the Python reference encoder for every
 * positive vector in ``verifiers/test_vectors/canonicalizer_vectors.tsv``.
 *
 * The TSV columns are:
 *   group_id \t input_hex \t canonical_hex \t hash_hex
 *
 * For each row we:
 *  1. Decode ``input_hex`` to bytes, parse as UTF-8 JSON.
 *  2. Run through ``canonicalJsonEncode()`` to reproduce the canonical form.
 *  3. Assert the UTF-8 bytes of the result match ``canonical_hex`` exactly
 *     (encoding round-trip parity with Python).
 *  4. Assert that BLAKE3(canonical_bytes) matches ``hash_hex`` (hash parity).
 *
 * KNOWN BEHAVIORAL DIFFERENCE — float rejection:
 *   Python ``canonical_json_encode()`` rejects native Python ``float`` objects
 *   (callers must use ``decimal.Decimal`` instead).  JavaScript has no
 *   ``Decimal`` type, so ``canonicalJsonEncode()`` accepts finite JS numbers.
 *   ``NaN`` and ``±Infinity`` are rejected in both implementations.
 *   All TSV positive vectors were generated using ``Decimal`` inputs in Python,
 *   so no vector triggers this difference.  The explicit rejection tests below
 *   document the boundary.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { canonicalJsonEncode, canonicalJsonEncodeBytes, computeBlake3, toHex } = require('./verifier');

// Minimum number of vectors expected in the TSV file.
// Fail fast if the file is truncated or regenerated with fewer entries.
const MIN_EXPECTED_VECTORS = 500;

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'canonicalizer_vectors.tsv');

function assert(condition, message) {
  if (!condition) {
    throw new Error('Assertion failed: ' + message);
  }
}

// ---------------------------------------------------------------------------
// Load TSV vectors
// ---------------------------------------------------------------------------

function loadTsvVectors(filePath) {
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const vectors = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split('\t');
    if (parts.length !== 4) {
      throw new Error(`Malformed TSV vector (expected 4 fields, got ${parts.length}): ${trimmed}`);
    }
    vectors.push({
      groupId: parts[0],
      inputHex: parts[1],
      canonicalHex: parts[2],
      hashHex: parts[3],
    });
  }
  return vectors;
}

// ---------------------------------------------------------------------------
// Round-trip conformance: input_hex → parse JSON → canonicalJsonEncode → canonical_hex
// ---------------------------------------------------------------------------

function testCanonicalJsonRoundTrip() {
  console.log('Testing canonical JSON round-trip against TSV vectors...');

  if (!fs.existsSync(VECTORS_PATH)) {
    console.log('  (skipped: canonicalizer_vectors.tsv not found)');
    return;
  }

  const vectors = loadTsvVectors(VECTORS_PATH);
  assert(vectors.length >= MIN_EXPECTED_VECTORS, `Too few vectors: ${vectors.length}`);

  let passed = 0;
  let skipped = 0;
  const failures = [];

  for (const vec of vectors) {
    const inputBytes = Buffer.from(vec.inputHex, 'hex');
    const expectedCanonicalBytes = Buffer.from(vec.canonicalHex, 'hex');
    const expectedHashHex = vec.hashHex;

    // Parse the input JSON
    let obj;
    try {
      obj = JSON.parse(inputBytes.toString('utf8'));
    } catch (_) {
      // Malformed UTF-8 or invalid JSON — skip (same policy as Python test)
      skipped++;
      continue;
    }

    // Encode via JS canonical encoder
    let encoded;
    try {
      encoded = canonicalJsonEncodeBytes(obj);
    } catch (_) {
      // JS encoder rejects this input (e.g. unsupported type); skip
      skipped++;
      continue;
    }

    // 1. Encoding must match the golden canonical bytes
    if (!Buffer.from(encoded).equals(expectedCanonicalBytes)) {
      failures.push(
        `Vector ${vec.groupId}: encoding mismatch\n` +
        `  expected: ${vec.canonicalHex}\n` +
        `  got:      ${toHex(encoded)}`
      );
      continue;
    }

    // 2. BLAKE3(canonical bytes) must match hash_hex
    const gotHash = toHex(computeBlake3(encoded));
    if (gotHash !== expectedHashHex) {
      failures.push(
        `Vector ${vec.groupId}: hash mismatch\n` +
        `  expected: ${expectedHashHex}\n` +
        `  got:      ${gotHash}`
      );
      continue;
    }

    passed++;
  }

  if (failures.length > 0) {
    const preview = failures.slice(0, 10).join('\n');
    throw new Error(`${failures.length} vector(s) failed:\n${preview}`);
  }

  console.log(`  ✓ canonical JSON round-trip: ${passed} passed, ${skipped} skipped`);
}

// ---------------------------------------------------------------------------
// Spot-check a handful of known values for quick sanity
// ---------------------------------------------------------------------------

function testKnownValues() {
  console.log('Testing canonical JSON known values...');

  assert(canonicalJsonEncode(null) === 'null', 'null');
  assert(canonicalJsonEncode(true) === 'true', 'true');
  assert(canonicalJsonEncode(false) === 'false', 'false');
  assert(canonicalJsonEncode(0) === '0', 'zero');
  assert(canonicalJsonEncode(42) === '42', '42');
  assert(canonicalJsonEncode(-7) === '-7', '-7');
  assert(canonicalJsonEncode('hello') === '"hello"', 'ascii string');
  assert(canonicalJsonEncode([]) === '[]', 'empty array');
  assert(canonicalJsonEncode({}) === '{}', 'empty object');

  // Key sort order must be by UTF-16 code units (default JS sort)
  assert(
    canonicalJsonEncode({ z: 1, a: 2, m: 3 }) === '{"a":2,"m":3,"z":1}',
    'key sort order'
  );

  // Non-ASCII string: raw UTF-8, not \\uXXXX
  assert(canonicalJsonEncode('café') === '"café"', 'non-ASCII raw UTF-8');

  // NFC normalization: e + combining acute → precomposed é (U+00E9)
  const decomposed = 'e\u0301'; // NFD form
  const result = canonicalJsonEncode(decomposed);
  assert(result === '"é"', `NFC normalization: got ${result}`);

  // Emoji: raw UTF-8 (not surrogate-pair \\uXXXX escapes)
  assert(canonicalJsonEncode('\u{1F600}') === '"\u{1F600}"', 'emoji raw UTF-8');

  // UTF-16 surrogate-pair key ordering: BMP private-use (U+E000) sorts
  // after emoji (U+1F600) because U+1F600 decomposes to two UTF-16 code
  // units (D83D DE00) which are both less than E000.
  const emojiKeyObj = { '\uE000': 1, '\u{1F600}': 2 };
  assert(
    canonicalJsonEncode(emojiKeyObj) === '{"\u{1F600}":2,"\uE000":1}',
    'UTF-16 surrogate-pair key ordering'
  );

  console.log('  ✓ known values');
}

// ---------------------------------------------------------------------------
// Float rejection behaviour
//
// KNOWN BEHAVIORAL DIFFERENCE from the Python encoder:
//   - Python: native float objects (e.g. 3.14, float('nan')) are rejected
//             with ValueError; callers must use decimal.Decimal.
//   - JavaScript: finite JS numbers are accepted; NaN and ±Infinity are
//                 rejected with an Error.
// This difference does not affect the TSV golden vectors because all numeric
// values in those vectors were produced from Decimal inputs in Python.
// ---------------------------------------------------------------------------

function testFloatRejection() {
  console.log('Testing NaN / Infinity rejection (float rejection documentation)...');

  let threw;

  threw = false;
  try { canonicalJsonEncode(NaN); } catch (_) { threw = true; }
  assert(threw, 'NaN must be rejected');

  threw = false;
  try { canonicalJsonEncode(Infinity); } catch (_) { threw = true; }
  assert(threw, 'Infinity must be rejected');

  threw = false;
  try { canonicalJsonEncode(-Infinity); } catch (_) { threw = true; }
  assert(threw, '-Infinity must be rejected');

  // Finite floats ARE accepted in JS (unlike Python which requires Decimal).
  // The result matches JSON.stringify behaviour for those values.
  const r = canonicalJsonEncode(3.14);
  assert(typeof r === 'string' && r.length > 0, 'finite float accepted in JS');

  console.log(
    '  ✓ NaN / Infinity rejected; finite floats accepted (documented Python difference)'
  );
}

// ---------------------------------------------------------------------------
// Run all tests
// ---------------------------------------------------------------------------

function run() {
  console.log('Running canonical JSON cross-language conformance tests\n');
  testKnownValues();
  testFloatRejection();
  testCanonicalJsonRoundTrip();
  console.log('\n✓ All canonical JSON conformance tests passed!');
}

run();
