/**
 * Conformance tests for the Olympus JavaScript verifier.
 *
 * Validates that this implementation produces outputs matching the committed
 * test vectors in verifiers/test_vectors/vectors.json (generated from the
 * Python reference implementation).
 */

const path = require('path');
const fs = require('fs');
const {
  computeBlake3,
  toHex,
  fromHex,
  merkleLeafHash,
  merkleParentHash,
  computeMerkleRoot,
  verifyMerkleProof,
  computeLedgerEntryHash,
  computeDualCommitment,
  SMT_EMPTY_LEAF,
  smtLeafHash,
  verifySmtInclusion,
  verifySmtNonInclusion,
} = require('./verifier');

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'vectors.json');
const CANONICALIZER_VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'canonicalizer_vectors.tsv');

function assert(condition, message) {
  if (!condition) {
    throw new Error('Assertion failed: ' + message);
  }
}

function loadVectors() {
  return JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
}

function loadCanonicalizerVectors() {
  return fs.readFileSync(CANONICALIZER_VECTORS_PATH, 'utf8')
    .split('\n')
    .filter(line => line && !line.startsWith('#'))
    .map(line => {
      const [groupId, inputHex, canonicalHex, hash] = line.split('\t');
      return {
        groupId,
        inputHex,
        canonicalBytes: Buffer.from(canonicalHex, 'hex'),
        hash,
      };
    });
}

function testBlake3Raw(vectors) {
  console.log('Testing conformance: blake3_raw...');
  for (const vec of vectors.blake3_raw) {
    const data = new TextEncoder().encode(vec.input_utf8);
    const got = toHex(computeBlake3(data));
    assert(got === vec.hash, `blake3_raw(${JSON.stringify(vec.input_utf8)}): got ${got}, want ${vec.hash}`);
  }
  console.log(`  ✓ blake3_raw: ${vectors.blake3_raw.length} vectors`);
}

function testMerkleLeafHash(vectors) {
  console.log('Testing conformance: merkle_leaf_hash...');
  for (const vec of vectors.merkle_leaf_hash) {
    const data = new TextEncoder().encode(vec.input_utf8);
    const got = toHex(merkleLeafHash(data));
    assert(got === vec.hash, `merkle_leaf_hash(${JSON.stringify(vec.input_utf8)}): got ${got}, want ${vec.hash}`);
  }
  console.log(`  ✓ merkle_leaf_hash: ${vectors.merkle_leaf_hash.length} vectors`);
}

function testMerkleParentHash(vectors) {
  console.log('Testing conformance: merkle_parent_hash...');
  for (const vec of vectors.merkle_parent_hash) {
    const left = fromHex(vec.left_hash);
    const right = fromHex(vec.right_hash);
    const got = toHex(merkleParentHash(left, right));
    assert(got === vec.parent_hash, `merkle_parent_hash: got ${got}, want ${vec.parent_hash}`);
  }
  console.log(`  ✓ merkle_parent_hash: ${vectors.merkle_parent_hash.length} vectors`);
}

function testMerkleRoot(vectors) {
  console.log('Testing conformance: merkle_root...');
  for (const vec of vectors.merkle_root) {
    const leaves = vec.leaves_utf8.map(s => new TextEncoder().encode(s));
    const got = computeMerkleRoot(leaves);
    assert(got === vec.root, `merkle_root(${JSON.stringify(vec.leaves_utf8)}): got ${got}, want ${vec.root}`);
  }
  console.log(`  ✓ merkle_root: ${vectors.merkle_root.length} vectors`);
}

function testMerkleProof(vectors) {
  console.log('Testing conformance: merkle_proof...');
  for (const vec of vectors.merkle_proof) {
    const proof = {
      leafHash: fromHex(vec.leaf_hash),
      siblings: vec.siblings.map(s => ({ hash: s.hash, position: s.position })),
      rootHash: vec.root_hash,
    };
    const got = verifyMerkleProof(proof);
    assert(
      got === vec.expected_valid,
      `merkle_proof verify (${vec.description}): got ${got}, want ${vec.expected_valid}`
    );
  }
  console.log(`  ✓ merkle_proof: ${vectors.merkle_proof.length} vectors`);
}

function testCanonicalizerHash(vectors) {
  console.log('Testing conformance: canonicalizer_hash...');
  assert(vectors.length >= 500, `canonicalizer_hash vector count too small: ${vectors.length}`);
  for (const vec of vectors) {
    const got = toHex(computeBlake3(vec.canonicalBytes));
    assert(got === vec.hash, `canonicalizer_hash(${vec.groupId}): got ${got}, want ${vec.hash}`);
  }
  console.log(`  ✓ canonicalizer_hash: ${vectors.length} vectors`);
}

function testLedgerEntryHash(vectors) {
  console.log('Testing conformance: ledger_entry_hash...');
  for (const vec of vectors.ledger_entry_hash) {
    const payloadBytes = Buffer.from(vec.canonical_payload_hex, 'hex');
    const got = toHex(computeLedgerEntryHash(payloadBytes));
    assert(got === vec.entry_hash, `ledger_entry_hash(${JSON.stringify(vec.description)}): got ${got}, want ${vec.entry_hash}`);
  }
  console.log(`  ✓ ledger_entry_hash: ${vectors.ledger_entry_hash.length} vectors`);
}

/**
 * Validate dual-root commitment vectors.
 *
 * For each vector this test:
 * 1. Recomputes the BLAKE3 Merkle root from document_parts_utf8 and checks it
 *    matches blake3_root iff expected_blake3_consistent is true.
 * 2. Recomputes the dual_commitment from the stored blake3_root + poseidon_root
 *    and verifies it matches the committed dual_commitment value.
 * 3. If a blake3_proof is present, verifies it is valid against the stored root.
 *
 * Note: Poseidon root consistency (expected_valid) is only checked by the Python
 * conformance test which has access to the full Poseidon hash implementation.
 */
function testDualRootCommitment(vectors) {
  console.log('Testing conformance: dual_root_commitment...');
  for (const vec of vectors.dual_root_commitment) {
    // 1. Recompute BLAKE3 root from document parts
    const parts = vec.document_parts_utf8.map(s => new TextEncoder().encode(s));
    const computedRoot = computeMerkleRoot(parts);
    const blake3Consistent = computedRoot === vec.blake3_root;
    assert(
      blake3Consistent === vec.expected_blake3_consistent,
      `expected_blake3_consistent=${vec.expected_blake3_consistent} but computed=${blake3Consistent} ` +
      `for "${vec.description}":\n  computed: ${computedRoot}\n  vector:   ${vec.blake3_root}`
    );

    // 2. Verify the dual_commitment formula using the stored blake3_root + poseidon_root
    const gotDual = computeDualCommitment(vec.blake3_root, vec.poseidon_root);
    assert(
      gotDual === vec.dual_commitment,
      `dual_commitment mismatch for "${vec.description}": got ${gotDual}, want ${vec.dual_commitment}`
    );

    // 3. Verify blake3_proof when present
    if (vec.blake3_proof !== null && vec.blake3_proof !== undefined) {
      const proof = {
        leafHash: fromHex(vec.blake3_proof.leaf_hash),
        siblings: vec.blake3_proof.siblings.map(s => ({ hash: s.hash, position: s.position })),
        rootHash: vec.blake3_proof.root_hash,
      };
      assert(
        verifyMerkleProof(proof),
        `blake3_proof verification failed for "${vec.description}"`
      );
    }
  }
  console.log(`  ✓ dual_root_commitment: ${vectors.dual_root_commitment.length} vectors`);
}

function testVerificationBundle(vectors) {
  console.log('Testing conformance: verification_bundle...');
  if (!vectors.verification_bundle) {
    console.log('  (skipped: no verification_bundle vectors)');
    return;
  }
  for (const vec of vectors.verification_bundle) {
    // 1. Verify leaf hashes from canonical events
    for (let i = 0; i < vec.canonical_events.length; i++) {
      const canonical = canonicalJsonBytes(vec.canonical_events[i]);
      const got = toHex(computeBlake3(canonical));
      assert(
        got === vec.leaf_hashes[i],
        `verification_bundle leaf[${i}]: got ${got}, want ${vec.leaf_hashes[i]}`
      );
    }

    // 2. Verify Merkle root from leaf hashes
    const leaves = vec.leaf_hashes.map(h => fromHex(h));
    const root = computeMerkleRoot(leaves);
    assert(
      root === vec.merkle_root,
      `verification_bundle merkle_root: got ${root}, want ${vec.merkle_root}`
    );

    // 3. Verify each Merkle inclusion proof
    for (const mp of vec.merkle_proofs) {
      const siblings = mp.siblings.map(s => {
        if (Array.isArray(s)) return { hash: s[0], position: s[1] };
        return s;
      });
      const valid = verifyMerkleProof({
        leafHash: fromHex(mp.leaf_hash),
        siblings: siblings,
        rootHash: mp.root_hash,
      });
      assert(valid, `verification_bundle proof[${mp.leaf_index}] failed`);
    }
  }
  console.log(`  ✓ verification_bundle: ${vectors.verification_bundle.length} vectors`);
}

/**
 * Produce canonical JSON bytes from an object (sorted keys, minimal separators).
 * Matches Python: json.dumps(data, sort_keys=True, separators=(',',':'), ensure_ascii=True)
 */
function canonicalJsonBytes(obj) {
  function sortedStringify(val) {
    if (val === null) return 'null';
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (typeof val === 'number') return JSON.stringify(val);
    if (typeof val === 'string') return JSON.stringify(val);
    if (Array.isArray(val)) {
      return '[' + val.map(sortedStringify).join(',') + ']';
    }
    if (typeof val === 'object') {
      const keys = Object.keys(val).sort();
      const pairs = keys.map(k => JSON.stringify(k) + ':' + sortedStringify(val[k]));
      return '{' + pairs.join(',') + '}';
    }
    return String(val);
  }
  return new TextEncoder().encode(sortedStringify(obj));
}

function runConformanceTests() {
  console.log('Running JavaScript conformance tests against vectors.json\n');
  const vectors = loadVectors();
  const canonicalizerVectors = loadCanonicalizerVectors();
  testBlake3Raw(vectors);
  testMerkleLeafHash(vectors);
  testMerkleParentHash(vectors);
  testMerkleRoot(vectors);
  testMerkleProof(vectors);
  testCanonicalizerHash(canonicalizerVectors);
  testLedgerEntryHash(vectors);
  testDualRootCommitment(vectors);
  testVerificationBundle(vectors);
  runSmtTests(vectors);
  console.log('\n✓ All JavaScript conformance tests passed!');
}

// ---------------------------------------------------------------------------
// SMT (SSMF) cross-language verifier conformance — ADR-0003
// Mirrors the Rust/Go conformance tests against ssmf_existence_proof and
// ssmf_nonexistence_proof entries in vectors.json. Includes the same six
// negative cases.
// ---------------------------------------------------------------------------

function buildInclusionProof(vec) {
  return {
    key: fromHex(vec.key),
    valueHash: fromHex(vec.value_hash),
    parserId: vec.parser_id,
    canonicalParserVersion: vec.canonical_parser_version,
    siblings: vec.siblings.map((s) => fromHex(s)),
    rootHash: fromHex(vec.root_hash),
  };
}

function buildNonInclusionProof(vec) {
  return {
    key: fromHex(vec.key),
    siblings: vec.siblings.map((s) => fromHex(s)),
    rootHash: fromHex(vec.root_hash),
  };
}

function testSmtEmptyLeafConstant() {
  console.log('Testing conformance: smt_empty_leaf...');
  const recomputed = computeBlake3(new TextEncoder().encode('OLY:EMPTY-LEAF:V1'));
  const recomputedHex = toHex(recomputed);
  const constantHex = toHex(SMT_EMPTY_LEAF);
  const expected = '0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29';
  assert(constantHex === expected,
    `SMT_EMPTY_LEAF constant has drifted: got ${constantHex}, want ${expected}`);
  assert(recomputedHex === expected,
    `BLAKE3(OLY:EMPTY-LEAF:V1) != ${expected}: got ${recomputedHex}`);
  console.log('  ✓ smt_empty_leaf: hardcoded constant matches BLAKE3(OLY:EMPTY-LEAF:V1)');
}

function testSmtExistenceProof(vectors) {
  console.log('Testing conformance: ssmf_existence_proof...');
  const cases = vectors.ssmf_existence_proof || [];
  assert(cases.length > 0, 'no ssmf_existence_proof vectors found');
  for (const vec of cases) {
    const proof = buildInclusionProof(vec);
    const got = verifySmtInclusion(proof);
    assert(got === vec.expected_valid,
      `ssmf_existence_proof verify (${vec.description}): got ${got}, want ${vec.expected_valid}`);
  }
  console.log(`  ✓ ssmf_existence_proof: ${cases.length} vectors`);
}

function testSmtNonExistenceProof(vectors) {
  console.log('Testing conformance: ssmf_nonexistence_proof...');
  const cases = vectors.ssmf_nonexistence_proof || [];
  assert(cases.length > 0, 'no ssmf_nonexistence_proof vectors found');
  for (const vec of cases) {
    const proof = buildNonInclusionProof(vec);
    const got = verifySmtNonInclusion(proof);
    assert(got === vec.expected_valid,
      `ssmf_nonexistence_proof verify (${vec.description}): got ${got}, want ${vec.expected_valid}`);
  }
  console.log(`  ✓ ssmf_nonexistence_proof: ${cases.length} vectors`);
}

function testSmtNegatives(vectors) {
  console.log('Testing conformance: ssmf negative cases...');
  const baseExist = vectors.ssmf_existence_proof[0];
  const baseNonExist = vectors.ssmf_nonexistence_proof[0];

  // Sanity baselines
  assert(verifySmtInclusion(buildInclusionProof(baseExist)),
    'baseline inclusion proof must verify');
  assert(verifySmtNonInclusion(buildNonInclusionProof(baseNonExist)),
    'baseline non-inclusion proof must verify');

  // 1) empty parser_id
  {
    const p = buildInclusionProof(baseExist);
    p.parserId = '';
    assert(verifySmtInclusion(p) === false, 'empty parser_id must fail');
  }
  // 2) empty canonical_parser_version
  {
    const p = buildInclusionProof(baseExist);
    p.canonicalParserVersion = '';
    assert(verifySmtInclusion(p) === false, 'empty canonical_parser_version must fail');
  }
  // 3) tampered root
  {
    const p = buildInclusionProof(baseExist);
    p.rootHash = new Uint8Array(p.rootHash);
    p.rootHash[0] ^= 0x01;
    assert(verifySmtInclusion(p) === false, 'tampered root must fail');
  }
  // 4) wrong value_hash
  {
    const p = buildInclusionProof(baseExist);
    p.valueHash = new Uint8Array(p.valueHash);
    p.valueHash[31] ^= 0xff;
    assert(verifySmtInclusion(p) === false, 'wrong value_hash must fail');
  }
  // 5) wrong number of siblings (255 instead of 256)
  {
    const p = buildInclusionProof(baseExist);
    p.siblings = p.siblings.slice(0, 255);
    assert(verifySmtInclusion(p) === false, '255 siblings must fail');
  }
  // 6) corrupted sibling[100]
  {
    const p = buildInclusionProof(baseExist);
    p.siblings[100] = new Uint8Array(p.siblings[100]);
    p.siblings[100][0] ^= 0x01;
    assert(verifySmtInclusion(p) === false, 'corrupted sibling[100] must fail');
  }

  // Parallel tampering for non-inclusion
  {
    const p = buildNonInclusionProof(baseNonExist);
    p.rootHash = new Uint8Array(p.rootHash);
    p.rootHash[0] ^= 0x01;
    assert(verifySmtNonInclusion(p) === false, 'tampered non-inclusion root must fail');
  }
  {
    const p = buildNonInclusionProof(baseNonExist);
    p.siblings = p.siblings.slice(0, 200);
    assert(verifySmtNonInclusion(p) === false, 'wrong sibling count must fail');
  }
  console.log('  ✓ ssmf negatives: 8 cases');
}

function runSmtTests(vectors) {
  testSmtEmptyLeafConstant();
  testSmtExistenceProof(vectors);
  testSmtNonExistenceProof(vectors);
  testSmtNegatives(vectors);
}

runConformanceTests();
