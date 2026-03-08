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
} = require('./verifier');

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'vectors.json');

function assert(condition, message) {
  if (!condition) {
    throw new Error('Assertion failed: ' + message);
  }
}

function loadVectors() {
  return JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
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

function runConformanceTests() {
  console.log('Running JavaScript conformance tests against vectors.json\n');
  const vectors = loadVectors();
  testBlake3Raw(vectors);
  testMerkleLeafHash(vectors);
  testMerkleParentHash(vectors);
  testMerkleRoot(vectors);
  testMerkleProof(vectors);
  console.log('\n✓ All JavaScript conformance tests passed!');
}

runConformanceTests();
