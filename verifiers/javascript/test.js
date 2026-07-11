/**
 * Simple test suite for Olympus JavaScript verifier
 */

const {
  verifyBlake3Hash,
  computeMerkleRoot,
  verifyMerkleProof,
  toHex,
  merkleLeafHash,
} = require("./verifier");

function assert(condition, message) {
  if (!condition) {
    throw new Error("Assertion failed: " + message);
  }
}

function testBlake3Verification() {
  console.log("Testing BLAKE3 verification...");

  const data = new TextEncoder().encode("Hello, Olympus!");
  const hash = require("@noble/hashes/blake3.js").blake3(data);
  const hexHash = toHex(hash);

  assert(verifyBlake3Hash(data, hexHash), "BLAKE3 hash should verify");
  assert(!verifyBlake3Hash(data, "invalid"), "Invalid hash should not verify");

  console.log("  ✓ BLAKE3 verification works");
}

function testMerkleRoot() {
  console.log("Testing Merkle root computation...");

  const leaves = [new TextEncoder().encode("leaf1"), new TextEncoder().encode("leaf2")];

  const root = computeMerkleRoot(leaves);
  assert(root.length === 64, "Root should be 32 bytes (64 hex chars)");

  // Computing same root twice should give same result
  const root2 = computeMerkleRoot(leaves);
  assert(root === root2, "Merkle root should be deterministic");

  console.log("  ✓ Merkle root computation works");
}

function testMerkleProof() {
  console.log("Testing Merkle proof verification...");

  const leaves = [
    new TextEncoder().encode("alpha"),
    new TextEncoder().encode("beta"),
    new TextEncoder().encode("gamma"),
    new TextEncoder().encode("delta"),
  ];

  // Compute the root
  const root = computeMerkleRoot(leaves);

  // Build a valid proof for the first leaf (index 0) in a 4-leaf tree
  // Tree structure:
  //        root
  //       /    \
  //    h01      h23
  //    / \      / \
  //   L0 L1    L2 L3
  //
  // To prove L0, we need: L1 (right sibling) and h23 (right uncle)
  const leafHash = merkleLeafHash(leaves[0]);
  const leaf1Hash = merkleLeafHash(leaves[1]);
  const leaf2Hash = merkleLeafHash(leaves[2]);
  const leaf3Hash = merkleLeafHash(leaves[3]);
  const h23 = require("@noble/hashes/blake3.js").blake3(
    new Uint8Array([
      ...new TextEncoder().encode("OLY:NODE:V1"),
      ...new TextEncoder().encode("|"),
      ...leaf2Hash,
      ...new TextEncoder().encode("|"),
      ...leaf3Hash,
    ]),
  );

  // Valid proof for leaf 0
  const validProof = {
    leafHash: leafHash,
    siblings: [
      { hash: toHex(leaf1Hash), position: "right" },
      { hash: toHex(h23), position: "right" },
    ],
    rootHash: root,
  };

  const validResult = verifyMerkleProof(validProof);
  assert(validResult === true, "Valid proof must return true");

  // Invalid proof: tamper with the leaf hash
  const invalidProof = {
    leafHash: leaf1Hash, // wrong leaf
    siblings: [
      { hash: toHex(leafHash), position: "right" },
      { hash: toHex(h23), position: "right" },
    ],
    rootHash: root,
  };

  const invalidResult = verifyMerkleProof(invalidProof);
  assert(invalidResult === false, "Invalid proof must return false");

  console.log("  ✓ Merkle proof verification works");
}

function runTests() {
  console.log("Running Olympus JavaScript Verifier Tests\n");

  try {
    testBlake3Verification();
    testMerkleRoot();
    testMerkleProof();

    console.log("\n✓ All tests passed!");
  } catch (error) {
    console.error("\n✗ Test failed:", error.message);
    process.exit(1);
  }
}

runTests();
