/**
 * Olympus Verifier for JavaScript/TypeScript
 *
 * Standalone verifier for Olympus commitments. Can be used in Node.js or browsers.
 */

// Use @noble/hashes for BLAKE3 (production) or fallback to simple implementation
const { blake3 } = require('@noble/hashes/blake3.js');

/**
 * Compute BLAKE3 hash of data
 * @param {Uint8Array} data - Data to hash
 * @returns {Uint8Array} - 32-byte BLAKE3 hash
 */
function computeBlake3(data) {
  return blake3(data);
}

/**
 * Convert bytes to hex string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} - Hex string
 */
function toHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string
 * @returns {Uint8Array} - Bytes
 */
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Verify a BLAKE3 hash
 * @param {Uint8Array} data - Original data
 * @param {string} expectedHash - Expected hash (hex string)
 * @returns {boolean} - True if hash matches
 */
function verifyBlake3Hash(data, expectedHash) {
  const actualHash = computeBlake3(data);
  const actualHex = toHex(actualHash);
  return actualHex === expectedHash.toLowerCase();
}

/**
 * Compute Merkle parent hash (BLAKE3)
 * @param {Uint8Array} leftHash - Left child hash
 * @param {Uint8Array} rightHash - Right child hash
 * @returns {Uint8Array} - Parent hash
 */
function merkleParentHash(leftHash, rightHash) {
  // Concatenate: NODE_PREFIX || HASH_SEPARATOR || left || HASH_SEPARATOR || right
  // Prefixes must match protocol/hashes.py: OLY:NODE:V1
  const NODE_PREFIX = new TextEncoder().encode('OLY:NODE:V1');
  const HASH_SEPARATOR = new TextEncoder().encode('|');

  const combined = new Uint8Array(
    NODE_PREFIX.length +
    HASH_SEPARATOR.length +
    leftHash.length +
    HASH_SEPARATOR.length +
    rightHash.length
  );

  let offset = 0;
  combined.set(NODE_PREFIX, offset);
  offset += NODE_PREFIX.length;
  combined.set(HASH_SEPARATOR, offset);
  offset += HASH_SEPARATOR.length;
  combined.set(leftHash, offset);
  offset += leftHash.length;
  combined.set(HASH_SEPARATOR, offset);
  offset += HASH_SEPARATOR.length;
  combined.set(rightHash, offset);

  return computeBlake3(combined);
}

/**
 * Compute Merkle leaf hash (BLAKE3 with LEAF_PREFIX)
 * @param {Uint8Array} leafData - Leaf data
 * @returns {Uint8Array} - Leaf hash
 */
function merkleLeafHash(leafData) {
  // Hash with LEAF_PREFIX domain separation
  // Prefix must match protocol/hashes.py: OLY:LEAF:V1
  const LEAF_PREFIX = new TextEncoder().encode('OLY:LEAF:V1');
  const HASH_SEPARATOR = new TextEncoder().encode('|');

  const combined = new Uint8Array(
    LEAF_PREFIX.length + HASH_SEPARATOR.length + leafData.length
  );

  let offset = 0;
  combined.set(LEAF_PREFIX, offset);
  offset += LEAF_PREFIX.length;
  combined.set(HASH_SEPARATOR, offset);
  offset += HASH_SEPARATOR.length;
  combined.set(leafData, offset);

  return computeBlake3(combined);
}

/**
 * Compute Merkle tree root from leaves
 * @param {Uint8Array[]} leaves - Array of leaf data
 * @returns {string} - Merkle root (hex string)
 */
function computeMerkleRoot(leaves) {
  if (leaves.length === 0) {
    throw new Error('Cannot compute Merkle root of empty tree');
  }

  // Hash all leaves with domain separation
  let level = leaves.map(leaf => merkleLeafHash(leaf));

  // Build tree bottom-up
  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(merkleParentHash(left, right));
    }

    level = nextLevel;
  }

  return toHex(level[0]);
}

/**
 * Verify a Merkle inclusion proof
 * @param {Object} proof - Merkle proof object
 * @param {Uint8Array} proof.leafHash - Hash of the leaf
 * @param {Array<{hash: string, position: string}>} proof.siblings - Sibling hashes and positions
 * @param {string} proof.rootHash - Expected root hash (hex)
 * @returns {boolean} - True if proof is valid
 */
function verifyMerkleProof(proof) {
  let currentHash = proof.leafHash;

  for (const sibling of proof.siblings) {
    const siblingBytes = fromHex(sibling.hash);

    if (sibling.position === 'left') {
      currentHash = merkleParentHash(siblingBytes, currentHash);
    } else if (sibling.position === 'right') {
      currentHash = merkleParentHash(currentHash, siblingBytes);
    } else {
      throw new Error('Invalid sibling position: ' + sibling.position);
    }
  }

  return toHex(currentHash) === proof.rootHash.toLowerCase();
}

/**
 * Compute the ledger entry hash from pre-canonicalized payload bytes.
 * Formula: BLAKE3(OLY:LEDGER:V1 || canonical_json_bytes(payload))
 * The canonical_json_bytes must be produced by the Olympus canonical JSON encoder
 * (JCS / RFC 8785 with BLAKE3-specific numeric rules — see protocol/canonical_json.py).
 * @param {Uint8Array} canonicalPayloadBytes - Pre-canonicalized JSON payload bytes
 * @returns {Uint8Array} - 32-byte entry hash
 */
function computeLedgerEntryHash(canonicalPayloadBytes) {
  const LEDGER_PREFIX = new TextEncoder().encode('OLY:LEDGER:V1');
  const combined = new Uint8Array(LEDGER_PREFIX.length + canonicalPayloadBytes.length);
  combined.set(LEDGER_PREFIX, 0);
  combined.set(canonicalPayloadBytes, LEDGER_PREFIX.length);
  return computeBlake3(combined);
}

/**
 * Compute the dual-root commitment hash from BLAKE3 and Poseidon roots.
 *
 * Formula:
 *   BLAKE3(OLY:LEDGER:V1 | "|" | blake3RootBytes | "|" | poseidonRoot32BEBytes)
 *
 * where poseidonRoot32BEBytes is the 32-byte big-endian encoding of the BN128
 * field element expressed as a decimal string.
 *
 * This matches the Python reference:
 *   blake3_hash([LEDGER_PREFIX, SEP, blake3_root_bytes, SEP, poseidon_root_32be])
 *
 * @param {string} blake3RootHex - BLAKE3 Merkle root as 64-char hex string
 * @param {string} poseidonRootDecimal - Poseidon root as decimal string (BN128 field element)
 * @returns {string} - 64-char hex dual commitment hash
 */
function computeDualCommitment(blake3RootHex, poseidonRootDecimal) {
  const LEDGER_PREFIX = new TextEncoder().encode('OLY:LEDGER:V1');
  const SEP = new TextEncoder().encode('|');
  const blake3RootBytes = fromHex(blake3RootHex);

  // Encode poseidon root decimal string as 32-byte big-endian
  const poseidonBytes = bigIntTo32BytesBE(BigInt(poseidonRootDecimal));

  const combined = new Uint8Array(
    LEDGER_PREFIX.length + SEP.length + blake3RootBytes.length + SEP.length + poseidonBytes.length
  );
  let offset = 0;
  combined.set(LEDGER_PREFIX, offset); offset += LEDGER_PREFIX.length;
  combined.set(SEP, offset);           offset += SEP.length;
  combined.set(blake3RootBytes, offset); offset += blake3RootBytes.length;
  combined.set(SEP, offset);           offset += SEP.length;
  combined.set(poseidonBytes, offset);

  return toHex(computeBlake3(combined));
}

/**
 * Encode a BigInt as a 32-byte big-endian Uint8Array.
 * @param {bigint} n - Non-negative integer to encode
 * @returns {Uint8Array} - 32 bytes, big-endian
 */
function bigIntTo32BytesBE(n) {
  const bytes = new Uint8Array(32);
  let tmp = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return bytes;
}

// Export functions
module.exports = {
  computeBlake3,
  toHex,
  fromHex,
  verifyBlake3Hash,
  merkleParentHash,
  merkleLeafHash,
  computeMerkleRoot,
  verifyMerkleProof,
  computeLedgerEntryHash,
  computeDualCommitment,
};
