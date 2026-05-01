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

  // Build tree bottom-up using CT-style promotion
  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      if (i + 1 < level.length) {
        // Pair exists: hash left and right
        const right = level[i + 1];
        nextLevel.push(merkleParentHash(left, right));
      } else {
        // CT-style promotion: lone node is promoted without hashing
        nextLevel.push(left);
      }
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
 * Compute the dual-root commitment binding hash (V2) from BLAKE3 and Poseidon roots.
 *
 * Formula:
 *   BLAKE3(OLY:LEDGER:V1 | "|" | lenB3 | blake3RootBytes
 *                        | "|" | lenPos | poseidonRoot32BEBytes)
 *
 * where lenB3 and lenPos are 2-byte big-endian length prefixes (always
 * 0x0020 = 32), and poseidonRoot32BEBytes is the 32-byte big-endian encoding
 * of the BN128 field element expressed as a decimal string.
 *
 * This matches the Python reference (V2, PR 4: M-15 + M-14):
 *   blake3_hash([LEDGER_PREFIX, SEP, lenB3, blake3_root_bytes,
 *                SEP, lenPos, poseidon_root_32be])
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

  // 2-byte big-endian length prefixes (M-14)
  const lenB3 = new Uint8Array([
    (blake3RootBytes.length >> 8) & 0xff,
    blake3RootBytes.length & 0xff,
  ]);
  const lenPos = new Uint8Array([
    (poseidonBytes.length >> 8) & 0xff,
    poseidonBytes.length & 0xff,
  ]);

  const combined = new Uint8Array(
    LEDGER_PREFIX.length + SEP.length + lenB3.length + blake3RootBytes.length
      + SEP.length + lenPos.length + poseidonBytes.length
  );
  let offset = 0;
  combined.set(LEDGER_PREFIX, offset); offset += LEDGER_PREFIX.length;
  combined.set(SEP, offset);           offset += SEP.length;
  combined.set(lenB3, offset);         offset += lenB3.length;
  combined.set(blake3RootBytes, offset); offset += blake3RootBytes.length;
  combined.set(SEP, offset);           offset += SEP.length;
  combined.set(lenPos, offset);        offset += lenPos.length;
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

// ---------------------------------------------------------------------------
// Sparse Merkle Tree (SSMF) cross-language verifier — ADR-0003
//
// Mirrors protocol/ssmf.py::verify_proof and verify_nonexistence_proof.
// Wire format: siblings are leaf-to-root (siblings[0] = leaf-adjacent,
// siblings[255] = root-adjacent). Do NOT model this on
// services/cdhs-smf-rust/src/smt.rs — that service uses the opposite
// (root-to-leaf) convention internally; this module follows the wire format
// used by verifiers/test_vectors/vectors.json and the Python reference.
// ---------------------------------------------------------------------------

/**
 * SMT empty-leaf sentinel: BLAKE3(b"OLY:EMPTY-LEAF:V1"). Must match
 * protocol/ssmf.py::EMPTY_LEAF. Hardcoded here for clarity; recomputed by
 * the conformance test to guard against drift.
 * Value: 0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29
 * @type {Uint8Array}
 */
const SMT_EMPTY_LEAF = new Uint8Array([
  0x0c, 0x51, 0xa9, 0xc6, 0xfd, 0x8d, 0xd8, 0x84,
  0x7b, 0xa1, 0x05, 0x3a, 0x17, 0xf6, 0x29, 0x43,
  0xc5, 0x90, 0x52, 0xf4, 0xe3, 0x11, 0xab, 0x4e,
  0x93, 0x86, 0x7c, 0x42, 0x80, 0x57, 0x9f, 0x29,
]);

/**
 * Compute the SMT leaf hash with parser-identity binding (ADR-0003).
 *
 * Layout (matches protocol/hashes.py::leaf_hash):
 *   BLAKE3(LEAF_PREFIX || SEP || key || SEP || value_hash || SEP ||
 *          len(parser_id)[4B BE] || parser_id || SEP ||
 *          len(canonical_parser_version)[4B BE] || canonical_parser_version)
 *
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} valueHash - 32-byte value hash
 * @param {string} parserId - Parser identity (must be non-empty)
 * @param {string} canonicalParserVersion - Canonical parser version (must be non-empty)
 * @returns {Uint8Array} - 32-byte leaf hash
 */
function smtLeafHash(key, valueHash, parserId, canonicalParserVersion) {
  const LEAF_PREFIX = new TextEncoder().encode('OLY:LEAF:V1');
  const SEP = new TextEncoder().encode('|');
  const pid = new TextEncoder().encode(parserId);
  const cpv = new TextEncoder().encode(canonicalParserVersion);
  const u32be = (n) => new Uint8Array([
    (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff,
  ]);
  const pidLen = u32be(pid.length);
  const cpvLen = u32be(cpv.length);

  const totalLen =
    LEAF_PREFIX.length + SEP.length + key.length + SEP.length + valueHash.length +
    SEP.length + pidLen.length + pid.length + SEP.length + cpvLen.length + cpv.length;
  const buf = new Uint8Array(totalLen);
  let off = 0;
  buf.set(LEAF_PREFIX, off); off += LEAF_PREFIX.length;
  buf.set(SEP, off); off += SEP.length;
  buf.set(key, off); off += key.length;
  buf.set(SEP, off); off += SEP.length;
  buf.set(valueHash, off); off += valueHash.length;
  buf.set(SEP, off); off += SEP.length;
  buf.set(pidLen, off); off += pidLen.length;
  buf.set(pid, off); off += pid.length;
  buf.set(SEP, off); off += SEP.length;
  buf.set(cpvLen, off); off += cpvLen.length;
  buf.set(cpv, off);
  return computeBlake3(buf);
}

/**
 * Convert a 32-byte key to a 256-bit MSB-first path.
 * pathBits[0] = MSB of key[0]; pathBits[255] = LSB of key[31].
 * @param {Uint8Array} key
 * @returns {Uint8Array} - 256 bytes each containing 0 or 1
 */
function keyToPathBits(key) {
  const path = new Uint8Array(256);
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    const b = key[byteIdx];
    for (let bitInByte = 0; bitInByte < 8; bitInByte++) {
      path[byteIdx * 8 + bitInByte] = (b >>> (7 - bitInByte)) & 1;
    }
  }
  return path;
}

/** Fixed-iteration equality check for same-length Uint8Arrays. */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Walk siblings from leaf to root starting at `start`; return whether the
 * computed root matches `root`.
 *
 * @param {Uint8Array} pathBits - 256 path bits (MSB-first)
 * @param {Uint8Array[]} siblings - exactly 256 siblings, leaf-to-root
 * @param {Uint8Array} start - 32-byte starting hash (leaf hash or empty-leaf sentinel)
 * @param {Uint8Array} root - 32-byte expected root
 * @returns {boolean}
 */
function smtWalkAndCheck(pathBits, siblings, start, root) {
  let current = start;
  for (let i = 0; i < 256; i++) {
    const bit = pathBits[255 - i];
    const sib = siblings[i];
    current = bit === 0
      ? merkleParentHash(current, sib)
      : merkleParentHash(sib, current);
  }
  return bytesEqual(current, root);
}

/**
 * Verify an SMT inclusion proof.
 *
 * Returns false for any input-validation failure (matches the Python
 * reference: never throws).
 *
 * @param {Object} proof
 * @param {Uint8Array} proof.key - 32-byte key
 * @param {Uint8Array} proof.valueHash - 32-byte value hash
 * @param {string} proof.parserId - Non-empty parser identity
 * @param {string} proof.canonicalParserVersion - Non-empty canonical parser version
 * @param {Uint8Array[]} proof.siblings - Exactly 256 32-byte siblings, leaf-to-root
 * @param {Uint8Array} proof.rootHash - 32-byte root
 * @returns {boolean}
 */
function verifySmtInclusion(proof) {
  if (!proof) return false;
  const { key, valueHash, parserId, canonicalParserVersion, siblings, rootHash } = proof;
  if (!(key instanceof Uint8Array) || key.length !== 32) return false;
  if (!(valueHash instanceof Uint8Array) || valueHash.length !== 32) return false;
  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) return false;
  if (typeof parserId !== 'string' || parserId === '') return false;
  if (typeof canonicalParserVersion !== 'string' || canonicalParserVersion === '') return false;
  if (!Array.isArray(siblings) || siblings.length !== 256) return false;
  for (const sib of siblings) {
    if (!(sib instanceof Uint8Array) || sib.length !== 32) return false;
  }
  const pathBits = keyToPathBits(key);
  const leaf = smtLeafHash(key, valueHash, parserId, canonicalParserVersion);
  return smtWalkAndCheck(pathBits, siblings, leaf, rootHash);
}

/**
 * Verify an SMT non-inclusion proof.
 *
 * Returns false for any input-validation failure.
 *
 * @param {Object} proof
 * @param {Uint8Array} proof.key - 32-byte key
 * @param {Uint8Array[]} proof.siblings - Exactly 256 32-byte siblings, leaf-to-root
 * @param {Uint8Array} proof.rootHash - 32-byte root
 * @returns {boolean}
 */
function verifySmtNonInclusion(proof) {
  if (!proof) return false;
  const { key, siblings, rootHash } = proof;
  if (!(key instanceof Uint8Array) || key.length !== 32) return false;
  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) return false;
  if (!Array.isArray(siblings) || siblings.length !== 256) return false;
  for (const sib of siblings) {
    if (!(sib instanceof Uint8Array) || sib.length !== 32) return false;
  }
  const pathBits = keyToPathBits(key);
  // Use a copy of SMT_EMPTY_LEAF to prevent callers from mutating the constant
  return smtWalkAndCheck(pathBits, siblings, new Uint8Array(SMT_EMPTY_LEAF), rootHash);
}

/**
 * Get a copy of the SMT empty-leaf sentinel.
 * Returns a new Uint8Array to prevent external mutation of the internal constant.
 * @returns {Uint8Array} - 32-byte copy of SMT_EMPTY_LEAF
 */
function getSmtEmptyLeaf() {
  return new Uint8Array(SMT_EMPTY_LEAF);
}

/**
 * SMT empty-leaf sentinel as an immutable hex string.
 * Primitives are immutable, so callers cannot corrupt the verifier's state.
 * Value: BLAKE3(b"OLY:EMPTY-LEAF:V1")
 * @type {string}
 */
const SMT_EMPTY_LEAF_HEX = toHex(SMT_EMPTY_LEAF);

/**
 * Canonical JSON encoder (JCS / RFC 8785 subset).
 *
 * Produces deterministic, byte-identical output matching the Python reference
 * implementation in ``protocol/canonical_json.py``:
 *
 * - Object keys are sorted by UTF-16 code units (native JS sort).
 * - Strings are NFC-normalized before encoding.
 * - Non-ASCII characters are emitted as raw UTF-8, not ``\uXXXX`` escapes.
 * - ``null``, ``true``, ``false``, integers, and arrays are handled
 *   identically to the Python encoder.
 *
 * **Known behavioral difference from the Python encoder:**
 * The Python ``canonical_json_encode()`` function rejects native Python
 * ``float`` objects and requires callers to use ``decimal.Decimal`` for
 * non-integer numbers. JavaScript has no separate ``Decimal`` type, so this
 * encoder accepts JS ``number`` values (finite only). ``NaN`` and ``±Infinity``
 * are rejected with an error, matching Python's rejection of ``float('nan')``
 * and ``float('inf')``.  All positive test vectors were generated from the
 * Python encoder using ``Decimal`` inputs, so round-trip output is
 * byte-identical for all vectors in ``canonicalizer_vectors.tsv``.
 *
 * @param {*} val - Value to encode. Must be null, boolean, finite number,
 *   string, Array, or plain Object. Other types throw TypeError.
 * @returns {string} Canonical JSON string.
 * @throws {Error} If val contains NaN, Infinity, or an unsupported type.
 */
function canonicalJsonEncode(val) {
  if (val === null) return 'null';
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'number') {
    if (Number.isNaN(val) || !Number.isFinite(val)) {
      const description = Number.isNaN(val) ? 'NaN' : (val > 0 ? 'Infinity' : '-Infinity');
      throw new Error('canonicalJsonEncode: non-finite number not allowed: ' + description);
    }
    return JSON.stringify(val);
  }
  if (typeof val === 'string') {
    const s = val.normalize('NFC');
    // Reject lone (unpaired) UTF-16 surrogates — they produce malformed JSON.
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) {
        const next = s.charCodeAt(i + 1);
        if (next < 0xDC00 || next > 0xDFFF) throw new Error('canonicalJsonEncode: lone high surrogate at index ' + i);
        i++;
      } else if (c >= 0xDC00 && c <= 0xDFFF) {
        throw new Error('canonicalJsonEncode: lone low surrogate at index ' + i);
      }
    }
    return JSON.stringify(s);
  }
  if (Array.isArray(val)) {
    return '[' + val.map(canonicalJsonEncode).join(',') + ']';
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val).sort();
    const normalizedKeys = keys.map(k => k.normalize('NFC'));
    for (let i = 1; i < normalizedKeys.length; i++) {
      if (normalizedKeys[i] === normalizedKeys[i - 1]) {
        throw new Error('canonicalJsonEncode: duplicate object key after NFC normalization: ' + JSON.stringify(normalizedKeys[i]));
      }
    }
    const pairs = normalizedKeys.map((nk, i) => JSON.stringify(nk) + ':' + canonicalJsonEncode(val[keys[i]]));
    return '{' + pairs.join(',') + '}';
  }
  throw new TypeError('canonicalJsonEncode: unsupported type: ' + typeof val);
}

/**
 * Encode val to canonical JSON and return the UTF-8 bytes.
 *
 * @param {*} val - Value to encode.
 * @returns {Uint8Array} UTF-8 bytes of the canonical JSON string.
 */
function canonicalJsonEncodeBytes(val) {
  return new TextEncoder().encode(canonicalJsonEncode(val));
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
  // Canonical JSON encoder (JCS / RFC 8785 subset)
  canonicalJsonEncode,
  canonicalJsonEncodeBytes,
  // SMT (SSMF) cross-language verifier — ADR-0003
  SMT_EMPTY_LEAF_HEX,
  getSmtEmptyLeaf,
  smtLeafHash,
  verifySmtInclusion,
  verifySmtNonInclusion,
};