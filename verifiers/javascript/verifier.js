/**
 * Olympus Verifier for JavaScript/TypeScript
 *
 * Standalone verifier for Olympus commitments. Can be used in Node.js or browsers.
 */

// Use @noble/hashes for BLAKE3 (production) or fallback to simple implementation
const { blake3 } = require('@noble/hashes/blake3.js');
// Ed25519 for redaction-bundle signatures (ADR-0023).
const { ed25519 } = require('@noble/curves/ed25519.js');

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
 * Compute the SMT leaf hash. Mirrors the canonical olympus_crypto::leaf_hash:
 * an ADR-0005 structured binary prefix (marker / namespace / object-type /
 * version, then the length-prefixed shard) followed by a count-framed body
 * binding parser provenance (ADR-0003) and the model hash (ADR-0004).
 *
 *   BLAKE3(
 *     0x01 || "OLY" || 0x01 || 0x01 ||   // structured prefix: marker, namespace, type=LEAF, version=V1
 *     lp(shard_id) ||
 *     0x05 ||                              // body field count
 *     lp(key) || value_hash ||            // value_hash raw (fixed 32 bytes)
 *     lp(parser_id) || lp(canonical_parser_version) || lp(model_hash))
 *
 * where lp(x) is a 4-byte big-endian length prefix followed by x.
 *
 * @param {string} shardId - Shard identifier (must be non-empty)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} valueHash - 32-byte value hash
 * @param {string} parserId - Parser identity (must be non-empty)
 * @param {string} canonicalParserVersion - Canonical parser version (must be non-empty)
 * @param {string} modelHash - Parser model-artifact hash (must be non-empty)
 * @returns {Uint8Array} - 32-byte leaf hash
 */
function smtLeafHash(shardId, key, valueHash, parserId, canonicalParserVersion, modelHash) {
  // Refuse inputs the canonical Rust `leaf_hash` would reject (key/value_hash
  // are fixed-width 32 bytes; the provenance fields are non-empty), so a misuse
  // fails loudly here rather than producing a digest Rust will never match.
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('smtLeafHash: key must be a 32-byte Uint8Array');
  }
  if (!(valueHash instanceof Uint8Array) || valueHash.length !== 32) {
    throw new Error('smtLeafHash: valueHash must be a 32-byte Uint8Array');
  }
  for (const [name, v] of [['shardId', shardId], ['parserId', parserId],
    ['canonicalParserVersion', canonicalParserVersion], ['modelHash', modelHash]]) {
    if (typeof v !== 'string' || v === '') {
      throw new Error(`smtLeafHash: ${name} must be a non-empty string`);
    }
  }
  const enc = new TextEncoder();
  const u32be = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const out = [];
  const pushLp = (bytes) => { out.push(...u32be(bytes.length)); out.push(...bytes); };

  // ADR-0005 structured prefix.
  out.push(0x01);                       // marker
  out.push(...enc.encode('OLY'));       // namespace
  out.push(0x01);                       // object type = LEAF
  out.push(0x01);                       // version = V1
  pushLp(enc.encode(shardId));
  // Count-framed body.
  out.push(0x05);
  pushLp(key);
  out.push(...valueHash);
  pushLp(enc.encode(parserId));
  pushLp(enc.encode(canonicalParserVersion));
  pushLp(enc.encode(modelHash));
  return computeBlake3(new Uint8Array(out));
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
 * @param {string} proof.shardId - Non-empty shard identifier (ADR-0005)
 * @param {string} proof.parserId - Non-empty parser identity
 * @param {string} proof.canonicalParserVersion - Non-empty canonical parser version
 * @param {string} proof.modelHash - Non-empty parser model-artifact hash (ADR-0004)
 * @param {Uint8Array[]} proof.siblings - Exactly 256 32-byte siblings, leaf-to-root
 * @param {Uint8Array} proof.rootHash - 32-byte root
 * @returns {boolean}
 */
function verifySmtInclusion(proof) {
  if (!proof) return false;
  const { key, valueHash, shardId, parserId, canonicalParserVersion, modelHash, siblings, rootHash } = proof;
  if (!(key instanceof Uint8Array) || key.length !== 32) return false;
  if (!(valueHash instanceof Uint8Array) || valueHash.length !== 32) return false;
  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) return false;
  if (typeof shardId !== 'string' || shardId === '') return false;
  if (typeof parserId !== 'string' || parserId === '') return false;
  if (typeof canonicalParserVersion !== 'string' || canonicalParserVersion === '') return false;
  if (typeof modelHash !== 'string' || modelHash === '') return false;
  if (!Array.isArray(siblings) || siblings.length !== 256) return false;
  for (const sib of siblings) {
    if (!(sib instanceof Uint8Array) || sib.length !== 32) return false;
  }
  // ADR-0005 authority: the in-leaf shardId must hash to the key's 64-bit prefix.
  if (!shardIdMatchesKey(shardId, key)) return false;
  const pathBits = keyToPathBits(key);
  const leaf = smtLeafHash(shardId, key, valueHash, parserId, canonicalParserVersion, modelHash);
  return smtWalkAndCheck(pathBits, siblings, leaf, rootHash);
}

/**
 * The 64-bit shard prefix = first 8 bytes of BLAKE3("OLY:SHARD-PREFIX:V1" || shardId).
 * Mirrors olympus_crypto::smt::shard_prefix.
 * @param {string} shardId
 * @returns {Uint8Array} 8 bytes
 */
function shardPrefix(shardId) {
  const enc = new TextEncoder();
  const tag = enc.encode('OLY:SHARD-PREFIX:V1');
  const sid = enc.encode(shardId);
  const buf = new Uint8Array(tag.length + sid.length);
  buf.set(tag, 0);
  buf.set(sid, tag.length);
  return computeBlake3(buf).slice(0, 8);
}

/** ADR-0005 authority link: key's high 64 bits must be shardPrefix(shardId). */
function shardIdMatchesKey(shardId, key) {
  return bytesEqual(shardPrefix(shardId), key.slice(0, 8));
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
// Maximum nesting depth — matches src/canonical.rs MAX_DEPTH (64).
const _CANONICAL_JSON_MAX_DEPTH = 64;

function canonicalJsonEncode(val) {
  return _canonicalJsonEncodeInner(val, 0);
}

function _canonicalJsonEncodeInner(val, depth) {
  if (depth > _CANONICAL_JSON_MAX_DEPTH) {
    throw new Error('canonicalJsonEncode: nesting depth ' + depth + ' exceeds maximum of ' + _CANONICAL_JSON_MAX_DEPTH);
  }
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
    return '[' + val.map(function(v) { return _canonicalJsonEncodeInner(v, depth + 1); }).join(',') + ']';
  }
  if (typeof val === 'object') {
    // NFC-normalise keys first, then sort by normalised form (UTF-16 code-unit
    // order, which is JS default string sort). Sorting on the raw key before
    // normalising would diverge from src/canonical.rs for supplementary-plane
    // characters whose NFC form changes their sort position.
    const nfcPairs = Object.keys(val).map(function(k) {
      return { raw: k, nfc: k.normalize('NFC') };
    });
    nfcPairs.sort(function(a, b) { return a.nfc < b.nfc ? -1 : a.nfc > b.nfc ? 1 : 0; });
    for (let i = 1; i < nfcPairs.length; i++) {
      if (nfcPairs[i].nfc === nfcPairs[i - 1].nfc) {
        throw new Error('canonicalJsonEncode: duplicate object key after NFC normalization: ' + JSON.stringify(nfcPairs[i].nfc));
      }
    }
    const pairs = nfcPairs.map(function(p) {
      return JSON.stringify(p.nfc) + ':' + _canonicalJsonEncodeInner(val[p.raw], depth + 1);
    });
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

// ---------------------------------------------------------------------------
// Pedersen commitments on Baby Jubjub — issue #992
//
// C = m*G + r*H on the Baby Jubjub prime-order subgroup, where G is the
// circomlib B8 base point and H is the NUMS generator derived from the domain
// tag OLY:PEDERSEN:H:V1. This mirrors src-tauri/src/zk/pedersen.rs — the
// authoritative Rust implementation (built on the Apache-2.0 babyjubjub-rs
// crate). Used to cross-check the `pedersen_commitment` block in
// verifiers/test_vectors/vectors.json.
//
// Curve (twisted Edwards): a*x^2 + y^2 = 1 + d*x^2*y^2 over BN254 Fr.
// Binding requires scalars m,r in [0, l) where l is the subgroup order; we
// reduce mod l here (the Rust API rejects out-of-range instead, but for a
// recompute-and-compare verifier reducing is equivalent and matches the
// vectors, whose m,r are already canonical).
// ---------------------------------------------------------------------------

const BJJ_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BJJ_A = 168700n;
const BJJ_D = 168696n;
const BJJ_L =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
// circomlib B8 base point.
const BJJ_G = {
  x: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
};
// NUMS generator H for OLY:PEDERSEN:H:V1 (pinned in zk/pedersen.rs).
const BJJ_H = {
  x: 198588470289489729947397318629051280907399291050874530267072873208967148441n,
  y: 19238664506574355524861866424113858387196810277823508736174698680331927248315n,
};
const BJJ_HALF = (BJJ_P - 1n) / 2n; // sign threshold for compression

function modP(n) {
  const r = n % BJJ_P;
  return r < 0n ? r + BJJ_P : r;
}

/** Modular inverse via Fermat (p is prime). */
function invP(n) {
  return powP(modP(n), BJJ_P - 2n);
}

function powP(base, exp) {
  let b = modP(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % BJJ_P;
    b = (b * b) % BJJ_P;
    e >>= 1n;
  }
  return r;
}

/** Twisted-Edwards point addition (unified, complete on BJJ). */
function bjjAdd(P, Q) {
  const x1y2 = (P.x * Q.y) % BJJ_P;
  const x2y1 = (Q.x * P.y) % BJJ_P;
  const y1y2 = (P.y * Q.y) % BJJ_P;
  const x1x2 = (P.x * Q.x) % BJJ_P;
  const dxy = modP(BJJ_D * x1x2 % BJJ_P * y1y2);
  const x3 = modP((x1y2 + x2y1) * invP(1n + dxy));
  const y3 = modP((y1y2 - BJJ_A * x1x2) * invP(1n - dxy));
  return { x: x3, y: y3 };
}

/** Scalar multiplication k*P via double-and-add. */
function bjjMul(P, k) {
  let R = { x: 0n, y: 1n }; // identity
  let base = P;
  let e = ((k % BJJ_L) + BJJ_L) % BJJ_L;
  while (e > 0n) {
    if (e & 1n) R = bjjAdd(R, base);
    base = bjjAdd(base, base);
    e >>= 1n;
  }
  return R;
}

/** True iff P lies on the Baby Jubjub curve. */
function bjjOnCurve(P) {
  const x2 = (P.x * P.x) % BJJ_P;
  const y2 = (P.y * P.y) % BJJ_P;
  return modP(BJJ_A * x2 + y2 - 1n - BJJ_D * x2 % BJJ_P * y2) === 0n;
}

/** True iff P is in the prime-order subgroup (l*P == identity). */
function bjjInPrimeSubgroup(P) {
  const o = bjjMul(P, BJJ_L);
  return o.x === 0n && o.y === 1n;
}

/**
 * Compute the Pedersen commitment C = m*G + r*H.
 * @param {bigint} m message scalar
 * @param {bigint} r blinding scalar
 * @returns {{x: bigint, y: bigint}} commitment point
 */
function pedersenCommit(m, r) {
  return bjjAdd(bjjMul(BJJ_G, m), bjjMul(BJJ_H, r));
}

/**
 * Compress a BJJ point to the iden3/babyjubjub-rs 32-byte form:
 * y little-endian, with bit 255 (MSB of the last byte) set when x > (p-1)/2.
 * @param {{x: bigint, y: bigint}} P
 * @returns {Uint8Array} 32 bytes
 */
function bjjCompress(P) {
  const b = new Uint8Array(32);
  let tmp = modP(P.y);
  for (let i = 0; i < 32; i++) {
    b[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  if (modP(P.x) > BJJ_HALF) b[31] |= 0x80;
  return b;
}

/** Tonelli–Shanks square root mod p (p % 4 == 1 here). Returns null if none. */
function sqrtP(n) {
  n = modP(n);
  if (n === 0n) return 0n;
  if (powP(n, (BJJ_P - 1n) / 2n) !== 1n) return null; // non-residue
  let q = BJJ_P - 1n;
  let s = 0n;
  while (q % 2n === 0n) {
    q /= 2n;
    s += 1n;
  }
  let z = 2n;
  while (powP(z, (BJJ_P - 1n) / 2n) !== BJJ_P - 1n) z += 1n;
  let m = s;
  let c = powP(z, q);
  let t = powP(n, q);
  let r = powP(n, (q + 1n) / 2n);
  while (t !== 1n) {
    let i = 0n;
    let tt = t;
    while (tt !== 1n) {
      tt = (tt * tt) % BJJ_P;
      i += 1n;
    }
    const b = powP(c, 1n << (m - i - 1n));
    m = i;
    c = (b * b) % BJJ_P;
    t = (t * c) % BJJ_P;
    r = (r * b) % BJJ_P;
  }
  return r;
}

/**
 * Decompress an iden3/babyjubjub-rs 32-byte commitment back to (x, y).
 * Recovers x from the curve equation and selects the root by the sign bit.
 * @param {Uint8Array} bytes 32 bytes
 * @returns {{x: bigint, y: bigint}}
 */
function bjjDecompress(bytes) {
  if (bytes.length !== 32) throw new Error('compressed point must be 32 bytes');
  const buf = Uint8Array.from(bytes);
  const sign = (buf[31] & 0x80) !== 0;
  buf[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(buf[i]);
  // a*x^2 + y^2 = 1 + d*x^2*y^2  →  x^2 = (1 - y^2) / (a - d*y^2)
  const y2 = (y * y) % BJJ_P;
  const x2 = modP((1n - y2) * invP(modP(BJJ_A - BJJ_D * y2)));
  let x = sqrtP(x2);
  if (x === null) throw new Error('not a valid curve point');
  if ((x > BJJ_HALF) !== sign) x = modP(-x);
  return { x, y };
}

/**
 * Verify a Pedersen commitment opening against a `pedersen_commitment`
 * vector entry. Recomputes C = m*G + r*H and checks the coordinates, the
 * compressed form, and (defence-in-depth) subgroup membership.
 * @param {object} vec one entry of vectors.pedersen_commitment.commitments
 * @returns {boolean}
 */
function verifyPedersenCommitment(vec) {
  const m = BigInt(vec.m_decimal);
  const r = BigInt(vec.r_decimal);
  const C = pedersenCommit(m, r);

  const expectedX = BigInt(vec.commitment_x_decimal);
  const expectedY = BigInt(vec.commitment_y_decimal);
  if (C.x !== expectedX || C.y !== expectedY) return false;

  // Recomputed point must be a valid in-subgroup curve point.
  if (!bjjOnCurve(C) || !bjjInPrimeSubgroup(C)) return false;

  // Compressed form must match the committed bytes...
  const compressed = toHex(bjjCompress(C));
  if (compressed !== vec.commitment_compressed_hex) return false;

  // ...and decompress back to the same point (round-trip).
  const back = bjjDecompress(fromHex(vec.commitment_compressed_hex));
  return back.x === C.x && back.y === C.y;
}

// ---------------------------------------------------------------------------
// Rasterized tile-redaction commitment (ADR-0023) — cross-language verifier leg.
// Mirrors src-tauri/src/zk/redaction_tile.rs and verifiers/rust/src/redaction_tile.rs.
// Reuses the Baby Jubjub / Pedersen primitives above; adds the three novel
// pieces: tile message scalar, tiles root, and bundle verification.
// ---------------------------------------------------------------------------

const TILE_PREFIX = new TextEncoder().encode('OLY:REDACTION:TILE:V1');
const BUNDLE_PREFIX = new TextEncoder().encode('OLY:REDACTION:BUNDLE:V1');
const EMPTY_LEAF_PREFIX = new TextEncoder().encode('OLY:EMPTY-LEAF:V1');

/** Big-endian 4-byte encoding of a u32. */
function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

function concatBytes(arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function bytesBeToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/**
 * Tile message scalar: m = reduce_l(BLAKE3_XOF(
 *   OLY:REDACTION:TILE:V1 || page||x||y || lp(tile_bytes) )[..64]).
 * @returns {bigint} m in [0, l)
 */
function tileMessageScalar(page, x, y, tileBytes) {
  const input = concatBytes([
    TILE_PREFIX,
    u32be(page), u32be(x), u32be(y),
    u32be(tileBytes.length), tileBytes,
  ]);
  const wide = blake3(input, { dkLen: 64 });
  return bytesBeToBigInt(wide) % BJJ_L;
}

/** Compressed Pedersen tile leaf hex = compress(m*G + blinding*H). */
function commitTileLeafHex(page, x, y, tileBytes, blinding) {
  const m = tileMessageScalar(page, x, y, tileBytes);
  return toHex(bjjCompress(pedersenCommit(m, blinding)));
}

/** The OLY:EMPTY-LEAF:V1 sentinel (32 bytes). */
function emptyLeaf() {
  return computeBlake3(EMPTY_LEAF_PREFIX);
}

/**
 * Positional Merkle root over leaf byte-arrays, padded to the next power of two
 * with the empty-leaf sentinel and folded with merkleParentHash (OLY:NODE:V1).
 * @param {Uint8Array[]} leaves
 * @returns {Uint8Array} 32-byte root
 */
function tilesRoot(leaves) {
  if (leaves.length === 0) return emptyLeaf();
  let level = leaves.slice();
  let target = 1;
  while (target < level.length) target <<= 1;
  while (level.length < target) level.push(emptyLeaf());
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(merkleParentHash(level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0];
}

/** Domain-separated bundle descriptor digest (mirrors the Rust reference). */
function redactionDescriptorDigest(rootBytes, recipientId, tiles) {
  const recip = new TextEncoder().encode(recipientId);
  const parts = [
    BUNDLE_PREFIX,
    u32be(rootBytes.length), rootBytes,
    u32be(recip.length), recip,
    u32be(tiles.length),
  ];
  for (const t of tiles) {
    parts.push(u32be(t.page), u32be(t.x), u32be(t.y));
    parts.push(Uint8Array.of(t.revealed_blinding_decimal != null ? 1 : 0));
    parts.push(fromHex(t.leaf_compressed_hex));
  }
  return computeBlake3(concatBytes(parts));
}

/**
 * Verify a redaction bundle vector: Ed25519 over the descriptor digest,
 * revealed-tile reopening from the artifact, and root binding. Never throws —
 * returns false on any malformed/failed check.
 * @param {object} b a `bundle` vector entry
 * @returns {boolean}
 */
function verifyRedactionBundle(b) {
  try {
    const root = fromHex(b.original_root_hex);

    // 1. Signature over the descriptor digest.
    const digest = redactionDescriptorDigest(root, b.recipient_id, b.tiles);
    if (!ed25519.verify(fromHex(b.signature_hex), digest, fromHex(b.signer_ed25519_pubkey_hex))) {
      return false;
    }

    // 2. Revealed-tile authenticity from the artifact.
    for (const t of b.tiles) {
      if (t.revealed_blinding_decimal != null) {
        const art = b.artifact_tiles.find(
          (a) => a.page === t.page && a.x === t.x && a.y === t.y,
        );
        if (!art) return false;
        const leafHex = commitTileLeafHex(
          t.page, t.x, t.y, fromHex(art.tile_bytes_hex), BigInt(t.revealed_blinding_decimal),
        );
        if (leafHex !== t.leaf_compressed_hex) return false;
      }
    }

    // 3. Root binding over all leaves in bundle order.
    const leaves = b.tiles.map((t) => fromHex(t.leaf_compressed_hex));
    return toHex(tilesRoot(leaves)) === b.original_root_hex;
  } catch (_) {
    return false;
  }
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
  // Pedersen commitments on Baby Jubjub — issue #992
  pedersenCommit,
  bjjAdd,
  bjjCompress,
  bjjDecompress,
  bjjOnCurve,
  bjjInPrimeSubgroup,
  verifyPedersenCommitment,
  // Rasterized tile-redaction commitment — ADR-0023
  tileMessageScalar,
  commitTileLeafHex,
  tilesRoot,
  redactionDescriptorDigest,
  verifyRedactionBundle,
  // SMT (SSMF) cross-language verifier — ADR-0003
  SMT_EMPTY_LEAF_HEX,
  getSmtEmptyLeaf,
  smtLeafHash,
  verifySmtInclusion,
  verifySmtNonInclusion,
};