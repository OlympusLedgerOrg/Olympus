/**
 * Cross-language conformance for the **ADR-0030 V3 signed-Merkle redaction
 * bundle** (Phase 3 offline recipient verifier).
 *
 * Loads the shared golden vectors generated from the canonical Rust reference
 * (`olympus-crypto examples/gen_redaction_vectors.rs`, the same
 * `olympus_crypto::redaction` encoders the producer uses) and reproduces the
 * full §3 verification byte-for-byte with an independent JavaScript
 * implementation:
 *
 *   - structural checks (N == len, 2 <= N <= 2^20, strictly-ascending-unique
 *     ids, ooxml-part dense 0..N-1 + label per entry),
 *   - per-format revealed-leaf reconstruction (slice + the §3 content_bytes rule
 *     per format),
 *   - the variable-depth fold (pad Fr(0) to 2^ceil(log2 N); domain_node(1,l,r))
 *     == original_root,
 *   - recompute table_hash + the signing payload, verify the Ed25519 issuer
 *     signature (@noble/curves), recompute + check the nullifier,
 *   - canonical-form REJECT rules (NO `% l` / `% r` reduction — hard reject any
 *     out-of-range leaf_hex / blinding_decimal / recipient_id).
 *
 * Poseidon comes from circomlibjs; Pedersen from verifier.js (the existing
 * cross-checked Baby Jubjub code). BLAKE3 from @noble/hashes. Ed25519 from
 * @noble/curves.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { blake3 } = require('@noble/hashes/blake3.js');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { buildPoseidon } = require('circomlibjs');
const { pedersenCommit } = require('./verifier.js');

const OBJ_DOMAIN = 'OLY:REDACTION:OBJ:V1';
const BLIND_PREFIX = 'OLY:REDACTION:BLIND:V1';
const BUNDLE_V3_PREFIX = 'OLY:REDACTION_BUNDLE:V3';
const TABLE_V3_PREFIX = 'OLY:REDACTION:TABLE:V3';
const NULLIFIER_V1_PREFIX = 'OLY:REDACTION:NULLIFIER:V1';

// Baby Jubjub prime-order subgroup order `l` (blinding scalars live in [0, l)).
const BJJ_L =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
// BN254 scalar field modulus `r` (leaf/recipient field elements live in [0, r)).
const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const MAX_REDACTION_SEGMENTS = 1n << 20n;
const FORMAT_TAGS = new Set(['pdf-object', 'pdf-xref-stream', 'text-line', 'ooxml-part']);
// pdf-xref-stream trim charset (ADR-0030 §3): SP, TAB, CR, LF, FF, NUL. Includes
// NUL (0x00) and FF (0x0c), which the JS regex \s class EXCLUDES — hardcode it.
const PDF_WS = new Set([0x20, 0x09, 0x0d, 0x0a, 0x0c, 0x00]);

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'redaction_vectors.json');

// ── byte helpers ─────────────────────────────────────────────────────────────
function isU32(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}
function u32be(n) {
  if (!isU32(n)) throw new RangeError(`u32be: not a uint32: ${n}`);
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}
function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n), 0);
  return b;
}
function lp(buf) {
  return Buffer.concat([u32be(buf.length), Buffer.from(buf)]);
}
function bytesBEToBigInt(u8) {
  let x = 0n;
  for (const b of u8) x = (x << 8n) | BigInt(b);
  return x;
}
function toHex32(x) {
  return x.toString(16).padStart(64, '0');
}
function hexToBuf(h) {
  return Buffer.from(h, 'hex');
}

// ── canonical-form validators (REJECT, do not reduce — ADR-0030 §2) ──────────
function isCanonicalDecimal(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  if (!/^[0-9]+$/.test(s)) return false;
  if (s.length > 1 && s[0] === '0') return false; // no leading zero except "0"
  return true;
}
/** recipient_id: canonical decimal and < r. */
function validRecipient(s) {
  return isCanonicalDecimal(s) && BigInt(s) < BN254_R;
}
/** blinding_decimal: canonical decimal and in [0, l). */
function validBlinding(s) {
  return isCanonicalDecimal(s) && BigInt(s) < BJJ_L;
}
/** leaf_hex: exactly 64 lowercase-hex chars and < r. */
function validLeafHex(s) {
  if (typeof s !== 'string' || s.length !== 64) return false;
  if (!/^[0-9a-f]{64}$/.test(s)) return false;
  return bytesBEToBigInt(hexToBuf(s)) < BN254_R;
}
/** original_root: exactly 64 lowercase-hex chars and < r. */
function validRootHex(s) {
  return validLeafHex(s);
}

// ── crypto core (mirrors olympus_crypto::redaction) ──────────────────────────
function makeCrypto(poseidon, blindSecret, contentHash) {
  const obj = (x) => poseidon.F.toObject(x);

  // content = reduce_l( BLAKE3_XOF(OBJ_DOMAIN || lp(u32_be(segId)) || contentBytes)[..64] )
  function contentScalar(segId, contentBytes) {
    const input = Buffer.concat([
      Buffer.from(OBJ_DOMAIN, 'ascii'),
      lp(u32be(segId)),
      Buffer.from(contentBytes),
    ]);
    return bytesBEToBigInt(blake3(input, { dkLen: 64 })) % BJJ_L;
  }
  // b = reduce_l( BLAKE3_XOF(BLIND_PREFIX || lp(blindSecret) || lp(contentHash) || lp(u32_be(segId)))[..64] )
  function deriveBlinding(segId) {
    const input = Buffer.concat([
      Buffer.from(BLIND_PREFIX, 'ascii'),
      lp(blindSecret),
      lp(contentHash),
      lp(u32be(segId)),
    ]);
    return bytesBEToBigInt(blake3(input, { dkLen: 64 })) % BJJ_L;
  }
  // leaf = Poseidon(C.x, C.y), C = content*G + blinding*H (Pedersen on BJJ).
  function leafFrom(content, blinding) {
    const c = pedersenCommit(content, blinding);
    return obj(poseidon([c.x, c.y]));
  }
  // domain_node(1, l, r) = Poseidon(Poseidon(1, l), r).
  function domainNode(d, left, right) {
    const inner = obj(poseidon([BigInt(d), left]));
    return obj(poseidon([inner, right]));
  }
  // Variable-depth fold (ADR-0030 §1): pad Fr(0) to 2^ceil(log2 N), domain 1.
  function variableDepthFold(leaves) {
    const n = leaves.length;
    if (n < 2) throw new Error('N must be >= 2');
    let depth = 0;
    while ((1 << depth) < n) depth++;
    const width = 1 << depth;
    let level = leaves.slice();
    while (level.length < width) level.push(0n);
    for (let d = 0; d < depth; d++) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(domainNode(2, level[i], level[i + 1])); // NODE=2 (audit L-4 split)
      level = next;
    }
    return level[0];
  }
  return { contentScalar, deriveBlinding, leafFrom, domainNode, variableDepthFold };
}

// Per-format content_bytes for a revealed segment (ADR-0030 §3 table). Returns the
// bytes fed to content_scalar. ooxml-part binds lp(label) || payload.
function revealedContentBytes(format, slice, label) {
  if (format === 'pdf-object' || format === 'text-line') {
    return Buffer.from(slice); // plain slice (untrimmed; text keeps trailing \n)
  }
  if (format === 'ooxml-part') {
    // committed = lp(label) || payload  (payload = the raw Stored slice)
    return Buffer.concat([lp(Buffer.from(label, 'utf8')), Buffer.from(slice)]);
  }
  if (format === 'pdf-xref-stream') {
    // inner = slice[find("obj")+3 .. rfind("endobj")], trim with PDF_WS.
    const objIdx = slice.indexOf(Buffer.from('obj'));
    const endIdx = slice.lastIndexOf(Buffer.from('endobj'));
    if (objIdx < 0 || endIdx < 0 || endIdx < objIdx + 3) {
      throw new Error('pdf-xref-stream: obj/endobj framing not found');
    }
    let lo = objIdx + 3;
    let hi = endIdx; // exclusive
    while (lo < hi && PDF_WS.has(slice[lo])) lo++;
    while (hi > lo && PDF_WS.has(slice[hi - 1])) hi--;
    return Buffer.from(slice.slice(lo, hi));
  }
  throw new Error('unknown format ' + format);
}

// table_hash = BLAKE3(TABLE_V3 || for each seg: u32(id) || u8(redacted) ||
//   u64(offset) || u64(length) || lp(label) || lp(redacted?leaf_hex:blinding_decimal))
function tableHash(segments) {
  const parts = [Buffer.from(TABLE_V3_PREFIX, 'ascii')];
  for (const s of segments) {
    parts.push(u32be(s.segment_id));
    parts.push(Buffer.from([s.redacted ? 0x01 : 0x00]));
    parts.push(u64be(s.artifact_offset));
    parts.push(u64be(s.artifact_length));
    parts.push(lp(Buffer.from(s.label || '', 'utf8')));
    const valueText = s.redacted ? s.leaf_hex : s.blinding_decimal;
    parts.push(lp(Buffer.from(valueText, 'ascii')));
  }
  return Buffer.from(blake3(Buffer.concat(parts)));
}

function signingPayload(rootHex, format, n, recipientDec, th) {
  return Buffer.concat([
    Buffer.from(BUNDLE_V3_PREFIX, 'ascii'),
    lp(Buffer.from(rootHex, 'ascii')),
    lp(Buffer.from(format, 'ascii')),
    u32be(n),
    lp(Buffer.from(recipientDec, 'ascii')),
    th, // un-length-prefixed terminal 32 bytes
  ]);
}

function nullifier(rootRaw32, th, recipientDec) {
  return Buffer.from(
    blake3(
      Buffer.concat([
        Buffer.from(NULLIFIER_V1_PREFIX, 'ascii'),
        rootRaw32,
        th,
        lp(Buffer.from(recipientDec, 'ascii')),
      ]),
    ),
  );
}

/**
 * Full V3 verification (ADR-0030 §3). Throws on the FIRST failed check with a
 * descriptive reason. `verifyFold` defaults true; the byte-dump fixture sets it
 * false (its original_root is a fixed layout anchor, not a fold of the segments).
 */
function verifyV3(bundle, crypto, issuerPubkey, format, opts = {}) {
  const verifyFold = opts.verifyFold !== false;
  const artifactHex = bundle.artifact_hex;
  const segs = bundle.segments;
  const n = bundle.segment_count;

  // 1. Structural.
  if (!FORMAT_TAGS.has(format)) throw new Error('unknown format ' + format);
  if (typeof n !== 'number' || BigInt(n) < 2n || BigInt(n) > MAX_REDACTION_SEGMENTS) {
    throw new Error('N out of [2, 2^20]: ' + n);
  }
  if (segs.length !== n) throw new Error('segment_count != segments.len()');
  if (!validRootHex(bundle.original_root)) throw new Error('non-canonical original_root');
  if (!validRecipient(bundle.recipient_id)) throw new Error('non-canonical recipient_id');

  const ooxml = format === 'ooxml-part';
  let prev = null;
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (!isU32(s.segment_id)) throw new Error('segment_id not a uint32 at ' + i);
    if (prev !== null && s.segment_id <= prev) throw new Error('ids not strictly ascending at ' + i);
    prev = s.segment_id;
    if (ooxml && (s.segment_id !== i || !s.label || s.label.length === 0)) {
      throw new Error('ooxml-part requires dense 0..N-1 ids + label at ' + i);
    }
    // optional-field correctness + canonical-form rejects
    if (s.redacted) {
      if (typeof s.leaf_hex !== 'string') throw new Error('redacted seg missing leaf_hex');
      if (!validLeafHex(s.leaf_hex)) throw new Error('non-canonical leaf_hex at seg ' + s.segment_id);
      if (s.blinding_decimal !== undefined) throw new Error('redacted seg carries blinding');
    } else {
      if (typeof s.blinding_decimal !== 'string') throw new Error('revealed seg missing blinding_decimal');
      if (!validBlinding(s.blinding_decimal)) throw new Error('non-canonical blinding at seg ' + s.segment_id);
      if (s.leaf_hex !== undefined) throw new Error('revealed seg carries leaf_hex');
    }
  }

  // 2/3. Reconstruct + fold.
  if (verifyFold) {
    const artifact = hexToBuf(artifactHex);
    const leaves = [];
    for (const s of segs) {
      if (s.redacted) {
        leaves.push(bytesBEToBigInt(hexToBuf(s.leaf_hex)));
      } else {
        const off = Number(s.artifact_offset);
        const len = Number(s.artifact_length);
        if (off + len > artifact.length) throw new Error('byte range outside artifact at seg ' + s.segment_id);
        const slice = artifact.slice(off, off + len);
        const cb = revealedContentBytes(format, slice, s.label || '');
        const content = crypto.contentScalar(s.segment_id, cb);
        const blinding = BigInt(s.blinding_decimal);
        leaves.push(crypto.leafFrom(content, blinding));
      }
    }
    const root = crypto.variableDepthFold(leaves);
    if (toHex32(root) !== bundle.original_root) {
      throw new Error('fold != original_root');
    }
  }

  // 4. table_hash + payload + signature + nullifier. table_hash is re-derived
  //    SOLELY from `segments` (the reveal/redact mask comes from each signed
  //    `redacted` flag); the `table_hash_hex` field, when present, is a
  //    convenience hint, NOT authoritative — the signature over the recomputed
  //    payload is. (So flipping a flag changes the recomputed table_hash and
  //    breaks the signature, per RT-1.)
  const th = tableHash(segs);
  const payload = signingPayload(bundle.original_root, format, n, bundle.recipient_id, th);
  const sig = hexToBuf(bundle.signature_hex);
  if (!ed25519.verify(sig, payload, issuerPubkey)) throw new Error('Ed25519 signature invalid');

  const rootRaw = hexToBuf(bundle.original_root);
  const nf = nullifier(rootRaw, th, bundle.recipient_id);
  if (nf.toString('hex') !== bundle.nullifier) throw new Error('nullifier mismatch');
}

async function main() {
  const data = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
  assert.strictEqual(data.scheme, 'redaction-signed-merkle-adr0030-v3', 'scheme mismatch');
  assert.strictEqual(data.obj_domain, OBJ_DOMAIN, 'obj_domain mismatch');
  assert.strictEqual(data.domain_tags.bundle, BUNDLE_V3_PREFIX, 'bundle tag mismatch');
  assert.strictEqual(data.domain_tags.table, TABLE_V3_PREFIX, 'table tag mismatch');
  assert.strictEqual(data.domain_tags.nullifier, NULLIFIER_V1_PREFIX, 'nullifier tag mismatch');
  assert.strictEqual(data.domain_tags.blind, BLIND_PREFIX, 'blind tag mismatch');
  assert.strictEqual(Number(data.max_redaction_segments), Number(MAX_REDACTION_SEGMENTS), 'cap mismatch');

  const poseidon = await buildPoseidon();
  const blindSecret = hexToBuf(data.blind_secret_hex);
  const contentHash = hexToBuf(data.content_hash_hex);
  const issuerPubkey = hexToBuf(data.issuer_ed25519_pubkey_hex);
  const crypto = makeCrypto(poseidon, blindSecret, contentHash);
  let checks = 0;

  // 1. Per-format positive bundles — each must fully verify, and the recomputed
  //    table_hash must match the bundle's convenience field (parity pin).
  for (const fmt of ['pdf-object', 'text-line', 'pdf-xref-stream', 'ooxml-part']) {
    const b = data.format_bundles[fmt];
    assert.ok(b, `missing ${fmt} bundle`);
    verifyV3(b, crypto, issuerPubkey, fmt);
    assert.strictEqual(tableHash(b.segments).toString('hex'), b.table_hash_hex, `${fmt} table_hash parity`);
    checks++;
  }

  // 2. Variable-depth fold roots: N=2, N=3 (Fr(0) padding), N=1024 + parity.
  for (const key of ['n2', 'n3']) {
    const fv = data.fold_vectors[key];
    const leaves = fv.leaves_hex.map((h) => bytesBEToBigInt(hexToBuf(h)));
    assert.strictEqual(leaves.length, fv.n, `${key} leaf count`);
    const root = crypto.variableDepthFold(leaves);
    assert.strictEqual(toHex32(root), fv.root_hex, `${key} fold root mismatch`);
    checks++;
  }
  {
    // N=1024: fold the 1024 provided leaf hexes (Poseidon-only — fast), assert
    // the root + the legacy fixed-1024 parity. To independently pin the leaf
    // construction we ALSO reconstruct + check a small sample of Pedersen leaves
    // (full 1024 in pure-bigint JS is prohibitively slow; the depth-10 fold over
    // the supplied leaves is the cross-language root check).
    const fv = data.fold_vectors.n1024;
    assert.strictEqual(fv.leaves_hex.length, 1024, 'n1024 leaf count');
    const leaves = fv.leaves_hex.map((h) => bytesBEToBigInt(hexToBuf(h)));
    const root = crypto.variableDepthFold(leaves);
    assert.strictEqual(toHex32(root), fv.root_hex, 'n1024 fold root mismatch');
    assert.strictEqual(fv.root_hex, fv.legacy_fixed_1024_root_hex, 'n1024 legacy parity mismatch');
    assert.strictEqual(fv.parity, true, 'n1024 parity flag');
    // Sample leaf reconstruction (indices 0 and 1023) pins the leaf_rule.
    for (const i of [0, 1023]) {
      const content = crypto.contentScalar(i, Buffer.from(`leaf-content-${i}`, 'ascii'));
      const blinding = crypto.deriveBlinding(i);
      assert.strictEqual(toHex32(crypto.leafFrom(content, blinding)), fv.leaves_hex[i], `n1024 leaf[${i}] reconstruction`);
    }
    checks++;
  }

  // 3. all-redacted + none-redacted bundles both verify.
  verifyV3(data.all_redacted_bundle, crypto, issuerPubkey, data.all_redacted_bundle.format);
  checks++;
  verifyV3(data.none_redacted_bundle, crypto, issuerPubkey, data.none_redacted_bundle.format);
  checks++;

  // 4. Byte-dump fixture: self-check the byte layout end-to-end. Its
  //    original_root is a fixed layout anchor (NOT a fold), so verifyFold=false.
  {
    const bd = data.byte_dump;
    const th = tableHash(bd.segments);
    assert.strictEqual(th.toString('hex'), bd.table_hash_hex, 'byte_dump table_hash');
    const payload = signingPayload(bd.original_root, bd.format, bd.segment_count, bd.recipient_id, th);
    assert.strictEqual(Buffer.from(payload).toString('hex'), bd.signing_payload_hex, 'byte_dump payload');
    assert.ok(ed25519.verify(hexToBuf(bd.signature_hex), payload, issuerPubkey), 'byte_dump signature');
    const nf = nullifier(hexToBuf(bd.original_root), th, bd.recipient_id);
    assert.strictEqual(nf.toString('hex'), bd.nullifier, 'byte_dump nullifier');
    checks++;
  }

  // 5. Negative vectors — each MUST be rejected for the stated reason.
  const neg = data.negatives;

  // N=0 / N=1: structural reject on the count.
  assert.throws(() => {
    const b = { segment_count: 0, segments: [], original_root: '00'.repeat(32), recipient_id: '1' };
    verifyV3(b, crypto, issuerPubkey, 'text-line');
  }, /N out of/, 'N=0 must reject');
  checks++;
  assert.throws(() => {
    const b = {
      segment_count: 1,
      segments: neg.n1_rejected.segments,
      original_root: '00'.repeat(32),
      recipient_id: '1',
    };
    verifyV3(b, crypto, issuerPubkey, 'text-line');
  }, /N out of/, 'N=1 must reject');
  checks++;

  // Over-cap: reject on the declared count BEFORE allocating leaves.
  assert.throws(() => {
    const b = {
      segment_count: neg.over_cap_rejected.segment_count,
      segments: [],
      original_root: '00'.repeat(32),
      recipient_id: '1',
    };
    verifyV3(b, crypto, issuerPubkey, 'text-line');
  }, /N out of/, 'over-cap must reject');
  checks++;

  // Flip-flag: signature must fail (table_hash changed under a stale signature).
  assert.throws(() => {
    verifyV3(neg.flip_flag_signature_fails.bundle, crypto, issuerPubkey, 'text-line');
  }, /signature invalid/, 'flip-flag must fail signature');
  checks++;

  // Tampered revealed bytes: fold must != original_root.
  assert.throws(() => {
    verifyV3(neg.tampered_revealed_bytes_fold_mismatch.bundle, crypto, issuerPubkey, 'text-line');
  }, /fold != original_root/, 'tampered bytes must break the fold');
  checks++;

  // Canonical-range: reject == r / == l; accept == r-1 / == l-1.
  const cr = neg.canonical_range;
  assert.throws(() => {
    verifyV3(cr.recipient_id_equals_r_rejected.bundle, crypto, issuerPubkey, 'text-line');
  }, /recipient_id/, 'recipient == r must reject');
  checks++;
  verifyV3(cr.recipient_id_equals_r_minus_1_accepted.bundle, crypto, issuerPubkey, 'text-line');
  checks++;

  assert.throws(() => {
    verifyV3(cr.blinding_equals_l_rejected.bundle, crypto, issuerPubkey, 'text-line');
  }, /blinding/, 'blinding == l must reject');
  checks++;
  verifyV3(cr.blinding_equals_l_minus_1_accepted.bundle, crypto, issuerPubkey, 'text-line');
  checks++;

  assert.throws(() => {
    verifyV3(cr.leaf_hex_equals_r_rejected.bundle, crypto, issuerPubkey, 'text-line');
  }, /leaf_hex/, 'leaf_hex == r must reject');
  checks++;
  verifyV3(cr.leaf_hex_equals_r_minus_1_accepted.bundle, crypto, issuerPubkey, 'text-line');
  checks++;

  // Defensive: the canonical-form rejects must NOT silently mod-reduce. Assert r
  // and l themselves fail their validators directly.
  assert.ok(!validRecipient(BN254_R.toString()), 'r must not pass recipient validator');
  assert.ok(validRecipient((BN254_R - 1n).toString()), 'r-1 must pass recipient validator');
  assert.ok(!validBlinding(BJJ_L.toString()), 'l must not pass blinding validator');
  assert.ok(validBlinding((BJJ_L - 1n).toString()), 'l-1 must pass blinding validator');
  assert.ok(!validLeafHex(toHex32(BN254_R)), 'r must not pass leaf_hex validator');
  assert.ok(validLeafHex(toHex32(BN254_R - 1n)), 'r-1 must pass leaf_hex validator');
  checks++;

  console.log(`PASS test_redaction.js — ${checks} checks (ADR-0030 V3 signed-Merkle redaction)`);
}

main().catch((e) => {
  console.error('FAIL test_redaction.js:', e.message);
  process.exit(1);
});
