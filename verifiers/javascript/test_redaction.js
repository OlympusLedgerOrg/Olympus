/**
 * Cross-language conformance for the PDF object-level redaction commitment
 * (ADR-0025). Loads the shared golden vectors generated from the authoritative
 * Rust reference (src-tauri/src/zk/pdf_objects.rs) and reproduces every value
 * — per-object leaf, Merkle root, and redactedCommitment — byte-for-byte with
 * an independent JavaScript implementation (BLAKE3 via @noble/hashes, Poseidon
 * via circomlibjs).
 *
 * Leaf:  content = BLAKE3("OLY:REDACTION:OBJ:V1" || lp(objId_be) || objBytes) mod p
 *        leaf    = Poseidon(Poseidon(1, content), 0)
 * Node:  domainNode(d, l, r) = Poseidon(Poseidon(d, l), r)   (node domain 1)
 * Root:  depth-10 fold over leaves padded to 1024 with zero-leaves.
 * Commit: acc = revealedCount; for each padded leaf: acc = domainNode(3, acc, mask?leaf:0)
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { blake3 } = require('@noble/hashes/blake3.js');
const { buildPoseidon } = require('circomlibjs');

const OBJ_DOMAIN = 'OLY:REDACTION:OBJ:V1';
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'redaction_vectors.json');

function lpU32(buf) {
  const p = Buffer.alloc(4);
  p.writeUInt32BE(buf.length, 0);
  return Buffer.concat([p, Buffer.from(buf)]);
}

function objIdBE(id) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(id >>> 0, 0);
  return b;
}

function bytesBEToBigInt(u8) {
  let x = 0n;
  for (const b of u8) x = (x << 8n) | BigInt(b);
  return x;
}

function toHex32(x) {
  return x.toString(16).padStart(64, '0');
}

function makeVerifier(poseidon) {
  const obj = (x) => poseidon.F.toObject(x);
  const objectLeaf = (objId, objBytes) => {
    const input = Buffer.concat([
      Buffer.from(OBJ_DOMAIN, 'ascii'),
      lpU32(objIdBE(objId)),
      Buffer.from(objBytes),
    ]);
    const content = bytesBEToBigInt(blake3(input)) % P;
    const inner = obj(poseidon([1n, content]));
    return obj(poseidon([inner, 0n]));
  };
  const domainNode = (domain, left, right) => {
    const inner = obj(poseidon([BigInt(domain), left]));
    return obj(poseidon([inner, right]));
  };
  const merkleRoot = (leaves, depth, maxLeaves) => {
    let level = leaves.slice();
    while (level.length < maxLeaves) level.push(0n);
    for (let d = 0; d < depth; d++) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(domainNode(1, level[i], level[i + 1]));
      }
      level = next;
    }
    return level[0];
  };
  const redactedCommitment = (paddedLeaves, fullMask, revealedCount) => {
    let acc = BigInt(revealedCount);
    for (let i = 0; i < paddedLeaves.length; i++) {
      const val = fullMask[i] ? paddedLeaves[i] : 0n;
      acc = domainNode(3, acc, val);
    }
    return acc;
  };
  return { objectLeaf, domainNode, merkleRoot, redactedCommitment };
}

async function main() {
  const data = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
  assert.strictEqual(data.obj_domain, OBJ_DOMAIN, 'obj_domain mismatch');
  const poseidon = await buildPoseidon();
  const v = makeVerifier(poseidon);
  let checks = 0;

  // 1. Per-object leaf parity.
  const realLeaves = [];
  for (const o of data.objects) {
    const bytes = Buffer.from(o.bytes_hex, 'hex');
    const leaf = v.objectLeaf(o.obj_id, bytes);
    assert.strictEqual(toHex32(leaf), o.leaf_hex, `leaf mismatch for object ${o.obj_id}`);
    realLeaves.push(leaf);
    checks++;
  }

  // 2. Merkle root parity (leaves padded to max_leaves).
  const root = v.merkleRoot(realLeaves, data.tree_depth, data.max_leaves);
  assert.strictEqual(toHex32(root), data.original_root_hex, 'originalRoot mismatch');
  checks++;

  // 3. redactedCommitment parity over the full padded mask.
  const padded = realLeaves.slice();
  while (padded.length < data.max_leaves) padded.push(0n);
  const fullMask = new Array(data.max_leaves).fill(false);
  data.reveal_mask.forEach((b, i) => { fullMask[i] = b === 1; });
  const revealedCount = fullMask.filter(Boolean).length;
  assert.strictEqual(revealedCount, data.revealed_count, 'revealedCount mismatch');
  const commit = v.redactedCommitment(padded, fullMask, revealedCount);
  assert.strictEqual(commit.toString(), data.redacted_commitment_decimal, 'redactedCommitment mismatch');
  checks++;

  // 4. Negative: a tampered (redacted) object must NOT reproduce its leaf,
  //    confirming the leaf binds the object bytes.
  {
    const o = data.objects[data.reveal_mask.indexOf(0)];
    if (o) {
      const tampered = v.objectLeaf(o.obj_id, Buffer.from(o.bytes_hex + '00', 'hex'));
      assert.notStrictEqual(toHex32(tampered), o.leaf_hex, 'tampered bytes must not match leaf');
      checks++;
    }
  }

  console.log(`PASS test_redaction.js — ${checks} checks (ADR-0025 object-level redaction)`);
}

main().catch((e) => {
  console.error('FAIL test_redaction.js:', e.message);
  process.exit(1);
});
