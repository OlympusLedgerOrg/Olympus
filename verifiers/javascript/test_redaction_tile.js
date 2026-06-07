/**
 * Cross-language conformance for the rasterized tile-redaction commitment
 * (ADR-0023). Loads the shared golden vectors generated from the authoritative
 * Rust reference (src-tauri/src/zk/redaction_tile.rs) and re-verifies them with
 * the JavaScript verifier — proving byte-for-byte agreement across languages.
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const v = require('./verifier.js');

const VECTORS_PATH = path.join(__dirname, '..', 'test_vectors', 'tile_redaction_vectors.json');
const data = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));

let checks = 0;

// 1. tile_message_scalar derivation parity.
assert(data.tile_message_scalars.length > 0, 'no tile_message_scalars vectors');
for (const s of data.tile_message_scalars) {
  const m = v.tileMessageScalar(s.page, s.x, s.y, v.fromHex(s.tile_bytes_hex));
  assert.strictEqual(
    m.toString(), s.m_decimal,
    `tile_message_scalar mismatch @ (${s.page},${s.x},${s.y})`,
  );
  checks++;
}

// 2. Pedersen tile leaf parity.
assert(data.tile_leaves.length > 0, 'no tile_leaves vectors');
for (const l of data.tile_leaves) {
  const leafHex = v.commitTileLeafHex(
    l.page, l.x, l.y, v.fromHex(l.tile_bytes_hex), BigInt(l.blinding_decimal),
  );
  assert.strictEqual(
    leafHex, l.leaf_compressed_hex,
    `tile leaf mismatch @ (${l.page},${l.x},${l.y})`,
  );
  checks++;
}

// 3. tiles_root parity.
assert(data.tiles_root.length > 0, 'no tiles_root vectors');
for (const r of data.tiles_root) {
  const root = v.toHex(v.tilesRoot(r.leaves_hex.map((h) => v.fromHex(h))));
  assert.strictEqual(root, r.root_hex, `tiles_root mismatch: ${r.description}`);
  checks++;
}

// 4. Full bundle verification (positive).
assert.strictEqual(
  v.verifyRedactionBundle(data.bundle), data.bundle.expected_valid,
  'bundle did not verify as expected',
);
checks++;

// 5. Negative: tampered recipient breaks the signature.
{
  const b = JSON.parse(JSON.stringify(data.bundle));
  b.recipient_id = 'mallory';
  assert.strictEqual(v.verifyRedactionBundle(b), false, 'wrong recipient must fail');
  checks++;
}

// 6. Negative: tampered revealed artifact tile is rejected.
{
  const b = JSON.parse(JSON.stringify(data.bundle));
  b.artifact_tiles[0].tile_bytes_hex = v.toHex(new TextEncoder().encode('TAMPERED'));
  assert.strictEqual(v.verifyRedactionBundle(b), false, 'tampered revealed tile must fail');
  checks++;
}

// 7. Negative: tampered redacted leaf breaks root/signature binding.
{
  const b = JSON.parse(JSON.stringify(data.bundle));
  const t = b.tiles.find((t) => t.revealed_blinding_decimal == null);
  const bytes = v.fromHex(t.leaf_compressed_hex);
  bytes[0] ^= 0xff;
  t.leaf_compressed_hex = v.toHex(bytes);
  assert.strictEqual(v.verifyRedactionBundle(b), false, 'tampered leaf must fail');
  checks++;
}

// 8. Negative: malformed hex (odd-length / non-hex) in attacker-controlled
//    fields must be strictly rejected — parity with Rust's hex::decode.
for (const bad of ['abc', 'zz', 'gg00', '']) {
  // original_root_hex
  {
    const b = JSON.parse(JSON.stringify(data.bundle));
    b.original_root_hex = bad;
    assert.strictEqual(
      v.verifyRedactionBundle(b), false, `malformed original_root_hex "${bad}" must fail`,
    );
    checks++;
  }
  // signature_hex
  {
    const b = JSON.parse(JSON.stringify(data.bundle));
    b.signature_hex = bad;
    assert.strictEqual(
      v.verifyRedactionBundle(b), false, `malformed signature_hex "${bad}" must fail`,
    );
    checks++;
  }
  // a tile's leaf_compressed_hex
  {
    const b = JSON.parse(JSON.stringify(data.bundle));
    b.tiles[0].leaf_compressed_hex = bad;
    assert.strictEqual(
      v.verifyRedactionBundle(b), false, `malformed leaf_compressed_hex "${bad}" must fail`,
    );
    checks++;
  }
  // signer_ed25519_pubkey_hex (strict-decoded before signature verify)
  {
    const b = JSON.parse(JSON.stringify(data.bundle));
    b.signer_ed25519_pubkey_hex = bad;
    assert.strictEqual(
      v.verifyRedactionBundle(b), false, `malformed signer_ed25519_pubkey_hex "${bad}" must fail`,
    );
    checks++;
  }
  // a revealed tile's artifact bytes (strict-decoded during revealed-tile reopen)
  {
    const b = JSON.parse(JSON.stringify(data.bundle));
    b.artifact_tiles[0].tile_bytes_hex = bad;
    assert.strictEqual(
      v.verifyRedactionBundle(b), false, `malformed artifact tile_bytes_hex "${bad}" must fail`,
    );
    checks++;
  }
}

console.log(`✓ tile redaction conformance: ${checks} checks passed`);
