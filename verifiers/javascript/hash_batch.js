const { computeBlake3, merkleLeafHash, computeMerkleRoot, toHex } = require('./verifier');

/**
 * Strictly decode a base64 string, exiting on invalid input.
 * Buffer.from(str, 'base64') silently ignores invalid characters in Node.js,
 * so we re-encode and compare to detect malformed input.
 */
function strictBase64Decode(b64, index) {
  const buf = Buffer.from(b64, 'base64');
  const roundTrip = buf.toString('base64');
  // Normalize: strip trailing '=' padding for comparison
  if (roundTrip.replace(/=+$/, '') !== b64.replace(/=+$/, '')) {
    process.stderr.write(`invalid base64 at index ${index}\n`);
    process.exit(1);
  }
  return buf;
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
});

process.stdin.on('end', () => {
  const request = JSON.parse(input);
  // Default to "blake3" for backward compatibility
  const op = request.op || 'blake3';
  let hashes;

  switch (op) {
    case 'blake3':
      hashes = request.records_b64.map((recordB64, index) => {
        const data = strictBase64Decode(recordB64, index);
        return toHex(computeBlake3(data));
      });
      break;

    case 'merkle_leaf_hash':
      hashes = request.records_b64.map((recordB64, index) => {
        const data = strictBase64Decode(recordB64, index);
        return toHex(merkleLeafHash(data));
      });
      break;

    case 'merkle_root': {
      // All records_b64 are leaves of a single tree.
      // computeMerkleRoot already returns a hex string.
      const leaves = request.records_b64.map((recordB64, index) => {
        return new Uint8Array(strictBase64Decode(recordB64, index));
      });
      const root = computeMerkleRoot(leaves);
      hashes = [root];
      break;
    }

    default:
      process.stderr.write(`unknown op: ${op}\n`);
      process.exit(1);
  }

  process.stdout.write(JSON.stringify({ hashes }) + '\n');
});
