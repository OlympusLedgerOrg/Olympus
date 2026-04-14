const { computeBlake3, merkleLeafHash, computeMerkleRoot, toHex } = require('./verifier');

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
        try {
          const data = Buffer.from(recordB64, 'base64');
          return toHex(computeBlake3(data));
        } catch (error) {
          throw new Error(`invalid base64 at index ${index}: ${error.message}`);
        }
      });
      break;

    case 'merkle_leaf_hash':
      hashes = request.records_b64.map((recordB64, index) => {
        try {
          const data = Buffer.from(recordB64, 'base64');
          return toHex(merkleLeafHash(data));
        } catch (error) {
          throw new Error(`invalid base64 at index ${index}: ${error.message}`);
        }
      });
      break;

    case 'merkle_root': {
      // All records_b64 are leaves of a single tree
      const leaves = request.records_b64.map((recordB64, index) => {
        try {
          return new Uint8Array(Buffer.from(recordB64, 'base64'));
        } catch (error) {
          throw new Error(`invalid base64 at index ${index}: ${error.message}`);
        }
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
