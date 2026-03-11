const { computeBlake3, toHex } = require('./verifier');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
});

process.stdin.on('end', () => {
  const request = JSON.parse(input);
  const hashes = request.records_b64.map((recordB64, index) => {
    try {
      const data = Buffer.from(recordB64, 'base64');
      return toHex(computeBlake3(data));
    } catch (error) {
      throw new Error(`invalid base64 at index ${index}: ${error.message}`);
    }
  });

  process.stdout.write(JSON.stringify({ hashes }) + '\n');
});
