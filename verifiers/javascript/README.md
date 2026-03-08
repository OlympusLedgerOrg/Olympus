# JavaScript/TypeScript Verifier for Olympus

A standalone JavaScript/TypeScript implementation for verifying Olympus commitments.

## Installation

```bash
npm install
```

## Usage

### Node.js

```javascript
const { verifyBlake3Hash, verifyMerkleRoot } = require('./verifier');

// Verify a BLAKE3 hash
const data = Buffer.from('Hello, Olympus!');
const expectedHash = 'a1b2c3...';
const isValid = verifyBlake3Hash(data, expectedHash);

// Verify a Merkle root
const leaves = [Buffer.from('leaf1'), Buffer.from('leaf2')];
const root = verifyMerkleRoot(leaves);
```

### Browser

```html
<script type="module">
  import { verifyBlake3Hash } from './verifier.js';
  // Use the verifier functions
</script>
```

## Features

- ✅ BLAKE3 hash verification
- ✅ Merkle tree root computation
- ✅ Inclusion proof verification
- ✅ Works in Node.js and browsers
- ✅ Zero dependencies (uses Web Crypto API)

## API Reference

See `verifier.ts` for full TypeScript types and documentation.
