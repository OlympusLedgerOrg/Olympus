pragma circom 2.0.0;

/*
 * Sparse Merkle Tree non-membership proof with keyed path derivation.
 *
 * Statement proved:
 *   Given a public Poseidon Merkle root `root` and a public 32-byte `key`,
 *   the prover knows a Merkle authentication path from the key-derived
 *   position to the root such that the leaf at that position is the empty
 *   sentinel value 0.
 *
 * Key-to-path derivation:
 *   The 32-byte key is converted to a 256-bit path by extracting bits
 *   MSB-first from each byte (matching protocol/ssmf.py semantics).
 *   This ensures the circuit proves non-existence at the cryptographically
 *   bound position hash(key), not at an arbitrary index chosen by the prover.
 *
 * Default hash chain semantics:
 *   An empty subtree at height h has hash DEFAULT[h], where:
 *     DEFAULT[0] = 0   (empty leaf)
 *     DEFAULT[h] = Poseidon(DEFAULT[h-1], DEFAULT[h-1])
 *   The prover must supply siblings that are either real subtree hashes
 *   or default hashes at the correct level. The circuit verifies the
 *   Merkle path recomputes to `root` starting from leaf = 0.
 *
 * Security hardening:
 *   - Num2Bits range check on each key byte (ensures 0-255 range)
 *   - Key-to-path derivation inside the circuit (prevents index malleability)
 *   - Domain-separated Poseidon via MerkleTreeInclusionProof
 */

include "./lib/merkleProof.circom";
include "./lib/poseidon.circom";
include "./parameters.circom";

// Range-checked Num2Bits converter
template Num2BitsStrictNE(n) {
    signal input in;
    signal output out[n];
    var sum = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (1 - out[i]) === 0;  // Binary constraint
        sum += out[i] * (1 << i);
    }

    sum === in;
}

// Convert a single byte (0-255) to 8 bits MSB-first
template ByteToBitsMSB() {
    signal input byte;
    signal output bits[8];

    // Range check: byte must fit in 8 bits (0-255)
    component byteBits = Num2BitsStrictNE(8);
    byteBits.in <== byte;

    // Reverse bit order from LSB-first to MSB-first
    // byteBits.out[0] is LSB, bits[7] is LSB in our output
    // byteBits.out[7] is MSB, bits[0] is MSB in our output
    for (var i = 0; i < 8; i++) {
        bits[i] <== byteBits.out[7 - i];
    }
}

template NonExistence(depth) {
    // ---- Public inputs ----
    signal input root;
    signal input key[32];  // 32-byte key (each element 0-255)

    // ---- Private inputs ----
    signal input pathElements[depth];
    // Note: pathIndices is derived from key, not a private input anymore

    // --- Derive path from key ---
    // Convert 32 bytes to 256 bits MSB-first (matching protocol/ssmf.py)
    component keyBits[32];
    signal pathIndices[depth];

    for (var b = 0; b < 32; b++) {
        keyBits[b] = ByteToBitsMSB();
        keyBits[b].byte <== key[b];

        // Copy the 8 bits from this byte into pathIndices
        for (var bit = 0; bit < 8; bit++) {
            pathIndices[b * 8 + bit] <== keyBits[b].bits[bit];
        }
    }

    // --- Verify all pathIndices are binary (redundant but explicit) ---
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
    }

    // --- Prove inclusion of the empty leaf (0) at the key-derived path ---
    // This is the default hash chain: starting from sentinel value 0
    component merkle = MerkleTreeInclusionProof(depth);
    merkle.root <== root;
    merkle.leaf <== 0;

    for (var j = 0; j < depth; j++) {
        merkle.pathElements[j] <== pathElements[j];
        merkle.pathIndices[j] <== pathIndices[j];
    }
}

component main { public [root, key] } = NonExistence(NON_EXISTENCE_MERKLE_DEPTH);
