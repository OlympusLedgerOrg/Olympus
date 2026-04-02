#!/usr/bin/env node
// poseidon_tree_conformance.js
// Computes a 3-leaf domain-separated Poseidon SMT root using circomlibjs,
// matching the 256-level sparse Merkle tree in protocol/poseidon_smt.py.
// Output: JSON { root, leaf_hashes } — all decimal strings.
// Python test compares this against PoseidonSMT.get_root() for same inputs.
"use strict";
const { buildPoseidon } = require("circomlibjs");

const DOMAIN_LEAF = BigInt(0);
const DOMAIN_NODE = BigInt(1);
const TREE_HEIGHT = 256;

const SNARK_SCALAR_FIELD = BigInt(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const LEAVES = [
    { key: BigInt(1), value: BigInt(100) },
    { key: BigInt(2), value: BigInt(200) },
    { key: BigInt(3), value: BigInt(300) },
];

// Convert a BigInt key to a 256-bit MSB-first path (array of 0/1).
// Matches protocol/poseidon_smt._key_to_path_bits for a 32-byte big-endian key.
function keyToPathBits(keyBigInt) {
    const bits = [];
    // Treat key as 256-bit big-endian integer, extract MSB first
    for (let i = TREE_HEIGHT - 1; i >= 0; i--) {
        bits.push(Number((keyBigInt >> BigInt(i)) & BigInt(1)));
    }
    return bits;
}

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const h2 = (a, b) => F.toObject(poseidon([a, b]));
    const hashLeaf = (k, v) => h2(h2(DOMAIN_LEAF, k), v);
    const hashNode = (l, r) => h2(h2(DOMAIN_NODE, l), r);

    // Precompute empty hashes: empty[0] = 0, empty[i+1] = hashNode(empty[i], empty[i])
    const empty = [BigInt(0)];
    for (let i = 0; i < TREE_HEIGHT; i++) {
        empty.push(BigInt(hashNode(empty[i], empty[i]).toString()) % SNARK_SCALAR_FIELD);
    }

    // Sparse node store: path_key (string) -> hash (BigInt)
    const nodes = new Map();

    // pathKey: convert a bit-array prefix to a string key for the Map
    const pathKey = (bits) => bits.join(",");

    // siblingPath: flip the last bit
    const siblingPath = (bits) => {
        const s = bits.slice();
        s[s.length - 1] = 1 - s[s.length - 1];
        return s;
    };

    // Insert each leaf, propagating up from level 255 to root
    const leafHashes = [];
    for (const { key, value } of LEAVES) {
        const keyInt = key % SNARK_SCALAR_FIELD;
        const val = value % SNARK_SCALAR_FIELD;
        const path = keyToPathBits(key);
        let currentHash = BigInt(hashLeaf(keyInt, val).toString()) % SNARK_SCALAR_FIELD;

        // Go from leaf level (level 0 counting from leaf) up to root
        for (let level = 0; level < TREE_HEIGHT; level++) {
            const bitPos = TREE_HEIGHT - 1 - level;
            const nodePath = path.slice(0, bitPos + 1);
            const sibPath = siblingPath(nodePath);
            const sibKey = pathKey(sibPath);

            let siblingHash;
            if (nodes.has(sibKey)) {
                siblingHash = nodes.get(sibKey);
            } else {
                siblingHash = empty[level];
            }

            let parentHash;
            if (path[bitPos] === 0) {
                // Current is left child
                parentHash = BigInt(hashNode(currentHash, siblingHash).toString()) % SNARK_SCALAR_FIELD;
            } else {
                // Current is right child
                parentHash = BigInt(hashNode(siblingHash, currentHash).toString()) % SNARK_SCALAR_FIELD;
            }

            // Store parent at path up to bitPos
            const parentPath = bitPos === 0 ? [] : path.slice(0, bitPos);
            nodes.set(pathKey(parentPath), parentHash);
            currentHash = parentHash;
        }

        leafHashes.push(currentHash.toString());
    }

    // Root is at empty path
    const root = nodes.get(pathKey([])) || empty[TREE_HEIGHT];

    console.log(JSON.stringify({
        root: root.toString(),
        leaf_hashes: leafHashes,
    }));
}
main().catch(e => { console.error(e); process.exit(1); });
