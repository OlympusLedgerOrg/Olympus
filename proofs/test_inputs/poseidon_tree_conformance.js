#!/usr/bin/env node
// poseidon_tree_conformance.js
// Computes a 3-leaf domain-separated Poseidon SMT root using circomlibjs.
// Output: JSON { root, leaf_hashes, node_01 } — all decimal strings.
// Python test compares this against PoseidonSMT.get_root() for same inputs.
"use strict";
const { buildPoseidon } = require("circomlibjs");

const DOMAIN_LEAF = BigInt(0);
const DOMAIN_NODE = BigInt(1);

const LEAVES = [
    { key: BigInt(1), value: BigInt(100) },
    { key: BigInt(2), value: BigInt(200) },
    { key: BigInt(3), value: BigInt(300) },
];

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const h2 = (a, b) => F.toObject(poseidon([a, b]));
    const hashLeaf = (k, v) => h2(h2(DOMAIN_LEAF, k), v);
    const hashNode = (l, r) => h2(h2(DOMAIN_NODE, l), r);

    const leafHashes = LEAVES.map(({ key, value }) => hashLeaf(key, value));
    const node01 = hashNode(leafHashes[0], leafHashes[1]);
    const root = hashNode(node01, leafHashes[2]);

    console.log(JSON.stringify({
        root: root.toString(),
        leaf_hashes: leafHashes.map(h => h.toString()),
        node_01: node01.toString(),
    }));
}
main().catch(e => { console.error(e); process.exit(1); });
