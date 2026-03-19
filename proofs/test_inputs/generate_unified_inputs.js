#!/usr/bin/env node

/**
 * Witness generator for unified_canonicalization_inclusion_root_sign circuit
 *
 * This script generates witness inputs for the unified proof circuit that verifies:
 * 1. Document canonicalization (Poseidon hash over sections)
 * 2. Merkle inclusion in ledger tree
 * 3. Ledger root commitment in SMT
 *
 * Note: Checkpoint integrity is verified at the Python layer via federation
 * signatures, not in the circuit.
 *
 * Usage:
 *   node generate_unified_inputs.js > unified_input.json
 *
 * The script produces a JSON file suitable for circom witness generation.
 */

const poseidon = require('circomlibjs').poseidon;
const { buildPoseidon } = require('circomlibjs');
const fs = require('fs');
const { hash } = require('blake3');

// BN128 scalar field prime (alt_bn128) used by Circom/snarkjs
const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Domain separation tag for structured canonicalization (matches protocol/poseidon_tree.py)
const POSEIDON_DOMAIN_COMMITMENT = 3;

/**
 * Convert BLAKE3 hash to BN128 field element (matching protocol/hashes.py:blake3_to_field_element)
 *
 * @param {Buffer} blake3Hash - 32-byte BLAKE3 hash
 * @returns {string} Field element as decimal string
 */
function blake3ToFieldElement(blake3Hash) {
    // Convert 32-byte hash to big integer (big-endian)
    let bigInt = 0n;
    for (let i = 0; i < blake3Hash.length; i++) {
        bigInt = (bigInt << 8n) | BigInt(blake3Hash[i]);
    }
    // Reduce into BN128 scalar field
    const fieldElement = bigInt % SNARK_SCALAR_FIELD;
    return fieldElement.toString();
}

/**
 * Compute domain-separated Poseidon hash: Poseidon(Poseidon(domain, left), right)
 * Matches protocol/poseidon_tree.py:poseidon_hash_with_domain and circuit DomainPoseidon template
 *
 * @param {*} poseidonHash - Poseidon hash function from circomlibjs
 * @param {number} domain - Domain separation tag (e.g., 3 for POSEIDON_DOMAIN_COMMITMENT)
 * @param {BigInt|string} left - Left input as BigInt or decimal string
 * @param {BigInt|string} right - Right input as BigInt or decimal string
 * @returns {string} Hash output as decimal string
 */
function domainPoseidon(poseidonHash, domain, left, right) {
    // Convert inputs to BigInt
    const leftBig = typeof left === 'string' ? BigInt(left) : left;
    const rightBig = typeof right === 'string' ? BigInt(right) : right;

    // Inner hash: Poseidon(domain, left)
    const innerHash = poseidonHash([BigInt(domain), leftBig]);

    // Outer hash: Poseidon(innerHash, right)
    const outerHash = poseidonHash([innerHash, rightBig]);

    return poseidonHash.F.toString(outerHash);
}

/**
 * Generate witness inputs for unified proof circuit
 *
 * @param {Object} params - Input parameters
 * @param {Array<string>} params.documentSections - Canonicalized document sections as UTF-8 strings
 * @param {number} params.sectionCount - Number of actual sections (rest are padding)
 * @param {string} params.merkleRoot - Expected Merkle root as decimal string
 * @param {Array<string>} params.merklePath - Merkle proof siblings as decimal strings
 * @param {Array<number>} params.merkleIndices - Merkle path indices (0=left, 1=right)
 * @param {number} params.leafIndex - Position in Merkle tree
 * @param {string} params.ledgerRoot - SMT root hash as decimal string
 * @param {Array<string>} params.ledgerPathElements - SMT path siblings as decimal strings
 * @param {Array<number>} params.ledgerPathIndices - SMT path indices
 * @returns {Object} Circuit inputs in circom format
 */
async function generateUnifiedInputs(params) {
    // Initialize Poseidon hash
    const poseidonHash = await buildPoseidon();

    // Validate inputs
    const maxSections = 8;  // Must match circuit parameter
    const merkleDepth = 20;  // Must match circuit parameter
    const smtDepth = 256;    // Must match circuit parameter

    if (params.documentSections.length > maxSections) {
        throw new Error(`Too many sections: ${params.documentSections.length} > ${maxSections}`);
    }

    if (params.merklePath.length !== merkleDepth) {
        throw new Error(`Invalid Merkle path length: ${params.merklePath.length} != ${merkleDepth}`);
    }

    if (params.ledgerPathElements.length !== smtDepth) {
        throw new Error(`Invalid SMT path length: ${params.ledgerPathElements.length} != ${smtDepth}`);
    }

    // Compute sectionLengths and sectionHashes for actual sections
    const sectionLengths = [];
    const sectionHashes = [];

    for (let i = 0; i < params.documentSections.length; i++) {
        const section = params.documentSections[i];
        const sectionBytes = Buffer.from(section, 'utf-8');

        // Compute byte length
        sectionLengths.push(sectionBytes.length.toString());

        // Compute BLAKE3 hash and map to field element
        const blake3Hash = hash(sectionBytes);
        const fieldElement = blake3ToFieldElement(blake3Hash);
        sectionHashes.push(fieldElement);
    }

    // Pad sectionLengths and sectionHashes to maxSections with zeros
    while (sectionLengths.length < maxSections) {
        sectionLengths.push("0");
        sectionHashes.push("0");
    }

    // Pad document sections to maxSections with zeros (for backward compatibility)
    const paddedSections = [...params.documentSections];
    while (paddedSections.length < maxSections) {
        paddedSections.push("0");
    }

    // Compute canonicalHash using structured DomainPoseidon(3) chain
    // Chain: acc = sectionCount
    //   for each i: acc = DomainPoseidon(3)(acc, sectionLength_i)
    //               acc = DomainPoseidon(3)(acc, sectionHash_i)
    let canonicalHash = params.sectionCount.toString();

    for (let i = 0; i < maxSections; i++) {
        // acc = DomainPoseidon(3)(acc, sectionLength_i)
        canonicalHash = domainPoseidon(
            poseidonHash,
            POSEIDON_DOMAIN_COMMITMENT,
            canonicalHash,
            sectionLengths[i]
        );

        // acc = DomainPoseidon(3)(acc, sectionHash_i)
        canonicalHash = domainPoseidon(
            poseidonHash,
            POSEIDON_DOMAIN_COMMITMENT,
            canonicalHash,
            sectionHashes[i]
        );
    }

    // Build circuit inputs
    const inputs = {
        // Public inputs
        canonicalHash: canonicalHash,
        merkleRoot: params.merkleRoot,
        ledgerRoot: params.ledgerRoot,

        // Private inputs - document canonicalization
        documentSections: paddedSections,
        sectionCount: params.sectionCount.toString(),
        sectionLengths: sectionLengths,
        sectionHashes: sectionHashes,

        // Private inputs - Merkle inclusion
        merklePath: params.merklePath,
        merkleIndices: params.merkleIndices.map(i => i.toString()),
        leafIndex: params.leafIndex.toString(),

        // Private inputs - SMT ledger proof
        ledgerPathElements: params.ledgerPathElements,
        ledgerPathIndices: params.ledgerPathIndices.map(i => i.toString()),
    };

    return inputs;
}

/**
 * Generate example witness for testing
 * Creates a self-contained example with dummy values
 */
async function generateExample() {
    // Example document sections (would come from canonicalizer in practice)
    const documentSections = [
        "123456789",      // Section 1
        "987654321",      // Section 2
        "555555555",      // Section 3
    ];

    // Example Merkle proof (20 levels, all zeros for demo)
    const merklePath = Array(20).fill("0");
    const merkleIndices = Array(20).fill(0);

    // Example SMT proof (256 levels, all zeros for demo)
    const ledgerPathElements = Array(256).fill("0");
    const ledgerPathIndices = Array(256).fill(0);

    const params = {
        documentSections: documentSections,
        sectionCount: 3,
        merkleRoot: "12345678901234567890",
        merklePath: merklePath,
        merkleIndices: merkleIndices,
        leafIndex: 0,
        ledgerRoot: "98765432109876543210",
        ledgerPathElements: ledgerPathElements,
        ledgerPathIndices: ledgerPathIndices,
    };

    return await generateUnifiedInputs(params);
}

// Main execution
if (require.main === module) {
    generateExample()
        .then(inputs => {
            console.log(JSON.stringify(inputs, null, 2));
        })
        .catch(error => {
            console.error("Error generating witness:", error.message);
            process.exit(1);
        });
}

// Export for use as module
module.exports = {
    generateUnifiedInputs,
    generateExample,
};
