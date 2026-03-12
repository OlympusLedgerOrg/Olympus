#!/usr/bin/env node

/**
 * Witness generator for unified_canonicalization_inclusion_root_sign circuit
 *
 * This script generates witness inputs for the unified proof circuit that verifies:
 * 1. Document canonicalization (Poseidon hash over sections)
 * 2. Merkle inclusion in ledger tree
 * 3. Ledger root commitment in SMT
 * 4. Checkpoint binding
 *
 * Usage:
 *   node generate_unified_inputs.js > unified_input.json
 *
 * The script produces a JSON file suitable for circom witness generation.
 */

const poseidon = require('circomlibjs').poseidon;
const { buildPoseidon } = require('circomlibjs');
const fs = require('fs');

/**
 * Generate witness inputs for unified proof circuit
 *
 * @param {Object} params - Input parameters
 * @param {Array<string>} params.documentSections - Canonicalized document sections as decimal strings
 * @param {number} params.sectionCount - Number of actual sections (rest are padding)
 * @param {string} params.merkleRoot - Expected Merkle root as decimal string
 * @param {Array<string>} params.merklePath - Merkle proof siblings as decimal strings
 * @param {Array<number>} params.merkleIndices - Merkle path indices (0=left, 1=right)
 * @param {number} params.leafIndex - Position in Merkle tree
 * @param {string} params.ledgerRoot - SMT root hash as decimal string
 * @param {Array<string>} params.ledgerPathElements - SMT path siblings as decimal strings
 * @param {Array<number>} params.ledgerPathIndices - SMT path indices
 * @param {string} params.checkpointHash - Checkpoint hash as decimal string
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

    // Pad document sections to maxSections with zeros
    const paddedSections = [...params.documentSections];
    while (paddedSections.length < maxSections) {
        paddedSections.push("0");
    }

    // Compute canonical hash by chaining Poseidon hashes
    // First section: hash(section[0])
    let canonicalHash = poseidonHash.F.toString(poseidonHash([paddedSections[0]]));

    // Chain subsequent sections: hash(prev_hash, section[i])
    for (let i = 1; i < maxSections; i++) {
        canonicalHash = poseidonHash.F.toString(
            poseidonHash([BigInt(canonicalHash), BigInt(paddedSections[i])])
        );
    }

    // Build circuit inputs
    const inputs = {
        // Public inputs
        canonicalHash: canonicalHash,
        merkleRoot: params.merkleRoot,
        ledgerRoot: params.ledgerRoot,
        checkpointHash: params.checkpointHash,

        // Private inputs - document canonicalization
        documentSections: paddedSections,
        sectionCount: params.sectionCount.toString(),

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
        checkpointHash: "11111111111111111111",
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
