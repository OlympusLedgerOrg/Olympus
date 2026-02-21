pragma circom 2.0.0;

include "./poseidon.circom";

// Poseidon-based Merkle proof for a fixed depth binary tree.
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth]; // 0 = current node is left, 1 = right
    signal output root;

    signal hash[depth + 1];
    component hashers[depth];
    signal left[depth];
    signal right[depth];
    hash[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices must be boolean
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        // Select left/right without non-quadratic expressions:
        // left = hash[i] when pathIndices=0, else pathElements[i]
        // right = pathElements[i] when pathIndices=0, else hash[i]
        left[i] <== hash[i] + pathIndices[i] * (pathElements[i] - hash[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (hash[i] - pathElements[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        hash[i + 1] <== hashers[i].out;
    }

    root <== hash[depth];
}
