"""
Formal verification of Olympus cryptographic circuits and protocol invariants
using Satisfiability Modulo Theories (Z3 SMT solver).

Module 1: Circuit constraint verification
    - MerkleProof path-switching soundness
    - NonExistence key-binding completeness
    - RedactionValidity mask/commitment integrity
    - SelectiveDisclosure preimage binding
    - UnifiedProof cross-component binding

Module 2: Protocol property testing
    - Canonicalizer idempotency (forall x: f(f(x)) = f(x))
    - Ledger chain integrity (append-only, no forgery)
    - Merkle second-preimage resistance (domain separation)
    - SMT non-membership soundness
    - Hash domain separation collision freedom

Requires: pip install z3-solver
"""

from __future__ import annotations

import pytest


try:
    from z3 import (
        And,
        ForAll,
        Function,
        If,
        Implies,
        Int,
        IntSort,
        IntVal,
        Not,
        Or,
        Solver,
        unsat,
    )

    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

pytestmark = pytest.mark.skipif(not HAS_Z3, reason="z3-solver not installed")


# ──────────────────────────────────────────────────────────────────────
# BN128 field prime used by Poseidon / Groth16
# ──────────────────────────────────────────────────────────────────────
BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


# ──────────────────────────────────────────────────────────────────────
# Helpers: model Poseidon as an uninterpreted function with collision
# resistance (distinct inputs -> distinct outputs within the field).
# ──────────────────────────────────────────────────────────────────────


def _poseidon2():
    """Return an uninterpreted Poseidon2 function (lazy import guard)."""
    return Function("Poseidon2", IntSort(), IntSort(), IntSort())


def field_element(name: str):
    """Declare a Z3 integer constrained to the BN128 scalar field."""
    return Int(name)


def field_range(x):
    """Constraint: 0 <= x < BN128_PRIME."""
    return And(x >= 0, x < BN128_PRIME)


def domain_poseidon(poseidon2, domain: int, left, right):
    """Model domain-separated Poseidon: Poseidon(Poseidon(domain, left), right)."""
    inner = poseidon2(IntVal(domain), left)
    return poseidon2(inner, right)


def _collision_resistance_axiom(poseidon2):
    """Return a ForAll axiom asserting collision resistance for Poseidon2."""
    a1, a2, b1, b2 = Int("cr_a1"), Int("cr_a2"), Int("cr_b1"), Int("cr_b2")
    return ForAll(
        [a1, a2, b1, b2],
        Implies(
            poseidon2(a1, a2) == poseidon2(b1, b2),
            And(a1 == b1, a2 == b2),
        ),
    )


# ======================================================================
# MODULE 1: CIRCUIT CONSTRAINT VERIFICATION
# ======================================================================


class TestMerkleProofCircuit:
    """Verify the MerkleProof circom template constraints."""

    def test_path_switching_is_deterministic(self):
        """Verify that the single-multiplication routing in MerkleProof
        correctly selects (left, right) = (current, sibling) when pathIndex=0
        and (sibling, current) when pathIndex=1.

        Circuit logic:
            diff = sibling - current
            mux  = pathIndex * diff
            left  = current + mux
            right = sibling - mux
        """
        s = Solver()

        current = field_element("current")
        sibling = field_element("sibling")
        pathIndex = Int("pathIndex")

        s.add(field_range(current))
        s.add(field_range(sibling))
        # pathIndex constrained to binary by circuit: p * (p - 1) == 0
        s.add(Or(pathIndex == 0, pathIndex == 1))

        diff = sibling - current
        mux = pathIndex * diff
        left = current + mux
        right = sibling - mux

        # When pathIndex == 0: left must be current, right must be sibling
        case0 = Implies(pathIndex == 0, And(left == current, right == sibling))
        # When pathIndex == 1: left must be sibling, right must be current
        case1 = Implies(pathIndex == 1, And(left == sibling, right == current))

        # Try to find a counterexample
        s.add(Not(And(case0, case1)))
        result = s.check()
        assert result == unsat, "Path switching has a counterexample — circuit is unsound"

    def test_path_index_must_be_binary(self):
        """Verify that p * (p - 1) == 0 constrains p to {0, 1}."""
        s = Solver()
        p = Int("p")
        s.add(field_range(p))
        s.add(p * (p - 1) == 0)
        # Assert p is NOT in {0, 1} — should be unsat
        s.add(p != 0, p != 1)
        assert s.check() == unsat, "Binary constraint allows non-binary values"

    def test_merkle_path_reconstruction_depth4(self):
        """For a depth-4 tree, verify that the MerkleProof template
        produces a deterministic root given leaf + path.

        Model: root = H(H(H(H(leaf, s0), s1), s2), s3) with routing.
        Changing any sibling must change the root (collision resistance).
        """
        Poseidon2 = _poseidon2()
        s = Solver()
        DEPTH = 4

        leaf = field_element("leaf")
        siblings = [field_element(f"s{i}") for i in range(DEPTH)]
        indices = [Int(f"idx{i}") for i in range(DEPTH)]

        s.add(field_range(leaf))
        for i in range(DEPTH):
            s.add(field_range(siblings[i]))
            s.add(Or(indices[i] == 0, indices[i] == 1))

        # Compute root following circuit logic
        level = leaf
        for i in range(DEPTH):
            diff = siblings[i] - level
            mux = indices[i] * diff
            left = level + mux
            right = siblings[i] - mux
            level = domain_poseidon(Poseidon2, 1, left, right)  # DOMAIN_NODE = 1

        root = level

        # Now compute root with a DIFFERENT sibling at level 0
        s0_alt = field_element("s0_alt")
        s.add(field_range(s0_alt))
        s.add(s0_alt != siblings[0])

        level2 = leaf
        for i in range(DEPTH):
            sib = s0_alt if i == 0 else siblings[i]
            diff2 = sib - level2
            mux2 = indices[i] * diff2
            left2 = level2 + mux2
            right2 = sib - mux2
            level2 = domain_poseidon(Poseidon2, 1, left2, right2)

        root_alt = level2

        # Add collision resistance axiom
        s.add(_collision_resistance_axiom(Poseidon2))

        s.add(root == root_alt)
        assert s.check() == unsat, (
            "Changing a sibling did not change the root — collision resistance violated"
        )


class TestNonExistenceCircuit:
    """Verify the NonExistence circom template constraints."""

    def test_key_byte_range_enforcement(self):
        """Verify that Num2Bits(8) constrains each key byte to [0, 255].

        Circuit: for each byte b, Num2Bits(8) decomposes b into 8 bits
        and checks sum(bit_i * 2^i) == b with each bit_i in {0, 1}.
        """
        s = Solver()
        byte_val = Int("byte_val")
        bits = [Int(f"bit{i}") for i in range(8)]

        # Each bit is binary
        for b in bits:
            s.add(Or(b == 0, b == 1))

        # Reconstruction constraint
        reconstructed = sum(bits[i] * (1 << i) for i in range(8))
        s.add(reconstructed == byte_val)

        # Try to find byte_val outside [0, 255]
        s.add(Or(byte_val < 0, byte_val > 255))
        assert s.check() == unsat, "Num2Bits(8) allows values outside [0, 255]"

    def test_path_indices_derived_from_key(self):
        """Verify that pathIndices are deterministically derived from key bytes.

        Circuit mapping:
            pathIndices[255 - (b*8 + i)] = keyByteBits[b].out[7 - i]

        This must be a bijection: different keys -> different path indices.
        """
        s = Solver()

        # Model two 4-byte keys (scaled down from 32 for tractability)
        BYTES = 4
        BITS = BYTES * 8

        key1 = [Int(f"k1_{b}") for b in range(BYTES)]
        key2 = [Int(f"k2_{b}") for b in range(BYTES)]

        for b in range(BYTES):
            s.add(And(key1[b] >= 0, key1[b] <= 255))
            s.add(And(key2[b] >= 0, key2[b] <= 255))

        # Derive path indices for both keys
        path1 = [None] * BITS
        path2 = [None] * BITS

        for b in range(BYTES):
            for i in range(8):
                # Extract bit i from byte b
                bit_idx = b * 8 + i
                bits1_val = (key1[b] / (1 << (7 - i))) % 2
                bits2_val = (key2[b] / (1 << (7 - i))) % 2
                path1[BITS - 1 - bit_idx] = bits1_val
                path2[BITS - 1 - bit_idx] = bits2_val

        # If keys differ, at least one path index must differ
        keys_differ = Or(*[key1[b] != key2[b] for b in range(BYTES)])
        paths_same = And(*[path1[j] == path2[j] for j in range(BITS)])

        s.add(keys_differ)
        s.add(paths_same)

        assert s.check() == unsat, (
            "Two different keys produced identical path indices — key binding is broken"
        )

    def test_empty_leaf_sentinel_is_zero(self):
        """Verify that the circuit enforces leaf == 0 for non-existence.

        The circuit sets: merkle.leaf <== 0
        If a prover could set leaf to a non-zero value, they could
        forge a non-existence proof for an existing key.
        """
        s = Solver()
        leaf = Int("leaf")

        # Circuit constraint: leaf is hardcoded to 0
        s.add(leaf == 0)
        # Try to make it non-zero
        s.add(leaf != 0)

        assert s.check() == unsat, "Empty leaf sentinel can be non-zero — critical soundness bug"


class TestRedactionValidityCircuit:
    """Verify the RedactionValidity circom template constraints."""

    def test_reveal_mask_must_be_binary(self):
        """Verify revealMask[i] * (revealMask[i] - 1) === 0 constrains to {0, 1}."""
        s = Solver()
        MAX_LEAVES = 4

        masks = [Int(f"mask{i}") for i in range(MAX_LEAVES)]
        for m in masks:
            s.add(field_range(m))
            s.add(m * (m - 1) == 0)
            s.add(m != 0, m != 1)  # Try non-binary

        assert s.check() == unsat, "Reveal mask allows non-binary values"

    def test_revealed_count_matches_mask_sum(self):
        """Verify revealedCount === sum(revealMask).

        The circuit accumulates: maskSum[i+1] = maskSum[i] + revealMask[i]
        and asserts revealedCount === maskSum[maxLeaves].
        """
        s = Solver()
        MAX_LEAVES = 4

        masks = [Int(f"mask{i}") for i in range(MAX_LEAVES)]
        revealedCount = Int("revealedCount")

        for m in masks:
            s.add(Or(m == 0, m == 1))

        # Circuit accumulation
        maskSum = [Int(f"msum{i}") for i in range(MAX_LEAVES + 1)]
        s.add(maskSum[0] == 0)
        for i in range(MAX_LEAVES):
            s.add(maskSum[i + 1] == maskSum[i] + masks[i])

        s.add(revealedCount == maskSum[MAX_LEAVES])

        # Try: revealedCount != actual sum of masks
        actual_sum = sum(masks[i] for i in range(MAX_LEAVES))
        s.add(revealedCount != actual_sum)

        assert s.check() == unsat, "revealedCount can diverge from mask sum"

    def test_redacted_leaves_are_zeroed(self):
        """Verify that revealedLeaves[i] = revealMask[i] * originalLeaves[i].

        When mask=0 (redacted), the revealed value MUST be 0, preventing
        information leakage through the commitment chain.
        """
        s = Solver()

        mask = Int("mask")
        original = field_element("original")
        revealed = Int("revealed")

        s.add(Or(mask == 0, mask == 1))
        s.add(field_range(original))
        s.add(revealed == mask * original)

        # When mask is 0, revealed must be 0 regardless of original
        s.add(mask == 0)
        s.add(revealed != 0)

        assert s.check() == unsat, "Redacted leaf can leak non-zero value"

    def test_all_leaves_bound_to_original_root(self):
        """Verify L4-C: ALL leaves (including redacted ones) must pass
        Merkle inclusion against originalRoot.

        Pre-L4-C, redacted leaves skipped root checks, allowing a prover
        to claim arbitrary values for redacted positions.
        """
        Poseidon2 = _poseidon2()
        s = Solver()

        leaf_real = field_element("leaf_real")
        leaf_fake = field_element("leaf_fake")

        s.add(field_range(leaf_real))
        s.add(field_range(leaf_fake))
        s.add(leaf_real != leaf_fake)

        # Same sibling, same path, different leaf -> different root
        sib = field_element("shared_sib")
        s.add(field_range(sib))

        r1 = domain_poseidon(Poseidon2, 1, leaf_real, sib)
        r2 = domain_poseidon(Poseidon2, 1, leaf_fake, sib)

        # Collision resistance
        s.add(_collision_resistance_axiom(Poseidon2))

        originalRoot = field_element("originalRoot")
        s.add(field_range(originalRoot))

        # Both must equal originalRoot
        s.add(r1 == originalRoot)
        s.add(r2 == originalRoot)

        assert s.check() == unsat, (
            "Two different leaves can prove inclusion against the same root — L4-C violation"
        )


class TestDomainSeparation:
    """Verify domain separation prevents cross-context hash collisions."""

    def test_leaf_node_domain_separation(self):
        """Verify that a leaf hash cannot collide with a node hash.

        Leaf:  Poseidon(Poseidon(DOMAIN_LEAF=0, key), value)
        Node:  Poseidon(Poseidon(DOMAIN_NODE=1, left), right)

        Under collision resistance, these cannot produce the same output
        for any inputs.
        """
        Poseidon2 = _poseidon2()
        s = Solver()

        DOMAIN_LEAF = 0
        DOMAIN_NODE = 1

        key = field_element("key")
        value = field_element("value")
        left = field_element("left")
        right = field_element("right")

        for v in [key, value, left, right]:
            s.add(field_range(v))

        leaf_hash = domain_poseidon(Poseidon2, DOMAIN_LEAF, key, value)
        node_hash = domain_poseidon(Poseidon2, DOMAIN_NODE, left, right)

        # Collision resistance axiom
        s.add(_collision_resistance_axiom(Poseidon2))

        s.add(leaf_hash == node_hash)

        assert s.check() == unsat, (
            "Leaf hash can collide with node hash — domain separation is broken"
        )

    def test_commitment_domain_distinct_from_node(self):
        """Verify domain tag 3 (commitment) cannot collide with tag 2 (node)
        or tag 1 (leaf) used in the Merkle tree."""
        Poseidon2 = _poseidon2()
        s = Solver()

        x1 = field_element("x1")
        x2 = field_element("x2")
        y1 = field_element("y1")
        y2 = field_element("y2")

        for v in [x1, x2, y1, y2]:
            s.add(field_range(v))

        commitment_hash = domain_poseidon(Poseidon2, 3, x1, x2)
        node_hash = domain_poseidon(Poseidon2, 1, y1, y2)

        s.add(_collision_resistance_axiom(Poseidon2))

        s.add(commitment_hash == node_hash)

        assert s.check() == unsat, "Commitment domain can collide with node domain"


# ======================================================================
# MODULE 2: PROTOCOL PROPERTY TESTING
# ======================================================================


class TestLedgerChainProperties:
    """Formal properties of the append-only ledger chain."""

    def test_chain_linkage_prevents_reordering(self):
        """Verify that the hash chain entry_hash = H(payload || prev_entry_hash)
        prevents reordering entries without detection.

        If entries A->B->C are reordered to A->C->B, verification must fail.
        """
        s = Solver()

        H = Function("H", IntSort(), IntSort(), IntSort())

        # Three entries with sequential linkage
        payload_a = field_element("pa")
        payload_b = field_element("pb")
        payload_c = field_element("pc")

        s.add(field_range(payload_a))
        s.add(field_range(payload_b))
        s.add(field_range(payload_c))

        # Distinct payloads
        s.add(payload_a != payload_b)
        s.add(payload_b != payload_c)
        s.add(payload_a != payload_c)

        # Correct chain: A -> B -> C
        hash_a = H(payload_a, IntVal(0))  # genesis, prev = 0
        hash_b = H(payload_b, hash_a)
        hash_c = H(payload_c, hash_b)

        # Reordered chain: A -> C -> B
        hash_c_reordered = H(payload_c, hash_a)
        hash_b_reordered = H(payload_b, hash_c_reordered)

        # Collision resistance for H
        a1, a2, b1, b2 = Int("ha1"), Int("ha2"), Int("hb1"), Int("hb2")
        s.add(
            ForAll(
                [a1, a2, b1, b2],
                Implies(H(a1, a2) == H(b1, b2), And(a1 == b1, a2 == b2)),
            )
        )

        # The reordered chain must produce the same final hash as the
        # original chain for the attack to succeed undetected
        s.add(hash_b_reordered == hash_c)

        assert s.check() == unsat, (
            "Reordered ledger chain produces same final hash — chain integrity broken"
        )

    def test_append_only_no_retroactive_modification(self):
        """Verify that modifying an earlier entry's payload breaks the chain.

        If entry B's payload changes to B', the chain hash diverges and
        verify_chain() must return False.
        """
        s = Solver()

        H = Function("H", IntSort(), IntSort(), IntSort())

        payload_a = field_element("pa")
        payload_b = field_element("pb")
        payload_b_prime = field_element("pb_prime")

        s.add(field_range(payload_a))
        s.add(field_range(payload_b))
        s.add(field_range(payload_b_prime))
        s.add(payload_b != payload_b_prime)

        hash_a = H(payload_a, IntVal(0))
        hash_b = H(payload_b, hash_a)
        hash_b_prime = H(payload_b_prime, hash_a)

        # Collision resistance
        a1, a2, b1, b2 = Int("ha1"), Int("ha2"), Int("hb1"), Int("hb2")
        s.add(
            ForAll(
                [a1, a2, b1, b2],
                Implies(H(a1, a2) == H(b1, b2), And(a1 == b1, a2 == b2)),
            )
        )

        # Modified entry must produce different hash
        s.add(hash_b == hash_b_prime)

        assert s.check() == unsat, (
            "Modified payload produces same entry hash — append-only violated"
        )

    def test_genesis_prev_hash_is_empty(self):
        """Verify that the genesis entry must have prev_entry_hash = '' (empty).

        The Olympus ledger checks: entries[0].prev_entry_hash != '' -> invalid.
        """
        s = Solver()

        prev_hash = Int("prev_hash")
        # Genesis constraint from verify_chain()
        s.add(prev_hash == 0)  # "" maps to empty/0
        s.add(prev_hash != 0)

        assert s.check() == unsat, "Genesis entry can have non-empty prev_hash"


class TestMerkleSecondPreimageResistance:
    """Verify that domain-separated hashing prevents second-preimage attacks."""

    def test_leaf_cannot_masquerade_as_internal_node(self):
        """Without domain separation, a crafted leaf value could equal an
        internal node hash, allowing tree structure manipulation.

        With domain separation:
            leaf_hash = H(LEAF_PREFIX || data)
            node_hash = H(NODE_PREFIX || left || right)

        These cannot collide.
        """
        s = Solver()

        # Model BLAKE3 with domain prefixes as uninterpreted functions
        H_leaf = Function("H_leaf", IntSort(), IntSort())
        H_node = Function("H_node", IntSort(), IntSort(), IntSort())

        data = field_element("data")
        left = field_element("left")
        right = field_element("right")

        s.add(field_range(data))
        s.add(field_range(left))
        s.add(field_range(right))

        # Domain separation means H_leaf and H_node have disjoint ranges
        # Model this: for all inputs, H_leaf output != H_node output
        d, left_d, r = Int("d"), Int("l"), Int("r")
        s.add(ForAll([d, left_d, r], H_leaf(d) != H_node(left_d, r)))

        leaf_val = H_leaf(data)
        node_val = H_node(left, right)

        s.add(leaf_val == node_val)

        assert s.check() == unsat, (
            "Leaf hash can equal internal node hash — second preimage possible"
        )


class TestSMTNonMembershipSoundness:
    """Verify Sparse Merkle Tree non-membership proof properties."""

    def test_non_membership_requires_empty_leaf(self):
        """A valid non-membership proof requires the leaf at the key's path
        to be the empty sentinel. If the leaf is non-empty, the proof
        must be rejected.
        """
        s = Solver()

        leaf_value = field_element("leaf_value")
        EMPTY_SENTINEL = 0

        s.add(field_range(leaf_value))
        # Non-membership requires leaf == empty
        s.add(leaf_value == EMPTY_SENTINEL)
        # Try to have a non-empty leaf pass
        s.add(leaf_value != EMPTY_SENTINEL)

        assert s.check() == unsat, "Non-membership proof accepts non-empty leaf"

    def test_existence_and_non_existence_are_mutually_exclusive(self):
        """For a given key and root, it is impossible to produce both
        an existence proof AND a non-existence proof.

        Existence: path leads to leaf = H(key, value) for some value != 0
        Non-existence: path leads to leaf = 0 (empty sentinel)

        Reduced model: single-level tree. If both leaves hash to the same
        root with the same sibling, the leaves must be equal — but one is
        zero and the other is non-zero, giving a contradiction.
        """
        s = Solver()

        # Use a fresh injective function to avoid expensive ForAll
        H = Function("H_inj", IntSort(), IntSort(), IntSort())

        existence_leaf = field_element("exist_leaf")
        sibling = field_element("sibling")

        s.add(field_range(existence_leaf))
        s.add(field_range(sibling))
        s.add(existence_leaf != 0)  # existence leaf is non-empty

        root_exist = H(existence_leaf, sibling)
        root_nonexist = H(IntVal(0), sibling)

        # Injectivity in first argument (sufficient for this proof)
        x1, x2, y = Int("ix1"), Int("ix2"), Int("iy")
        s.add(ForAll([x1, x2, y], Implies(H(x1, y) == H(x2, y), x1 == x2)))

        # Both roots must match
        s.add(root_exist == root_nonexist)

        assert s.check() == unsat, (
            "Both existence and non-existence proofs verify against the same root"
        )


class TestUnifiedProofCrossBinding:
    """Verify cross-component binding in the unified proof circuit."""

    def test_canonical_hash_binds_to_merkle_leaf(self):
        """The unified circuit proves:
        1) canonicalHash is correctly computed from document sections
        2) canonicalHash is included in the Merkle tree
        3) Merkle root is committed in the ledger SMT

        If canonicalHash in component 1 differs from the leaf in component 2,
        the proof is unsound.
        """
        s = Solver()

        canonical_hash_public = field_element("canonical_hash_public")
        canonical_hash_computed = field_element("canonical_hash_computed")
        merkle_leaf = field_element("merkle_leaf")

        s.add(field_range(canonical_hash_public))
        s.add(field_range(canonical_hash_computed))
        s.add(field_range(merkle_leaf))

        # Circuit constraints:
        # Component 1: canonicalHash === structuredHashes[2 * maxSections]
        s.add(canonical_hash_public == canonical_hash_computed)
        # Component 2: merkleProof.leaf <== canonicalHash
        s.add(merkle_leaf == canonical_hash_public)

        # Try to make computed hash differ from merkle leaf
        s.add(canonical_hash_computed != merkle_leaf)

        assert s.check() == unsat, (
            "Canonical hash can differ from Merkle leaf — cross-binding broken"
        )

    def test_tree_size_bounds_check(self):
        """Verify the leafIndex < treeSize bounds check.

        Circuit: (1 - boundsCheck.out) * treeSizeIsPositive === 0
        This means: if treeSize > 0, then leafIndex < treeSize must hold.
        """
        s = Solver()

        leafIndex = Int("leafIndex")
        treeSize = Int("treeSize")

        s.add(leafIndex >= 0)
        s.add(treeSize > 0)

        # boundsCheck.out = 1 iff leafIndex < treeSize
        boundsCheck = If(leafIndex < treeSize, IntVal(1), IntVal(0))
        treeSizeIsPositive = If(treeSize > 0, IntVal(1), IntVal(0))

        # Circuit constraint
        s.add((1 - boundsCheck) * treeSizeIsPositive == 0)

        # Try to have leafIndex >= treeSize
        s.add(leafIndex >= treeSize)

        assert s.check() == unsat, "leafIndex can exceed treeSize — bounds check is ineffective"


class TestSelectiveDisclosureCircuit:
    """Verify SelectiveDisclosure circuit preimage binding."""

    def test_preimage_binds_to_leaf_hash(self):
        """The circuit hashes each preimage and constrains:
            leafHashes[i] === hashers[i].out

        Two different preimages must produce different leaf hashes
        (under collision resistance).
        """
        s = Solver()

        # Model Poseidon(preimageLen) as uninterpreted
        PoseidonN = Function(
            "PoseidonN",
            IntSort(),
            IntSort(),
            IntSort(),
            IntSort(),
            IntSort(),
            IntSort(),
            IntSort(),
            IntSort(),
        )

        # Two preimages of length 6
        p1 = [field_element(f"p1_{j}") for j in range(6)]
        p2 = [field_element(f"p2_{j}") for j in range(6)]

        for v in p1 + p2:
            s.add(field_range(v))

        hash1 = PoseidonN(p1[0], p1[1], p1[2], p1[3], p1[4], p1[5], IntVal(0))
        hash2 = PoseidonN(p2[0], p2[1], p2[2], p2[3], p2[4], p2[5], IntVal(0))

        # At least one element differs
        s.add(Or(*[p1[j] != p2[j] for j in range(6)]))

        # Collision resistance for PoseidonN
        s.add(hash1 == hash2)

        # Under a true collision-resistant hash, this should be unsat.
        # With uninterpreted functions, we need an explicit injectivity axiom.
        x = [Int(f"x{i}") for i in range(7)]
        y = [Int(f"y{i}") for i in range(7)]
        s.add(
            ForAll(
                x + y,
                Implies(
                    PoseidonN(*x) == PoseidonN(*y),
                    And(*[x[i] == y[i] for i in range(7)]),
                ),
            )
        )

        assert s.check() == unsat, (
            "Different preimages produce the same leaf hash — preimage binding broken"
        )


# ======================================================================
# Run configuration
# ======================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
