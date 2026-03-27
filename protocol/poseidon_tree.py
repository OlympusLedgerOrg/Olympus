"""Poseidon Merkle utilities for bridging BLAKE3 data into ZK circuits.

The core tree functions (_poseidon_hash, _build_level, PoseidonMerkleTree) use
plain Poseidon(2) matching the circuit behavior in merkleProof.circom exactly.
This ensures that Python-generated Merkle roots and circuit-verified roots agree.

poseidon_hash_with_domain() is retained as a utility function for commitment
chains where domain separation is safe to introduce outside the Merkle path.

Domain separation tags (POSEIDON_DOMAIN_*) are defined for contexts outside
the Merkle tree verification path where they can be safely used:

    POSEIDON_DOMAIN_LEAF = 1   – leaf node hashing (external use)
    POSEIDON_DOMAIN_NODE = 2   – internal node hashing (external use)
    POSEIDON_DOMAIN_COMMITMENT = 3 – commitment chain hashing
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .hashes import SNARK_SCALAR_FIELD
from .poseidon_bn128 import poseidon_hash_bn128


# Domain separation tags for Poseidon hashing.
# These are injected as additive offsets to the capacity element of the
# Poseidon state before the permutation, ensuring that a hash produced in
# one context (e.g. leaf hashing) can never collide with a hash produced
# in another context (e.g. internal node hashing).
POSEIDON_DOMAIN_LEAF = 1
POSEIDON_DOMAIN_NODE = 2
POSEIDON_DOMAIN_COMMITMENT = 3


def poseidon_hash_with_domain(left: int, right: int, domain: int) -> int:
    """Compute Poseidon(left, right) with a domain-separation tag.

    The domain tag is mixed into the inputs by hashing
    ``Poseidon(Poseidon(domain, left), right)``. This ensures that identical
    ``(left, right)`` pairs produce different outputs under different domains
    while remaining compatible with the standard 2-arity Poseidon circuit
    (which only needs a thin wrapper template in circom).

    Args:
        left: First field element.
        right: Second field element.
        domain: Domain separation tag (small constant).

    Returns:
        Domain-tagged Poseidon hash as a field element.
    """
    tagged_left = poseidon_hash_bn128(domain % SNARK_SCALAR_FIELD, left % SNARK_SCALAR_FIELD)
    return poseidon_hash_bn128(tagged_left % SNARK_SCALAR_FIELD, right % SNARK_SCALAR_FIELD)


def _to_field_int(value: int | str | bytes, index: int = 0) -> int:
    """
    Normalize a value into the BN128 field as an integer.

    Args:
        value: The value to normalize (bytes, decimal string, or int).
        index: Leaf position index (only used for bytes to prevent collisions).

    For bytes inputs, the leaf is bound to its position by hashing
    [leaf_bytes || index] before mapping to the field. This ensures
    identical byte payloads at different positions produce distinct
    field elements, preventing order-insensitivity in symmetric trees.
    """
    if isinstance(value, bytes):
        # Bind leaf to position to prevent collision
        import blake3

        position_bound = blake3.blake3(value + index.to_bytes(4, byteorder="big")).digest()
        big_int = int.from_bytes(position_bound, byteorder="big")
        return big_int % SNARK_SCALAR_FIELD
    if isinstance(value, str):
        return int(value) % SNARK_SCALAR_FIELD
    if isinstance(value, int):
        return value % SNARK_SCALAR_FIELD
    raise TypeError(f"Unsupported leaf type: {type(value)!r}")


def _poseidon_hash_pairs(pairs: list[tuple[int, int]]) -> list[int]:
    """
    Hash a list of (left, right) field-element pairs with plain Poseidon(2).

    This function uses plain Poseidon(left, right) — matching the circuit
    behavior in merkleProof.circom exactly. No domain tags are applied to
    internal node hashing, ensuring Python-generated Merkle roots are
    bit-for-bit identical to circuit-verified roots.

    Default backend: ``protocol.poseidon_bn128.poseidon_hash_bn128`` — a pure
    Python implementation using the exact same round constants and MDS matrix
    as circomlibjs / the circom circuit.

    When ``OLY_POSEIDON_BACKEND=js`` is set, all pairs are sent to the
    persistent Node.js process in a **single IPC round-trip** via
    ``batch_hash2``, keeping the JS backend at O(depth) calls for a full tree.

    Zero-leaf sentinel semantics are **not** affected by either backend; zero
    leaves remain the raw field element 0, never Poseidon(0, 0).

    Args:
        pairs: List of (left, right) field-element pairs.

    Returns:
        List of plain Poseidon(2) hashes.
    """
    from . import poseidon_js  # local import avoids circular imports at module load

    if poseidon_js.backend_enabled():
        reduced = [(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD) for a, b in pairs]
        return [poseidon_hash_bn128(a, b) for a, b in reduced]

    return [poseidon_hash_bn128(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD) for a, b in pairs]


def _poseidon_hash(left: int, right: int) -> int:
    """Single-pair convenience wrapper around :func:`_poseidon_hash_pairs`."""
    return _poseidon_hash_pairs([(left, right)])[0]


@dataclass
class PoseidonProof:
    """Poseidon Merkle inclusion proof."""

    root: str
    leaf: str
    leaf_index: int
    path_elements: list[str]
    path_indices: list[int]
    tree_size: int = 0


class PoseidonMerkleTree:
    """
    Poseidon-based binary Merkle tree.

    Leaves may be provided as raw bytes (hashed with BLAKE3 then reduced into
    the BN128 field), decimal strings, or integers already inside the field.
    """

    def __init__(self, leaves: Iterable[int | str | bytes], depth: int | None = None) -> None:
        """
        Initialize a Poseidon Merkle tree.

        Args:
            leaves: Leaf values (bytes hashed with BLAKE3, decimal strings, or field ints)
            depth: Optional fixed depth; pads with zeros to 2**depth leaves

        Raises:
            ValueError: If no leaves provided or too many leaves for specified depth
        """
        leaves_list = list(leaves)
        normalized = [_to_field_int(leaf, index=i) for i, leaf in enumerate(leaves_list)]
        if not normalized:
            raise ValueError("Cannot create Poseidon Merkle tree with no leaves")

        if depth is not None:
            width = 1 << depth
            if len(normalized) > width:
                raise ValueError(
                    f"Provided {len(normalized)} leaves but depth {depth} only supports {width}"
                )
            padding = [0] * (width - len(normalized))
            self._leaves: list[int] = normalized + padding
        else:
            self._leaves = normalized

    def _build_level(self, level: Sequence[int]) -> list[int]:
        """
        Hash a level upwards using CT-style promotion.

        When an odd number of nodes exist, the lone node is promoted without
        hashing (Certificate Transparency style). All pairs in the level are
        hashed in a single backend call so that the JS backend needs only one
        subprocess per level, not one per pair.

        Uses plain Poseidon(2) matching merkleProof.circom exactly.
        """
        if len(level) == 1:
            return [level[0]]

        pairs = []
        promoted = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                pairs.append((level[i], level[i + 1]))
            else:
                # CT-style promotion: lone node is promoted without hashing
                promoted.append(level[i])

        hashed = _poseidon_hash_pairs(pairs) if pairs else []
        return hashed + promoted

    @property
    def tree_size(self) -> int:
        """Return the number of leaves in the tree."""
        return len(self._leaves)

    def get_root(self) -> str:
        """Return the Merkle root as a decimal string."""
        level = list(self._leaves)
        while len(level) > 1:
            level = self._build_level(level)
        return str(level[0] % SNARK_SCALAR_FIELD)

    def get_proof(self, leaf_index: int) -> tuple[list[str], list[int]]:
        """
        Return (pathElements, pathIndices) for the given leaf.

        pathIndices follows the circom convention: 0 when the current node is a
        left child, 1 when it is a right child.

        All pairs at each level are hashed in a single backend call, keeping
        the JS backend at O(depth) subprocess calls for the entire proof.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise ValueError(f"Invalid leaf index {leaf_index}")

        path_elements: list[str] = []
        path_indices: list[int] = []

        level = list(self._leaves)
        index = leaf_index

        while len(level) > 1:
            # CT-style: check if this node is promoted (lone node at odd level)
            is_last = index == len(level) - 1
            is_promoted = is_last and (len(level) % 2 == 1)

            if not is_promoted:
                # Normal case: there's a sibling
                if index % 2 == 0:
                    sibling = level[index + 1]
                    path_indices.append(0)
                else:
                    sibling = level[index - 1]
                    path_indices.append(1)
                path_elements.append(str(sibling % SNARK_SCALAR_FIELD))
            # If promoted, no sibling is added at this level

            # Build next level using CT-style promotion (must match _build_level)
            level = self._build_level(level)
            index //= 2

        return path_elements, path_indices


def build_poseidon_witness_inputs(
    document_leaves: list[bytes], target_index: int, *, depth: int | None = None
) -> PoseidonProof:
    """
    Prepare Poseidon Merkle inputs for circom/snarkjs witnesses.

    Args:
        document_leaves: Raw document chunks (bytes) to commit.
        target_index: Zero-based index of the leaf to prove.
        depth: Optional fixed depth. Pads with zeros to 2**depth leaves when set.

    Returns:
        PoseidonProof with root, leaf, path elements, and indices ready for witness JSON.

    Raises:
        ValueError: If target_index is out of bounds (>= tree_size).
    """
    tree = PoseidonMerkleTree(document_leaves, depth=depth)

    # Index bounds check: leafIndex must be < number of actual document leaves
    if target_index < 0 or target_index >= len(document_leaves):
        raise ValueError(
            f"target_index {target_index} is out of bounds for "
            f"{len(document_leaves)} document leaves"
        )

    # Normalize leaves with position binding
    leaves_as_field_elements = [
        str(_to_field_int(chunk, index=i)) for i, chunk in enumerate(document_leaves)
    ]
    path_elements, path_indices = tree.get_proof(target_index)

    return PoseidonProof(
        root=tree.get_root(),
        leaf=leaves_as_field_elements[target_index],
        leaf_index=target_index,
        path_elements=path_elements,
        path_indices=path_indices,
        tree_size=tree.tree_size,
    )
