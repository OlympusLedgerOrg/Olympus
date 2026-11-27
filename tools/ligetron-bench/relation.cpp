// SPDX-License-Identifier: Apache-2.0

// Depth-limited benchmark guest for Olympus's BLAKE3 item tree.
// Public: statement, authenticated item_root, query key, partition bits, depth.
// Private: partition count, terminal witness, partition siblings, top siblings.
#include <ligetron/api.h>
#include <blake3.h>
#include <algorithm>
#include <cstdint>
#include <cstring>

extern "C" {
#include <blake3_impl.h>
}

#include "domains.h"

constexpr size_t kMaxDepth = 50;

static uint64_t read_u64(const char* arg) {
    uint64_t value;
    std::memcpy(&value, arg, sizeof(value));
    return value;
}

static uint8_t key_bit(const uint8_t* key, size_t bit) {
    return (key[bit / 8] >> (7 - bit % 8)) & 1;
}

static bool same(const uint8_t* left, const uint8_t* right) {
    uint8_t difference = 0;
    for (size_t i = 0; i < 32; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

static uint8_t select(uint8_t bit, uint8_t zero, uint8_t one) {
    uint8_t mask = static_cast<uint8_t>(0 - bit);
    return zero ^ ((zero ^ one) & mask);
}

// For one keyed block, the first 32 root-output bytes are the digest.
static void keyed_block(const uint8_t* key, const uint8_t* data, uint8_t size,
                        uint8_t* digest) {
    uint32_t cv[8];
    load_key_words(key, cv);
    uint8_t out[64];
    blake3_compress_xof_portable(cv, data, size, 0,
        KEYED_HASH | CHUNK_START | CHUNK_END | ROOT, out);
    std::memcpy(digest, out, 32);
}

static void fold(const uint8_t* domain, uint8_t* current,
                 const uint8_t* sibling, uint8_t bit) {
    uint8_t message[64];
    for (size_t i = 0; i < 32; ++i) {
        message[i] = select(bit, current[i], sibling[i]);
        message[32 + i] = select(bit, sibling[i], current[i]);
    }
    keyed_block(domain, message, 64, current);
}

static void member_terminal(const uint8_t* query, const uint8_t* item,
                            uint8_t* digest) {
    // The benchmark pins one authenticated profile, bytes/raw v1 at index 0.
    assert_one((item[0] | item[1]) == 0);
    // M1-open requires occurrence_count >= 1 (u64_be at item[74..82)).
    uint8_t occurrences = 0;
    for (size_t i = 74; i < 82; ++i) occurrences |= item[i];
    assert_one(occurrences != 0);
    uint8_t key_preimage[49] = {0, 0, 0, 9, 'b', 'y', 't', 'e', 's', '/',
                               'r', 'a', 'w', 0, 0, 0, 1};
    std::memcpy(key_preimage + 17, item + 10, 32);
    uint8_t derived_key[32];
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "olympus 2026-11 dataset content-key v1");
    blake3_hasher_update(&hasher, key_preimage, sizeof(key_preimage));
    blake3_hasher_finalize(&hasher, derived_key, sizeof(derived_key));
    assert_one(same(query, derived_key));

    uint8_t leaf_preimage[64];
    std::memcpy(leaf_preimage, query, 32);
    blake3_hasher_init_keyed(&hasher, kItem);
    blake3_hasher_update(&hasher, item, 114);
    blake3_hasher_finalize(&hasher, leaf_preimage + 32, 32);
    keyed_block(kLeaf, leaf_preimage, 64, digest);
}

static void neighbor_terminal(const uint8_t* query, const uint8_t* witness,
                              size_t path_len, uint8_t* digest) {
    assert_one(!same(query, witness));
    for (size_t i = 0; i < path_len; ++i) {
        assert_one(key_bit(query, i) == key_bit(witness, i));
    }
    keyed_block(kLeaf, witness, 64, digest);
}

int main(int argc, char** argv) {
    constexpr size_t kArgCount = 10;
    int lengths[kArgCount];
    if (argc != kArgCount || args_len_get(argv, lengths) != 0 ||
        lengths[1] != 8 || lengths[2] != 32 || lengths[3] != 32 ||
        lengths[4] != 8 || lengths[5] != 8 || lengths[6] != 8) {
        assert_one(false);
        return 0;
    }
    const uint64_t mode = read_u64(argv[1]);
    const uint64_t p = read_u64(argv[4]);
    const uint64_t depth = read_u64(argv[5]);
    if (mode > 2 || p > 16 || depth > kMaxDepth - p ||
        lengths[7] != (mode == 0 ? 114 : mode == 1 ? 64 : 1) ||
        lengths[8] != static_cast<int>(std::max<uint64_t>(1, depth * 32)) ||
        lengths[9] != static_cast<int>(std::max<uint64_t>(1, p * 32))) {
        assert_one(false);
        return 0;
    }
    const auto* root = reinterpret_cast<const uint8_t*>(argv[2]);
    const auto* query = reinterpret_cast<const uint8_t*>(argv[3]);
    const auto* witness = reinterpret_cast<const uint8_t*>(argv[7]);
    const auto* siblings = reinterpret_cast<const uint8_t*>(argv[8]);
    const auto* top = reinterpret_cast<const uint8_t*>(argv[9]);

    uint8_t current[32];
    if (mode == 0) member_terminal(query, witness, current);
    else if (mode == 1) neighbor_terminal(query, witness, p + depth, current);
    else std::memcpy(current, kEmptyRoot, sizeof(current));
    if (depth != 0) assert_one(!same(siblings + 32 * (depth - 1), kEmptyRoot));
    for (size_t level = depth; level > 0; --level) {
        const size_t i = level - 1;
        fold(kNode, current, siblings + 32 * i, key_bit(query, p + i));
    }

    uint32_t partition = 0;
    for (size_t i = 0; i < p; ++i) partition = (partition << 1) | key_bit(query, i);
    uint8_t bound_root[64] = {static_cast<uint8_t>(p)};
    for (size_t i = 0; i < 4; ++i) bound_root[1 + i] = partition >> (24 - 8 * i);
    std::memcpy(bound_root + 5, argv[6], 8);
    std::memcpy(bound_root + 13, current, 32);
    keyed_block(kPartition, bound_root, 45, current);
    for (size_t i = 0; i < p; ++i) {
        fold(kTop, current, top + 32 * i, key_bit(query, p - 1 - i));
    }
    assert_one(same(root, current));
    return 0;
}
