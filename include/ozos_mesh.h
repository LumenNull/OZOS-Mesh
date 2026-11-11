/**
 * =============================================================================
 *   O.Z.O.S // SOVEREIGN MESH P2P ROUTER (ozos_mesh.h)
 *   Zero-IP Multi-Hop Physical Mesh & Opportunistic Store-and-Forward DTN
 *   Version: 1.1.0-MESH (Round 1 Sovereign Hardened Edition)
 *   Compliance: MISRA C99 / Zero Heap Malloc=0 / 80-Byte OZOS-80 Wire Invariant
 *   License: MIT | Copyright (c) 2026 LumenNull
 * =============================================================================
 */

#ifndef OZOS_MESH_H
#define OZOS_MESH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "tweetnacl.h"

/* =============================================================================
   1. WIRE CONSTANTS, FLAGS & PROTOCOL LIMITS
   ============================================================================= */

#define OZOS_MAGIC_MESH_FRAME        0x4F5A4D53U /* ASCII "OZMS" */
#define OZOS_MAGIC_MESH_BEACON       0x4F5A4D42U /* ASCII "OZMB" */

#define OZOS_MESH_FRAME_SIZE         80U         /* Canonical OZOS-80 Wire Size (640 bits) */
#define OZOS_MESH_HEADER_SIZE        20U         /* Fixed 20-byte Routing Header */
#define OZOS_MESH_PAYLOAD_SIZE       58U         /* Fixed 58-byte Payload Slice */
#define OZOS_MESH_BROADCAST_ID       0xFFFFFFFFU /* Flood all nodes in spectrum range */

#define OZOS_MESH_DEFAULT_TTL        7U          /* Default multi-hop limit */
#define OZOS_MESH_MAX_TTL            64U         /* Hard upper ceiling against zombie storms */

/* Canonical Frame Flags */
#define OZOS_MESH_FLAG_CLEARTEXT     0x0000U     /* Unencrypted diagnostic / public beacon */
#define OZOS_MESH_FLAG_ENCRYPTED     0x0001U     /* Bit 0: X25519 + XSalsa20-Poly1305 E2EE */
#define OZOS_MESH_FLAG_EPHEMERAL     0x0002U     /* Bit 1: Ephemeral one-time sender key */
#define OZOS_MESH_FLAG_PQC           0x0004U     /* Bit 2: Post-Quantum hybrid envelope */
#define OZOS_MESH_VALID_FLAGS_MASK   0x0007U     /* Reject unknown reserved flag bits */

/* Onion AEAD Envelope Constants inside 58-Byte Payload:
   [0..7]   8B CSPRNG Per-Packet Salt
   [8..23]  16B Poly1305 Authentication Tag (bound to header AAD via 24B Nonce)
   [24]     1B Encrypted Plaintext Length (0..33)
   [25..57] 33B Encrypted Zero-Padded Plaintext */
#define OZOS_MESH_SALT_SIZE          8U
#define OZOS_MESH_TAG_SIZE           16U
#define OZOS_MESH_CIPHERTEXT_BODY    34U         /* 1B length + 33B padded message */
#define OZOS_MESH_MAX_CRYPTO_PLAIN   33U         /* Maximum E2EE plaintext per 80B frame */

/* Dual-Generation SipHash-2-4 Rotating Bloom Filter Constants (Zero-Heap) */
#define OZOS_BLOOM_BANK_BITS         4096U       /* 4096 bits per generation bank */
#define OZOS_BLOOM_BANK_BYTES        (OZOS_BLOOM_BANK_BITS / 8U) /* 512 Bytes per bank */
#define OZOS_BLOOM_ROTATE_THRESHOLD  256U        /* Rotate active/standby every 256 frames (~0.5% FPR) */

#define OZOS_CACHE_CAPACITY          16U         /* Ephemeral Store-and-Forward ring depth */

/* =============================================================================
   2. CONSTANT-TIME MEMORY WIPE & PORTABLE LITTLE-ENDIAN SERIALIZATION
   ============================================================================= */

static inline void ozos_mesh_zeroize(void* ptr, size_t len) {
    if (!ptr || len == 0U) return;
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0U;
    }
}

static inline uint16_t ozos_le16_read(const uint8_t p[2]) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline void ozos_le16_write(uint8_t p[2], uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline uint32_t ozos_le32_read(const uint8_t p[4]) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void ozos_le32_write(uint8_t p[4], uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline uint64_t ozos_le64_read(const uint8_t p[8]) {
    return ((uint64_t)ozos_le32_read(p)) |
           (((uint64_t)ozos_le32_read(p + 4)) << 32);
}

/* =============================================================================
   3. CANONICAL 80-BYTE MESH ENVELOPE (OZOS-80 COMPLIANT)
   ============================================================================= */

#if defined(_MSC_VER)
#pragma pack(push, 1)
#endif
typedef struct {
    uint32_t magic;              /* [00-03] 0x4F5A4D53 ("OZMS") Little-Endian */
    uint16_t hop_limit;          /* [04-05] TTL: 1..64, decremented on each relay */
    uint16_t flags;              /* [06-07] Bitmask: Encrypted / Ephemeral / PQC */
    uint32_t src_node_id;        /* [08-11] Originating Cryptographic Node ID */
    uint32_t dst_node_id;        /* [12-15] Target Node ID (or OZOS_MESH_BROADCAST_ID) */
    uint32_t packet_id;          /* [16-19] Non-zero CSPRNG / Monotonic Sequence ID */
    uint8_t  payload[OZOS_MESH_PAYLOAD_SIZE]; /* [20-77] 58-Byte Payload / AEAD Envelope */
    uint16_t tripwire_mac;       /* [78-79] Fast Link CRC-16 Pre-Filter Checksum */
} ozos_mesh_frame_t;
#if defined(_MSC_VER)
#pragma pack(pop)
#endif

/* Compile-time verification of the 80-Byte OZOS-80 Wire Invariant */
typedef char ozos_mesh_frame_size_invariant[(sizeof(ozos_mesh_frame_t) == 80U) ? 1 : -1];

typedef enum {
    OZOS_MESH_ACTION_DELIVER = 0,          /* Unicast/final-hop broadcast addressed to local node */
    OZOS_MESH_ACTION_RELAY = 1,            /* Transit unicast frame decremented & resealed for PHY */
    OZOS_MESH_ACTION_DROP_SEEN = 2,        /* Duplicate or self-echo suppressed by SipHash Bloom */
    OZOS_MESH_ACTION_DROP_EXPIRED = 3,     /* Hop limit <= 1 or > OZOS_MESH_MAX_TTL */
    OZOS_MESH_ACTION_DROP_INVALID = 4,     /* Corrupted CRC-16, invalid magic, or malformed IDs/flags */
    OZOS_MESH_ACTION_DELIVER_AND_RELAY = 5 /* Multi-hop broadcast: deliver locally AND relay onward */
} ozos_mesh_action_t;

/**
 * Alignment-safe, endian-independent serialization to 80 wire bytes (Little-Endian).
 */
static inline void ozos_mesh_frame_encode(const ozos_mesh_frame_t* frame, uint8_t raw_out[OZOS_MESH_FRAME_SIZE]) {
    if (!frame || !raw_out) return;
    ozos_le32_write(raw_out + 0,  frame->magic);
    ozos_le16_write(raw_out + 4,  frame->hop_limit);
    ozos_le16_write(raw_out + 6,  frame->flags);
    ozos_le32_write(raw_out + 8,  frame->src_node_id);
    ozos_le32_write(raw_out + 12, frame->dst_node_id);
    ozos_le32_write(raw_out + 16, frame->packet_id);
    memcpy(raw_out + 20, frame->payload, OZOS_MESH_PAYLOAD_SIZE);
    ozos_le16_write(raw_out + 78, frame->tripwire_mac);
}

/**
 * Alignment-safe, endian-independent deserialization from 80 wire bytes (Little-Endian).
 */
static inline void ozos_mesh_frame_decode(const uint8_t raw_in[OZOS_MESH_FRAME_SIZE], ozos_mesh_frame_t* frame) {
    if (!raw_in || !frame) return;
    frame->magic        = ozos_le32_read(raw_in + 0);
    frame->hop_limit    = ozos_le16_read(raw_in + 4);
    frame->flags        = ozos_le16_read(raw_in + 6);
    frame->src_node_id  = ozos_le32_read(raw_in + 8);
    frame->dst_node_id  = ozos_le32_read(raw_in + 12);
    frame->packet_id    = ozos_le32_read(raw_in + 16);
    memcpy(frame->payload, raw_in + 20, OZOS_MESH_PAYLOAD_SIZE);
    frame->tripwire_mac = ozos_le16_read(raw_in + 78);
}

/* =============================================================================
   4. DUAL-GENERATION SIPHASH-2-4 ROTATING BLOOM FILTER (ANTI-BLACKHOLE & ANTI-COLLISION)
   ============================================================================= */

#define OZOS_SIPROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64U - (b))))

#define OZOS_SIPROUND(v0, v1, v2, v3)       \
    do {                                    \
        (v0) += (v1);                       \
        (v1) = OZOS_SIPROTL64((v1), 13U);   \
        (v1) ^= (v0);                       \
        (v0) = OZOS_SIPROTL64((v0), 32U);   \
        (v2) += (v3);                       \
        (v3) = OZOS_SIPROTL64((v3), 16U);   \
        (v3) ^= (v2);                       \
        (v0) += (v3);                       \
        (v3) = OZOS_SIPROTL64((v3), 21U);   \
        (v3) ^= (v0);                       \
        (v2) += (v1);                       \
        (v1) = OZOS_SIPROTL64((v1), 17U);   \
        (v1) ^= (v2);                       \
        (v2) = OZOS_SIPROTL64((v2), 32U);   \
    } while (0)

/**
 * Keyed SipHash-2-4 PRF over an 8-byte tuple (packet_id || src_node_id).
 * Prevents offline pre-image collision poisoning by unauthenticated peers.
 */
static inline uint64_t ozos_mesh_siphash24_u64(uint64_t msg64, const uint8_t key[16]) {
    uint64_t k0 = ozos_le64_read(key);
    uint64_t k1 = ozos_le64_read(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    v3 ^= msg64;
    OZOS_SIPROUND(v0, v1, v2, v3);
    OZOS_SIPROUND(v0, v1, v2, v3);
    v0 ^= msg64;

    uint64_t b = 8ULL << 56;
    v3 ^= b;
    OZOS_SIPROUND(v0, v1, v2, v3);
    OZOS_SIPROUND(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xFFULL;
    OZOS_SIPROUND(v0, v1, v2, v3);
    OZOS_SIPROUND(v0, v1, v2, v3);
    OZOS_SIPROUND(v0, v1, v2, v3);
    OZOS_SIPROUND(v0, v1, v2, v3);

    return (v0 ^ v1 ^ v2 ^ v3);
}

typedef struct {
    uint8_t  bits[2][OZOS_BLOOM_BANK_BYTES]; /* Active + Standby 4096-bit banks */
    uint8_t  sip_key[16];                    /* Per-node 128-bit CSPRNG SipHash key */
    uint32_t active_idx;                     /* 0 or 1 */
    uint32_t active_count;                   /* Insertions in current active generation */
    uint64_t total_insertions;               /* Monotonic 64-bit telemetry counter */
    uint32_t rotation_epochs;                /* Number of generation rotations completed */
} ozos_mesh_bloom_t;

static inline void ozos_mesh_bloom_init_with_key(ozos_mesh_bloom_t* bf, const uint8_t key[16]) {
    if (!bf || !key) return;
    memset(bf->bits, 0, sizeof(bf->bits));
    memcpy(bf->sip_key, key, 16);
    bf->active_idx = 0U;
    bf->active_count = 0U;
    bf->total_insertions = 0ULL;
    bf->rotation_epochs = 0U;
}

static inline void ozos_mesh_bloom_init(ozos_mesh_bloom_t* bf) {
    if (!bf) return;
    uint8_t rnd_key[16];
    randombytes(rnd_key, sizeof(rnd_key));
    ozos_mesh_bloom_init_with_key(bf, rnd_key);
    ozos_mesh_zeroize(rnd_key, sizeof(rnd_key));
}

static inline void ozos_mesh_bloom_indices(
    const ozos_mesh_bloom_t* bf,
    uint32_t packet_id,
    uint32_t src_node_id,
    uint32_t out_idx[3]
) {
    uint64_t tuple64 = ((uint64_t)src_node_id << 32) | (uint64_t)packet_id;
    uint64_t digest = ozos_mesh_siphash24_u64(tuple64, bf->sip_key);
    uint32_t h1 = (uint32_t)(digest & 0xFFFFFFFFULL);
    uint32_t h2 = (uint32_t)((digest >> 32) | 1ULL); /* Odd stride ensures coprime coverage */

    out_idx[0] = h1 % OZOS_BLOOM_BANK_BITS;
    out_idx[1] = (h1 + h2) % OZOS_BLOOM_BANK_BITS;
    out_idx[2] = (h1 + (2U * h2)) % OZOS_BLOOM_BANK_BITS;
}

static inline bool ozos_mesh_bloom_bank_has(const uint8_t bank[OZOS_BLOOM_BANK_BYTES], const uint32_t idx[3]) {
    bool b0 = (bank[idx[0] / 8U] & (uint8_t)(1U << (idx[0] % 8U))) != 0;
    bool b1 = (bank[idx[1] / 8U] & (uint8_t)(1U << (idx[1] % 8U))) != 0;
    bool b2 = (bank[idx[2] / 8U] & (uint8_t)(1U << (idx[2] % 8U))) != 0;
    return (b0 && b1 && b2);
}

static inline bool ozos_mesh_bloom_test(const ozos_mesh_bloom_t* bf, uint32_t packet_id, uint32_t src_node_id) {
    if (!bf) return false;
    uint32_t idx[3];
    ozos_mesh_bloom_indices(bf, packet_id, src_node_id, idx);
    /* Check both active and warm-standby generations for seamless anti-replay continuity */
    return ozos_mesh_bloom_bank_has(bf->bits[0], idx) ||
           ozos_mesh_bloom_bank_has(bf->bits[1], idx);
}

static inline void ozos_mesh_bloom_add(ozos_mesh_bloom_t* bf, uint32_t packet_id, uint32_t src_node_id) {
    if (!bf) return;
    if (bf->active_count >= OZOS_BLOOM_ROTATE_THRESHOLD) {
        /* Rotate generations: previous active becomes warm standby, new active is wiped clean */
        bf->active_idx = 1U - (bf->active_idx & 1U);
        memset(bf->bits[bf->active_idx], 0, OZOS_BLOOM_BANK_BYTES);
        bf->active_count = 0U;
        bf->rotation_epochs++;
    }

    uint32_t idx[3];
    uint32_t bank = bf->active_idx & 1U;
    ozos_mesh_bloom_indices(bf, packet_id, src_node_id, idx);

    bf->bits[bank][idx[0] / 8U] |= (uint8_t)(1U << (idx[0] % 8U));
    bf->bits[bank][idx[1] / 8U] |= (uint8_t)(1U << (idx[1] % 8U));
    bf->bits[bank][idx[2] / 8U] |= (uint8_t)(1U << (idx[2] % 8U));

    bf->active_count++;
    bf->total_insertions++;
}

/* =============================================================================
   5. EPHEMERAL STORE-AND-FORWARD RING BUFFER (DELAY-TOLERANT DTN)
   ============================================================================= */

typedef struct {
    ozos_mesh_frame_t slots[OZOS_CACHE_CAPACITY];
    bool occupied[OZOS_CACHE_CAPACITY];
    size_t head;
    size_t count;
} ozos_mesh_cache_t;

static inline void ozos_mesh_cache_init(ozos_mesh_cache_t* cache) {
    if (!cache) return;
    memset(cache->slots, 0, sizeof(cache->slots));
    memset(cache->occupied, 0, sizeof(cache->occupied));
    cache->head = 0U;
    cache->count = 0U;
}

static inline void ozos_mesh_cache_push(ozos_mesh_cache_t* cache, const ozos_mesh_frame_t* frame) {
    if (!cache || !frame) return;
    cache->slots[cache->head] = *frame;
    cache->occupied[cache->head] = true;
    cache->head = (cache->head + 1U) % OZOS_CACHE_CAPACITY;
    if (cache->count < OZOS_CACHE_CAPACITY) cache->count++;
}

/* =============================================================================
   6. OUTER LINK CRC-16 PRE-FILTER & HEADER VALIDATION
   ============================================================================= */

/**
 * Computes fast outer link-layer CRC-16 checksum over canonical Little-Endian wire bytes [0..77].
 * Note: This outer checksum filters physical RF/acoustic noise in O(1) time before crypto;
 * cryptographic peer authenticity & header integrity are enforced by the inner Poly1305 tag.
 */
static inline uint16_t ozos_mesh_calculate_mac(const ozos_mesh_frame_t* frame) {
    if (!frame) return 0U;
    uint8_t wire[OZOS_MESH_FRAME_SIZE];
    ozos_mesh_frame_encode(frame, wire);

    uint16_t crc = 0xFFFFU;
    for (size_t i = 0U; i < 78U; ++i) {
        crc ^= (uint16_t)wire[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 1U) ? (uint16_t)((crc >> 1) ^ 0x8408U) : (uint16_t)(crc >> 1);
        }
    }
    return crc;
}

static inline void ozos_mesh_seal(ozos_mesh_frame_t* frame) {
    if (!frame) return;
    frame->magic = OZOS_MAGIC_MESH_FRAME;
    frame->tripwire_mac = ozos_mesh_calculate_mac(frame);
}

static inline bool ozos_mesh_verify_integrity(const ozos_mesh_frame_t* frame) {
    if (!frame) return false;
    if (frame->magic != OZOS_MAGIC_MESH_FRAME) return false;
    if ((frame->flags & ~OZOS_MESH_VALID_FLAGS_MASK) != 0U) return false;
    if (frame->src_node_id == 0U || frame->src_node_id == OZOS_MESH_BROADCAST_ID) return false;
    if (frame->dst_node_id == 0U) return false;
    if (frame->packet_id == 0U) return false;
    return (frame->tripwire_mac == ozos_mesh_calculate_mac(frame));
}

/* =============================================================================
   7. CORE ROUTER ENGINE & DISPATCH STATE MACHINE
   ============================================================================= */

static inline ozos_mesh_action_t ozos_mesh_process_frame(
    ozos_mesh_frame_t* frame,
    uint32_t local_node_id,
    ozos_mesh_bloom_t* bf,
    ozos_mesh_cache_t* cache
) {
    if (!frame || local_node_id == 0U || local_node_id == OZOS_MESH_BROADCAST_ID) {
        return OZOS_MESH_ACTION_DROP_INVALID;
    }

    /* Step 1: Gatekeeper Header Invariant & Link CRC-16 Check */
    if (!ozos_mesh_verify_integrity(frame)) {
        return OZOS_MESH_ACTION_DROP_INVALID;
    }

    /* Step 2: Suppress self-originated RF/acoustic reflections & seen duplicates */
    if (frame->src_node_id == local_node_id) {
        return OZOS_MESH_ACTION_DROP_SEEN;
    }
    if (bf && ozos_mesh_bloom_test(bf, frame->packet_id, frame->src_node_id)) {
        return OZOS_MESH_ACTION_DROP_SEEN;
    }

    /* Step 3: Unicast Local Delivery (Never pollute DTN transit cache with private local frames) */
    if (frame->dst_node_id == local_node_id) {
        if (frame->hop_limit == 0U || frame->hop_limit > OZOS_MESH_MAX_TTL) {
            return OZOS_MESH_ACTION_DROP_EXPIRED;
        }
        if (bf) {
            ozos_mesh_bloom_add(bf, frame->packet_id, frame->src_node_id);
        }
        return OZOS_MESH_ACTION_DELIVER;
    }

    /* Step 4: Multi-Hop Broadcast Handling (Deliver locally AND relay if TTL > 1) */
    if (frame->dst_node_id == OZOS_MESH_BROADCAST_ID) {
        if (frame->hop_limit == 0U || frame->hop_limit > OZOS_MESH_MAX_TTL) {
            return OZOS_MESH_ACTION_DROP_EXPIRED;
        }
        if (bf) {
            ozos_mesh_bloom_add(bf, frame->packet_id, frame->src_node_id);
        }
        if (frame->hop_limit == 1U) {
            /* Final broadcast hop: consume locally without caching or rebroadcasting */
            return OZOS_MESH_ACTION_DELIVER;
        }
        frame->hop_limit--;
        ozos_mesh_seal(frame);
        if (cache) {
            ozos_mesh_cache_push(cache, frame);
        }
        return OZOS_MESH_ACTION_DELIVER_AND_RELAY;
    }

    /* Step 5: Unicast Multi-Hop Relay (Enforce strict TTL ceiling & floor BEFORE DTN caching) */
    if (frame->hop_limit <= 1U || frame->hop_limit > OZOS_MESH_MAX_TTL) {
        return OZOS_MESH_ACTION_DROP_EXPIRED;
    }
    if (bf) {
        ozos_mesh_bloom_add(bf, frame->packet_id, frame->src_node_id);
    }

    /* Decrement TTL, reseal CRC-16, and store post-decremented transit frame in DTN cache */
    frame->hop_limit--;
    ozos_mesh_seal(frame);
    if (cache) {
        ozos_mesh_cache_push(cache, frame);
    }

    return OZOS_MESH_ACTION_RELAY;
}

/* =============================================================================
   8. X25519 + XSALSA20-POLY1305 AUTHENTICATED ONION ENCLAVE (WITH HEADER AAD)
   ============================================================================= */

/**
 * Generates an X25519 keypair (pk[32], sk[32]) using OS CSPRNG.
 */
static inline void ozos_mesh_keygen(uint8_t pk[32], uint8_t sk[32]) {
    if (!pk || !sk) return;
    crypto_box_keypair(pk, sk);
}

/**
 * Deterministically derives a valid 32-bit Sovereign Node ID from a 32-byte Public Key
 * via SHA-512 truncation, clamping reserved sentinels (0x00000000 and 0xFFFFFFFF).
 */
static inline uint32_t ozos_mesh_node_id_from_pk(const uint8_t pk[32]) {
    if (!pk) return 0U;
    uint8_t digest[64];
    crypto_hash(digest, pk, 32ULL);
    uint32_t id = ozos_le32_read(digest);
    ozos_mesh_zeroize(digest, sizeof(digest));
    if (id == 0U) id = 1U;
    if (id == OZOS_MESH_BROADCAST_ID) id = 0xFFFFFFFEU;
    return id;
}

/**
 * Computes symmetric X25519 shared key via Curve25519 + HSalsa20, rejecting all
 * RFC 7748 canonical & non-canonical low-order points in constant time.
 */
static inline bool ozos_mesh_derive_shared_key(
    uint8_t out_shared_k[32],
    uint8_t out_local_pk[32],
    const uint8_t peer_pk[32],
    const uint8_t local_sk[32]
) {
    static const uint8_t zero32[32] = {0};
    static const uint8_t zero16[16] = {0};
    static const uint8_t hsalsa_sigma[16] = {
        'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
    };

    uint8_t raw_dh[32];
    crypto_scalarmult_base(out_local_pk, local_sk);

    /* Reject self-reflection where peer_pk == local_pk */
    if (crypto_verify_32(peer_pk, out_local_pk) == 0) {
        return false;
    }

    crypto_scalarmult(raw_dh, local_sk, peer_pk);

    /* RFC 7748 Sec 6.1: Clamped scalar multiplication maps ALL 8 low-order points to 0 */
    if (crypto_verify_32(raw_dh, zero32) == 0) {
        ozos_mesh_zeroize(raw_dh, sizeof(raw_dh));
        return false;
    }

    crypto_core_hsalsa20(out_shared_k, zero16, raw_dh, hsalsa_sigma);
    ozos_mesh_zeroize(raw_dh, sizeof(raw_dh));
    return true;
}

/**
 * Builds an injective 24-byte XSalsa20-Poly1305 nonce binding:
 *   [0..7]   8-byte per-packet CSPRNG salt
 *   [8..11]  src_node_id (LE32)
 *   [12..15] dst_node_id (LE32)
 *   [16..19] packet_id   (LE32)
 *   [20..21] flags       (LE16)
 *   [22]     'O' (0x4F) protocol domain tag
 *   [23]     Directional key-ordering byte (0x5A if sender_pk < recipient_pk, else 0xA5)
 * Any modification to src_node_id, dst_node_id, packet_id, flags, or direction invalidates Poly1305!
 */
static inline void ozos_mesh_build_aad_nonce(
    uint8_t nonce[24],
    const uint8_t salt[8],
    uint32_t src_node_id,
    uint32_t dst_node_id,
    uint32_t packet_id,
    uint16_t flags,
    const uint8_t sender_pk[32],
    const uint8_t recipient_pk[32]
) {
    memcpy(nonce + 0, salt, 8U);
    ozos_le32_write(nonce + 8,  src_node_id);
    ozos_le32_write(nonce + 12, dst_node_id);
    ozos_le32_write(nonce + 16, packet_id);
    ozos_le16_write(nonce + 20, flags);
    nonce[22] = 0x4FU;

    /* Constant-time lexicographical direction bit between sender_pk and recipient_pk */
    int diff = 0;
    for (int i = 0; i < 32; ++i) {
        int a = (int)sender_pk[i];
        int b = (int)recipient_pk[i];
        int gt = (a > b) ? 1 : ((a < b) ? -1 : 0);
        if (diff == 0 && gt != 0) diff = gt;
    }
    nonce[23] = (diff < 0) ? 0x5AU : 0xA5U;
}

/**
 * Encrypts plaintext (up to 33 bytes) into an 80-byte OZOS-80 frame using X25519 + XSalsa20-Poly1305,
 * cryptographically authenticating header metadata (src_node_id, dst_node_id, packet_id, flags)
 * and sealing the outer link CRC-16.
 */
static inline bool ozos_mesh_frame_encrypt(
    ozos_mesh_frame_t* frame,
    const uint8_t* plaintext,
    size_t plain_len,
    const uint8_t recipient_pk[32],
    const uint8_t sender_sk[32]
) {
    if (!frame || (!plaintext && plain_len > 0U) || plain_len > OZOS_MESH_MAX_CRYPTO_PLAIN || !recipient_pk || !sender_sk) {
        return false;
    }
    if (frame->src_node_id == 0U || frame->src_node_id == OZOS_MESH_BROADCAST_ID || frame->dst_node_id == 0U) {
        return false;
    }

    uint8_t shared_k[32];
    uint8_t sender_pk[32];
    if (!ozos_mesh_derive_shared_key(shared_k, sender_pk, recipient_pk, sender_sk)) {
        ozos_mesh_zeroize(shared_k, sizeof(shared_k));
        ozos_mesh_zeroize(sender_pk, sizeof(sender_pk));
        return false;
    }

    /* Ensure non-zero CSPRNG packet_id if caller left it unset */
    while (frame->packet_id == 0U) {
        uint8_t pid_bytes[4];
        randombytes(pid_bytes, sizeof(pid_bytes));
        frame->packet_id = ozos_le32_read(pid_bytes);
    }

    frame->flags |= OZOS_MESH_FLAG_ENCRYPTED;

    uint8_t salt[OZOS_MESH_SALT_SIZE];
    randombytes(salt, sizeof(salt));

    uint8_t nonce[24];
    ozos_mesh_build_aad_nonce(
        nonce, salt,
        frame->src_node_id, frame->dst_node_id, frame->packet_id, frame->flags,
        sender_pk, recipient_pk
    );

    uint8_t m[32U + OZOS_MESH_CIPHERTEXT_BODY];
    uint8_t c[32U + OZOS_MESH_CIPHERTEXT_BODY];
    memset(m, 0, sizeof(m));
    memset(c, 0, sizeof(c));

    m[32] = (uint8_t)plain_len;
    if (plain_len > 0U) {
        memcpy(m + 33, plaintext, plain_len);
    }

    int rc = crypto_secretbox(c, m, sizeof(m), nonce, shared_k);
    if (rc != 0) {
        ozos_mesh_zeroize(shared_k, sizeof(shared_k));
        ozos_mesh_zeroize(sender_pk, sizeof(sender_pk));
        ozos_mesh_zeroize(nonce, sizeof(nonce));
        ozos_mesh_zeroize(m, sizeof(m));
        ozos_mesh_zeroize(c, sizeof(c));
        return false;
    }

    /* Pack [8B salt][16B Poly1305 tag][34B constant-size ciphertext] == 58B */
    memcpy(frame->payload + 0, salt, OZOS_MESH_SALT_SIZE);
    memcpy(frame->payload + OZOS_MESH_SALT_SIZE, c + 16, OZOS_MESH_TAG_SIZE + OZOS_MESH_CIPHERTEXT_BODY);

    ozos_mesh_seal(frame);

    ozos_mesh_zeroize(shared_k, sizeof(shared_k));
    ozos_mesh_zeroize(sender_pk, sizeof(sender_pk));
    ozos_mesh_zeroize(nonce, sizeof(nonce));
    ozos_mesh_zeroize(m, sizeof(m));
    ozos_mesh_zeroize(c, sizeof(c));
    return true;
}

/**
 * Authenticates and decrypts an 80-byte OZOS-80 encrypted frame into caller-bounded out_plaintext.
 * Writes a trailing NUL byte (requires out_max_len >= plain_len + 1). Fails closed on any header or payload tampering.
 */
static inline bool ozos_mesh_frame_decrypt(
    uint8_t* out_plaintext,
    size_t out_max_len,
    size_t* out_plain_len,
    const ozos_mesh_frame_t* frame,
    const uint8_t sender_pk[32],
    const uint8_t recipient_sk[32]
) {
    if (!out_plaintext || out_max_len == 0U || !out_plain_len || !frame || !sender_pk || !recipient_sk) {
        return false;
    }
    *out_plain_len = 0U;

    if ((frame->flags & OZOS_MESH_FLAG_ENCRYPTED) == 0U) {
        return false;
    }
    if (!ozos_mesh_verify_integrity(frame)) {
        return false;
    }

    uint8_t shared_k[32];
    uint8_t recipient_pk[32];
    if (!ozos_mesh_derive_shared_key(shared_k, recipient_pk, sender_pk, recipient_sk)) {
        ozos_mesh_zeroize(shared_k, sizeof(shared_k));
        ozos_mesh_zeroize(recipient_pk, sizeof(recipient_pk));
        return false;
    }

    const uint8_t* salt = frame->payload;
    uint8_t nonce[24];
    ozos_mesh_build_aad_nonce(
        nonce, salt,
        frame->src_node_id, frame->dst_node_id, frame->packet_id, frame->flags,
        sender_pk, recipient_pk
    );

    uint8_t c[32U + OZOS_MESH_CIPHERTEXT_BODY];
    uint8_t m[32U + OZOS_MESH_CIPHERTEXT_BODY];
    memset(c, 0, sizeof(c));
    memset(m, 0, sizeof(m));

    memcpy(c + 16, frame->payload + OZOS_MESH_SALT_SIZE, OZOS_MESH_TAG_SIZE + OZOS_MESH_CIPHERTEXT_BODY);

    if (crypto_secretbox_open(m, c, sizeof(c), nonce, shared_k) != 0) {
        ozos_mesh_zeroize(shared_k, sizeof(shared_k));
        ozos_mesh_zeroize(recipient_pk, sizeof(recipient_pk));
        ozos_mesh_zeroize(nonce, sizeof(nonce));
        ozos_mesh_zeroize(c, sizeof(c));
        ozos_mesh_zeroize(m, sizeof(m));
        return false;
    }

    size_t len = (size_t)m[32];
    if (len > OZOS_MESH_MAX_CRYPTO_PLAIN || (len + 1U) > out_max_len) {
        ozos_mesh_zeroize(shared_k, sizeof(shared_k));
        ozos_mesh_zeroize(recipient_pk, sizeof(recipient_pk));
        ozos_mesh_zeroize(nonce, sizeof(nonce));
        ozos_mesh_zeroize(c, sizeof(c));
        ozos_mesh_zeroize(m, sizeof(m));
        return false;
    }

    if (len > 0U) {
        memcpy(out_plaintext, m + 33, len);
    }
    out_plaintext[len] = '\0';
    *out_plain_len = len;

    ozos_mesh_zeroize(shared_k, sizeof(shared_k));
    ozos_mesh_zeroize(recipient_pk, sizeof(recipient_pk));
    ozos_mesh_zeroize(nonce, sizeof(nonce));
    ozos_mesh_zeroize(c, sizeof(c));
    ozos_mesh_zeroize(m, sizeof(m));
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* OZOS_MESH_H */
