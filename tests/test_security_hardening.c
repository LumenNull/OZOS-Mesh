/**
 * =============================================================================
 *   O.Z.O.S // MESH ROUND 1 SECURITY HARDENING VERIFICATION SUITE
 *   Empirical C99 Verification of Crypto, Anti-Storm, DTN & Wire Invariants
 * =============================================================================
 */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "ozos_mesh.h"
#include "ozos_mesh_phy.h"

static int16_t g_test_sonic_tx[OZOS_SONIC_BURST_SAMPLES];
static int16_t g_test_sonic_rx[OZOS_SONIC_BURST_SAMPLES + 2048U];

#define REQUIRE(cond, msg)                                                      \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "[ASSERTION FAILED] %s (%s:%d)\n",                  \
                    (msg), __FILE__, __LINE__);                                 \
            return 1;                                                           \
        }                                                                       \
    } while (0)

int main(void) {
    printf("=================================================================\n");
    printf("  O.Z.O.S // NATIVE C99 SECURITY & PHY SUITE (10 INVARIANTS)\n");
    printf("=================================================================\n");

    /* 1. Canonical 80-Byte Size & Little-Endian Wire Codec */
    REQUIRE(sizeof(ozos_mesh_frame_t) == 80U, "Frame struct must be 80 bytes");
    ozos_mesh_frame_t f_wire;
    memset(&f_wire, 0, sizeof(f_wire));
    f_wire.hop_limit = 7U;
    f_wire.flags = OZOS_MESH_FLAG_CLEARTEXT;
    f_wire.src_node_id = 0x11223344U;
    f_wire.dst_node_id = 0x55667788U;
    f_wire.packet_id = 0x99AABBCCU;
    memcpy(f_wire.payload, "OZOS80_LE_TEST", 14U);
    ozos_mesh_seal(&f_wire);

    uint8_t wire_raw[80];
    ozos_mesh_frame_encode(&f_wire, wire_raw);
    /* Verify exact Little-Endian magic 0x4F5A4D53 -> 53 4D 5A 4F */
    REQUIRE(wire_raw[0] == 0x53U && wire_raw[1] == 0x4DU &&
            wire_raw[2] == 0x5AU && wire_raw[3] == 0x4FU,
            "Wire magic must serialize in deterministic Little-Endian order");

    ozos_mesh_frame_t f_dec;
    ozos_mesh_frame_decode(wire_raw, &f_dec);
    REQUIRE(ozos_mesh_verify_integrity(&f_dec), "Decoded wire frame must pass integrity");
    REQUIRE(f_dec.src_node_id == 0x11223344U && f_dec.dst_node_id == 0x55667788U &&
            f_dec.packet_id == 0x99AABBCCU && f_dec.hop_limit == 7U,
            "Decoded header fields must match original values");

    /* 1b: 1-bit wire corruption must fail outer Link CRC-16 & return DROP_INVALID */
    uint8_t wire_corrupt[80];
    memcpy(wire_corrupt, wire_raw, 80U);
    wire_corrupt[30] ^= 0x01U;
    ozos_mesh_frame_t f_corrupt;
    ozos_mesh_frame_decode(wire_corrupt, &f_corrupt);
    REQUIRE(!ozos_mesh_verify_integrity(&f_corrupt), "1-bit corrupted frame must fail CRC-16");
    REQUIRE(ozos_mesh_process_frame(&f_corrupt, 0x22220002U, NULL, NULL) == OZOS_MESH_ACTION_DROP_INVALID,
            "Router must return DROP_INVALID on corrupted CRC-16");
    printf("  [PASS 1/10] Canonical 80-Byte Little-Endian Wire Serialization & CRC-16 Gate\n");

    /* 2. X25519 + XSalsa20-Poly1305 E2EE Roundtrip & Nonce Uniqueness (No Two-Time Pad) */
    uint8_t alice_pk[32], alice_sk[32];
    uint8_t bob_pk[32], bob_sk[32];
    ozos_mesh_keygen(alice_pk, alice_sk);
    ozos_mesh_keygen(bob_pk, bob_sk);

    uint32_t alice_id = ozos_mesh_node_id_from_pk(alice_pk);
    uint32_t bob_id   = ozos_mesh_node_id_from_pk(bob_pk);
    if (bob_id == alice_id) bob_id ^= 1U;

    const char* secret = "ALPHA_COORDINATES_37.7749N";
    ozos_mesh_frame_t enc1, enc2;
    memset(&enc1, 0, sizeof(enc1));
    memset(&enc2, 0, sizeof(enc2));
    enc1.hop_limit = 5U; enc1.src_node_id = alice_id; enc1.dst_node_id = bob_id; enc1.packet_id = 101U;
    enc2.hop_limit = 5U; enc2.src_node_id = alice_id; enc2.dst_node_id = bob_id; enc2.packet_id = 101U;

    REQUIRE(ozos_mesh_frame_encrypt(&enc1, (const uint8_t*)secret, strlen(secret), bob_pk, alice_sk),
            "Encryption 1 must succeed");
    REQUIRE(ozos_mesh_frame_encrypt(&enc2, (const uint8_t*)secret, strlen(secret), bob_pk, alice_sk),
            "Encryption 2 must succeed");

    /* Even with identical plaintext and packet_id, random 8B salt forces distinct ciphertexts */
    REQUIRE(memcmp(enc1.payload, enc2.payload, 8U) != 0, "Per-packet 8B CSPRNG salt must differ");
    REQUIRE(memcmp(enc1.payload + 24, enc2.payload + 24, 34U) != 0,
            "Ciphertexts of identical messages must differ (no static keystream reuse)");

    uint8_t plain_out[64];
    size_t plain_len = 0U;
    REQUIRE(ozos_mesh_frame_decrypt(plain_out, sizeof(plain_out), &plain_len, &enc1, alice_pk, bob_sk),
            "Bob must decrypt Alice's E2EE frame");
    REQUIRE(plain_len == strlen(secret) && memcmp(plain_out, secret, plain_len) == 0,
            "Decrypted plaintext must match original");
    printf("  [PASS 2/10] X25519 ECDH + XSalsa20-Poly1305 Roundtrip & Unique Nonces\n");

    /* 3. RFC 7748 Low-Order Point & Self-Reflection Key Rejection */
    static const uint8_t low_order_zero[32] = {0};
    static const uint8_t low_order_one[32]  = {1};
    static const uint8_t low_order_p_minus_1[32] = {
        0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f
    };
    ozos_mesh_frame_t bad_frame = enc1;
    REQUIRE(!ozos_mesh_frame_encrypt(&bad_frame, (const uint8_t*)"X", 1U, low_order_zero, alice_sk),
            "Must reject all-zero X25519 point");
    REQUIRE(!ozos_mesh_frame_encrypt(&bad_frame, (const uint8_t*)"X", 1U, low_order_one, alice_sk),
            "Must reject order-1 point {1,0...}");
    REQUIRE(!ozos_mesh_frame_encrypt(&bad_frame, (const uint8_t*)"X", 1U, low_order_p_minus_1, alice_sk),
            "Must reject order-2 point p-1");
    REQUIRE(!ozos_mesh_frame_encrypt(&bad_frame, (const uint8_t*)"X", 1U, alice_pk, alice_sk),
            "Must reject self-reflection keypair (peer_pk == sender_pk)");
    printf("  [PASS 3/10] RFC 7748 Low-Order Curve25519 & Self-Reflection Rejection\n");

    /* 4. Header AAD Binding Against Spoofing & Forgery (Even With Valid Outer CRC-16) */
    ozos_mesh_frame_t forged_src = enc1;
    forged_src.src_node_id ^= 0x00000001U;
    ozos_mesh_seal(&forged_src); /* Recompute valid outer link CRC-16 */
    REQUIRE(!ozos_mesh_frame_decrypt(plain_out, sizeof(plain_out), &plain_len, &forged_src, alice_pk, bob_sk),
            "Tampered src_node_id must fail Poly1305 AAD verification");

    ozos_mesh_frame_t forged_dst = enc1;
    forged_dst.dst_node_id ^= 0x00000001U;
    ozos_mesh_seal(&forged_dst);
    REQUIRE(!ozos_mesh_frame_decrypt(plain_out, sizeof(plain_out), &plain_len, &forged_dst, alice_pk, bob_sk),
            "Tampered dst_node_id must fail Poly1305 AAD verification");

    ozos_mesh_frame_t forged_seq = enc1;
    forged_seq.packet_id += 1U;
    ozos_mesh_seal(&forged_seq);
    REQUIRE(!ozos_mesh_frame_decrypt(plain_out, sizeof(plain_out), &plain_len, &forged_seq, alice_pk, bob_sk),
            "Tampered packet_id must fail Poly1305 AAD verification");

    /* Relay hop_limit decrement MUST remain valid end-to-end! */
    ozos_mesh_frame_t relayed_ok = enc1;
    relayed_ok.hop_limit--;
    ozos_mesh_seal(&relayed_ok);
    REQUIRE(ozos_mesh_frame_decrypt(plain_out, sizeof(plain_out), &plain_len, &relayed_ok, alice_pk, bob_sk),
            "Legitimate intermediate hop_limit decrement must still decrypt cleanly");
    printf("  [PASS 4/10] Header AAD Poly1305 Binding & Transit TTL Compatibility\n");

    /* 5. Caller Output Buffer Capacity Enforcement */
    uint8_t tiny_buf[8];
    size_t tiny_len = 0U;
    REQUIRE(!ozos_mesh_frame_decrypt(tiny_buf, sizeof(tiny_buf), &tiny_len, &enc1, alice_pk, bob_sk),
            "Must fail closed when caller out_max_len is smaller than plaintext + NUL");
    printf("  [PASS 5/10] Bounded Caller Output Buffer Enforcement (out_max_len)\n");

    /* 6. Dual-Generation SipHash-2-4 Rotating Bloom Filter Anti-Blackhole Resilience */
    ozos_mesh_bloom_t bf;
    ozos_mesh_bloom_init(&bf);

    /* Flood 5,000 adversarial packets to attempt saturation blackhole DoS */
    for (uint32_t i = 1U; i <= 5000U; ++i) {
        ozos_mesh_bloom_add(&bf, i, 0xBADF0001U);
    }
    REQUIRE(bf.rotation_epochs >= 18U, "Dual-gen Bloom filter must rotate epochs automatically");

    /* Immediately re-testing the most recent 200 packets MUST still be suppressed 100% */
    for (uint32_t i = 4850U; i <= 5000U; ++i) {
        REQUIRE(ozos_mesh_bloom_test(&bf, i, 0xBADF0001U),
                "Recent duplicates across active/standby banks must be 100% suppressed");
    }

    /* Now test 1,000 brand-new unseen legitimate frames: >98% MUST pass (0% blackhole!) */
    uint32_t passed_legit = 0U;
    for (uint32_t seq = 900000U; seq < 901000U; ++seq) {
        if (!ozos_mesh_bloom_test(&bf, seq, 0xA11CE001U)) {
            passed_legit++;
        }
    }
    REQUIRE(passed_legit >= 980U, "Rotating SipHash Bloom filter must resist saturation blackhole (>98% pass)");
    printf("  [PASS 6/10] Dual-Gen SipHash-2-4 Bloom Anti-Blackhole (%u/1000 passed after 5000-pkt flood)\n",
           passed_legit);

    /* 7. DTN Store-and-Forward Cache Isolation (No Zombie / Private Frame Pollution) */
    ozos_mesh_bloom_t r_bf;
    ozos_mesh_cache_t r_cache;
    ozos_mesh_bloom_init(&r_bf);
    ozos_mesh_cache_init(&r_cache);

    /* 7a: Expired frame (TTL = 1) must be dropped AND excluded from DTN cache */
    ozos_mesh_frame_t f_exp;
    memset(&f_exp, 0, sizeof(f_exp));
    f_exp.hop_limit = 1U; f_exp.src_node_id = 0x11110001U; f_exp.dst_node_id = 0x99990009U; f_exp.packet_id = 1U;
    ozos_mesh_seal(&f_exp);
    REQUIRE(ozos_mesh_process_frame(&f_exp, 0x22220002U, &r_bf, &r_cache) == OZOS_MESH_ACTION_DROP_EXPIRED,
            "TTL=1 transit frame must return DROP_EXPIRED");
    REQUIRE(r_cache.count == 0U, "Expired frame must NOT enter DTN cache");

    /* 7b: Oversized TTL (> 64) zombie frame must be dropped */
    f_exp.hop_limit = 65535U; f_exp.packet_id = 2U;
    ozos_mesh_seal(&f_exp);
    REQUIRE(ozos_mesh_process_frame(&f_exp, 0x22220002U, &r_bf, &r_cache) == OZOS_MESH_ACTION_DROP_EXPIRED,
            "TTL > OZOS_MESH_MAX_TTL must be dropped");
    REQUIRE(r_cache.count == 0U, "Oversized TTL frame must NOT enter DTN cache");

    /* 7c: Private unicast frame addressed to local node must DELIVER without entering DTN cache */
    ozos_mesh_frame_t f_priv;
    memset(&f_priv, 0, sizeof(f_priv));
    f_priv.hop_limit = 5U; f_priv.src_node_id = 0x11110001U; f_priv.dst_node_id = 0x22220002U; f_priv.packet_id = 3U;
    ozos_mesh_seal(&f_priv);
    REQUIRE(ozos_mesh_process_frame(&f_priv, 0x22220002U, &r_bf, &r_cache) == OZOS_MESH_ACTION_DELIVER,
            "Local unicast frame must DELIVER");
    REQUIRE(r_cache.count == 0U, "Private DELIVER frame must NOT enter DTN transit cache");

    /* 7d: Valid transit frame (TTL = 4) must RELAY and store decremented TTL = 3 in DTN cache */
    ozos_mesh_frame_t f_rel;
    memset(&f_rel, 0, sizeof(f_rel));
    f_rel.hop_limit = 4U; f_rel.src_node_id = 0x11110001U; f_rel.dst_node_id = 0x99990009U; f_rel.packet_id = 4U;
    ozos_mesh_seal(&f_rel);
    REQUIRE(ozos_mesh_process_frame(&f_rel, 0x22220002U, &r_bf, &r_cache) == OZOS_MESH_ACTION_RELAY,
            "Valid transit frame must RELAY");
    REQUIRE(r_cache.count == 1U && r_cache.slots[0].hop_limit == 3U &&
            ozos_mesh_verify_integrity(&r_cache.slots[0]),
            "DTN cache must hold post-decremented resealed frame (TTL=3)");

    /* 7e: Re-injecting identical (packet_id, src_node_id) into router must return DROP_SEEN */
    REQUIRE(ozos_mesh_process_frame(&f_rel, 0x22220002U, &r_bf, &r_cache) == OZOS_MESH_ACTION_DROP_SEEN,
            "Router must return DROP_SEEN when duplicate frame arrives");
    REQUIRE(r_cache.count == 1U, "Duplicate frame must not be pushed to DTN cache");
    printf("  [PASS 7/10] DTN Store-and-Forward Isolation, Duplicate Drop & Post-Decrement Integrity\n");

    /* 8. Multi-Hop Broadcast Propagation & Final-Hop Termination */
    ozos_mesh_bloom_t b_bf1, b_bf2;
    ozos_mesh_cache_t b_c1, b_c2;
    ozos_mesh_bloom_init(&b_bf1); ozos_mesh_bloom_init(&b_bf2);
    ozos_mesh_cache_init(&b_c1);  ozos_mesh_cache_init(&b_c2);

    ozos_mesh_frame_t f_bcast;
    memset(&f_bcast, 0, sizeof(f_bcast));
    f_bcast.hop_limit = 2U;
    f_bcast.src_node_id = 0x11110001U;
    f_bcast.dst_node_id = OZOS_MESH_BROADCAST_ID;
    f_bcast.packet_id = 777U;
    ozos_mesh_seal(&f_bcast);

    /* Hop 1 (TTL 2 -> 1): DELIVER_AND_RELAY */
    REQUIRE(ozos_mesh_process_frame(&f_bcast, 0x22220002U, &b_bf1, &b_c1) == OZOS_MESH_ACTION_DELIVER_AND_RELAY,
            "Broadcast with TTL=2 must DELIVER_AND_RELAY");
    REQUIRE(f_bcast.hop_limit == 1U && b_c1.count == 1U, "Broadcast hop 1 must decrement TTL to 1");

    /* Hop 2 (TTL == 1): Final hop DELIVER only, no further relay/cache */
    REQUIRE(ozos_mesh_process_frame(&f_bcast, 0x33330003U, &b_bf2, &b_c2) == OZOS_MESH_ACTION_DELIVER,
            "Broadcast at final hop TTL=1 must DELIVER without relaying");
    REQUIRE(b_c2.count == 0U, "Final-hop broadcast must not enter DTN relay cache");
    printf("  [PASS 8/10] Multi-Hop Broadcast Propagation & Final-Hop Termination\n");

    /* 9. SLIP-84 Hardware UART Byte-Stuffing & Line-Noise Resynchronization */
    uint8_t enc_wire[80];
    ozos_mesh_frame_t f_slip_src = enc1;
    /* Force SLIP special bytes (0xC0 END, 0xDB ESC) inside payload to prove byte-stuffing */
    f_slip_src.flags = OZOS_MESH_FLAG_CLEARTEXT;
    f_slip_src.payload[0] = OZOS_SLIP_END;
    f_slip_src.payload[1] = OZOS_SLIP_ESC;
    f_slip_src.payload[2] = OZOS_SLIP_ESC_END;
    f_slip_src.payload[3] = OZOS_SLIP_ESC_ESC;
    ozos_mesh_seal(&f_slip_src);
    ozos_mesh_frame_encode(&f_slip_src, enc_wire);

    uint8_t slip_pkt[OZOS_PHY_SLIP_MAX_WIRE];
    size_t slip_len = 0U;
    ozos_phy_slip_encode(enc_wire, slip_pkt, &slip_len);
    REQUIRE(slip_len > 86U && slip_len <= OZOS_PHY_SLIP_MAX_WIRE, "SLIP-84 encoded size must expand stuffed bytes");

    ozos_phy_slip_rx_t slip_rx;
    ozos_phy_slip_rx_init(&slip_rx);
    uint8_t rec_wire[80];
    /* Prepend random UART line noise & truncated garbage frame before valid SLIP frame */
    static const uint8_t uart_noise[9] = { 0xFFU, 0x13U, 0xDBU, 0x00U, 0x42U, 0xC0U, 0x99U, 0xAAU, 0xC0U };
    for (size_t i = 0U; i < sizeof(uart_noise); ++i) {
        REQUIRE(!ozos_phy_slip_feed_byte(&slip_rx, uart_noise[i], rec_wire), "UART noise must not emit false frame");
    }
    bool got_slip = false;
    for (size_t i = 0U; i < slip_len; ++i) {
        if (ozos_phy_slip_feed_byte(&slip_rx, slip_pkt[i], rec_wire)) {
            got_slip = true;
        }
    }
    REQUIRE(got_slip && memcmp(rec_wire, enc_wire, 80U) == 0,
            "SLIP-84 receiver must resynchronize after line noise and recover exact 80-byte frame");
    printf("  [PASS 9/10] SLIP-84 Hardware UART Byte-Stuffing & Line-Noise Resync\n");

    /* 10. Near-Ultrasound 18.1-19.8 kHz Modem Async Offset, Attenuation & AWGN Resilience */
    uint8_t sonic_orig[80];
    ozos_mesh_frame_encode(&enc1, sonic_orig);
    ozos_sonic_modulate_frame(sonic_orig, g_test_sonic_tx);

    /* Simulate async microphone capture: +317 sample offset, 0.18x room attenuation, and AWGN */
    memset(g_test_sonic_rx, 0, sizeof(g_test_sonic_rx));
    uint32_t lfsr = 0xACE1CAFEU;
    const size_t async_offset = 317U;
    for (size_t i = 0U; i < sizeof(g_test_sonic_rx) / sizeof(g_test_sonic_rx[0]); ++i) {
        lfsr = (lfsr >> 1) ^ (-(int32_t)(lfsr & 1U) & 0xB400U);
        int16_t noise = (int16_t)((int32_t)(lfsr & 0xFFU) - 128); /* +-128 LSB floor noise */
        int32_t sig = 0;
        if (i >= async_offset && (i - async_offset) < OZOS_SONIC_BURST_SAMPLES) {
            sig = ((int32_t)g_test_sonic_tx[i - async_offset] * 18) / 100;
        }
        g_test_sonic_rx[i] = (int16_t)(sig + noise);
    }

    uint8_t sonic_recovered[80];
    size_t sonic_consumed = 0U;
    REQUIRE(ozos_sonic_demodulate_stream(
                g_test_sonic_rx,
                sizeof(g_test_sonic_rx) / sizeof(g_test_sonic_rx[0]),
                sonic_recovered,
                &sonic_consumed),
            "18.1-19.8 kHz Ultrasonic demodulator must lock onto async attenuated noisy burst");
    REQUIRE(memcmp(sonic_recovered, sonic_orig, 80U) == 0,
            "Demodulated ultrasonic 80-byte E2EE frame must match transmitted bytes 100%");
    printf("  [PASS 10/12] 18.1-19.8 kHz Ultrasonic Modem Async Offset & Noise Recovery\n");

    /* 11. Pre-Bloom Anti-Poisoning TTL Gate: Expired/Invalid TTL Must Not Poison or Rotate Bloom */
    ozos_mesh_bloom_t poison_bf;
    ozos_mesh_bloom_init(&poison_bf);
    ozos_mesh_frame_t poison_f;
    memset(&poison_f, 0, sizeof(poison_f));
    poison_f.flags = OZOS_MESH_FLAG_CLEARTEXT;
    poison_f.src_node_id = 0xCAFE0001U;
    poison_f.dst_node_id = 0xCAFE0002U;
    poison_f.packet_id = 0x77770001U;
    poison_f.hop_limit = 0U;
    memcpy(poison_f.payload, "POISON", 6U);
    ozos_mesh_seal(&poison_f);
    REQUIRE(ozos_mesh_process_frame(&poison_f, 0xCAFE0002U, &poison_bf, NULL) == OZOS_MESH_ACTION_DROP_EXPIRED,
            "Zero-TTL unicast frame must be dropped as expired");
    REQUIRE(poison_bf.active_count == 0U && !ozos_mesh_bloom_test(&poison_bf, 0x77770001U, 0xCAFE0001U),
            "Dropped expired unicast frame must NOT poison SipHash Bloom filter");

    poison_f.hop_limit = 1U;
    ozos_mesh_seal(&poison_f);
    REQUIRE(ozos_mesh_process_frame(&poison_f, 0xBBBB0009U, &poison_bf, NULL) == OZOS_MESH_ACTION_DROP_EXPIRED,
            "TTL=1 transit frame must be dropped as expired");
    REQUIRE(poison_bf.active_count == 0U && !ozos_mesh_bloom_test(&poison_bf, 0x77770001U, 0xCAFE0001U),
            "Dropped TTL=1 transit frame must NOT poison SipHash Bloom filter");

    /* Legitimate frame with same (src_node_id, packet_id) and valid TTL must still deliver! */
    poison_f.hop_limit = 4U;
    ozos_mesh_seal(&poison_f);
    REQUIRE(ozos_mesh_process_frame(&poison_f, 0xCAFE0002U, &poison_bf, NULL) == OZOS_MESH_ACTION_DELIVER,
            "Valid frame after expired-TTL spoof attempt must be delivered");
    printf("  [PASS 11/12] Pre-Bloom Anti-Poisoning TTL Gate (Zero False Suppression / Rotation)\n");

    /* 12. RIFF-WAV Chunk Parser Hardening: Reject Missing 'data' Chunk & Skip 'JUNK' Chunk */
    const char* bad_wav_path = "test_bad_chunk.wav";
    uint8_t fake_wav[48];
    memset(fake_wav, 0, sizeof(fake_wav));
    memcpy(fake_wav + 0,  "RIFF", 4U);
    ozos_le32_write(fake_wav + 4, 40U);
    memcpy(fake_wav + 8,  "WAVEfmt ", 8U);
    ozos_le32_write(fake_wav + 16, 16U);
    ozos_le16_write(fake_wav + 20, 1U);
    ozos_le16_write(fake_wav + 22, 1U);
    ozos_le32_write(fake_wav + 24, OZOS_SONIC_SAMPLE_RATE);
    ozos_le32_write(fake_wav + 28, OZOS_SONIC_SAMPLE_RATE * 2U);
    ozos_le16_write(fake_wav + 32, 2U);
    ozos_le16_write(fake_wav + 34, 16U);
    memcpy(fake_wav + 36, "JUNK", 4U); /* Non-audio metadata chunk instead of 'data' */
    ozos_le32_write(fake_wav + 40, 4U);
    memcpy(fake_wav + 44, "META", 4U);
    FILE* f_bad = fopen(bad_wav_path, "wb");
    REQUIRE(f_bad != NULL, "Open temporary bad WAV");
    (void)fwrite(fake_wav, 1U, sizeof(fake_wav), f_bad);
    fclose(f_bad);
    int16_t dummy_pcm[16];
    size_t dummy_n = 0U;
    REQUIRE(!ozos_phy_wav_read(bad_wav_path, dummy_pcm, 16U, &dummy_n),
            "WAV parser must reject RIFF file lacking a valid 'data' chunk");
    (void)remove(bad_wav_path);
    printf("  [PASS 12/12] RIFF-WAV Chunk Parser Hardening & Non-Data Chunk Rejection\n");

    ozos_mesh_zeroize(alice_sk, sizeof(alice_sk));
    ozos_mesh_zeroize(bob_sk, sizeof(bob_sk));

    printf("=================================================================\n");
    printf("  ALL 12/12 NATIVE C99 SECURITY & PHY INVARIANTS VERIFIED 100%%!\n");
    printf("=================================================================\n");
    return 0;
}
