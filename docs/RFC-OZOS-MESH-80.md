# RFC-OZOS-MESH-80: Sovereign Zero-IP P2P Mesh Routing Protocol

```text
Status: Informational / Standards Track
Category: Sovereign Decentralized Networking
Version: 1.3.0-MESH (Physical Transport & Sovereign Hardened)
Author: LumenNull & The Sovereign Citizens of Humankind
Date: 2026-11-07
Parity Invariant: Bitcoin Block Header Alignment (Exactly 80 Bytes / 640 Bits, Little-Endian)
```

---

## 1. Abstract

RFC-OZOS-MESH-80 defines the canonical wire framing, routing logic, duplicate suppression, and physical transport interfaces for **OZOS-Mesh**, a zero-heap, zero-IP peer-to-peer mesh routing protocol. Designed as **Leg 2 of the Sovereign Triad**, OZOS-Mesh provides resilient, decentralized communication across contested, offline, or air-gapped environments without relying on internet service providers, cellular infrastructure, or TCP/IP addressing.

---

## 2. Terminology & Core Invariants

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

1. **Zero-IP Addressing:** Nodes SHALL NOT use IPv4, IPv6, or IEEE 802.3/802.11 MAC addresses for network routing. All network endpoints MUST be identified strictly by a 32-bit Cryptographic Node ID derived from an Ed25519 public key.
2. **Canonical 80-Byte Invariant (`OZOS-80`):** Every transmitted frame SHALL be exactly 80 bytes (640 bits) in length. Variable-length framing is strictly forbidden to eliminate heap fragmentation and metadata leakage.
3. **Zero Heap Allocation (`malloc = 0`):** All router operations, packet queues, and duplicate filters MUST execute strictly within stack or static memory. Dynamic heap allocation (`malloc`, `free`, `realloc`) is prohibited.
4. **Epidemic Delay-Tolerant Store-and-Forward (DTN):** In disconnected environments, nodes opportunistically cache and forward frames upon encountering neighboring nodes across heterogeneous physical carriers.
5. **Dual-Generation Keyed SipHash-2-4 Rotating Bloom Filter:** To prevent broadcast storms, saturation blackhole DoS, and offline hash-collision censorship, every node MUST maintain a stack/static-resident $2 \times 4096$-bit rotating Bloom filter keyed with a 128-bit CSPRNG SipHash-2-4 secret evaluated in $O(1)$ time.

---

## 3. Canonical Frame Structure (80 Bytes)

The `OZOS-80` frame format is packed with 1-byte alignment:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Magic (0x4F5A4D53)                       | [00-03]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Hop Limit (TTL)      |             Flags             | [04-07]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Node ID                         | [08-11]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Node ID                       | [12-15]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Packet Sequence ID                      | [16-19]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | [20-23]
|                                                               | [24-27]
|                    Payload Data (58 Bytes)                    |  ...
|                                                               | [74-77]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tripwire MAC16        |                                 [78-79]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.1 Field Definitions

| Offset | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00 - 0x03` | `magic` | `uint32_t` | Magic constant `0x4F5A4D53` (Little-Endian wire bytes `53 4D 5A 4F`). |
| `0x04 - 0x05` | `hop_limit` | `uint16_t` | Time-to-Live (`1..64` LE16). Decremented at each intermediate hop. |
| `0x06 - 0x07` | `flags` | `uint16_t` | Bit 0: X25519-AEAD Encrypted (`0x0001`); Bit 1: Ephemeral; Bit 2: PQC. |
| `0x08 - 0x0B` | `src_node_id` | `uint32_t` | Non-zero SHA-512[0..3] LE32 truncation of sender's 32B Public Key. |
| `0x0C - 0x0F` | `dst_node_id` | `uint32_t` | Recipient ID, or `0xFFFFFFFF` for multi-hop broadcast. |
| `0x10 - 0x13` | `packet_id` | `uint32_t` | Non-zero CSPRNG / monotonic sequence identifier (LE32). |
| `0x14 - 0x4D` | `payload` | `uint8_t[58]` | `[8B Salt][16B Poly1305 Tag][34B Constant-Size AEAD Body]` or beacon data. |
| `0x4E - 0x4F` | `tripwire_mac`| `uint16_t` | Outer Link CRC-16 pre-filter over wire bytes `0x00..0x4D` (LE16). |

---

## 4. Anti-Storm Duplicate Suppression (Dual-Generation SipHash-2-4 Rotating Bloom Filter)

Because epidemic mesh protocols broadcast frames across shared physical media (RF, audio, optical), duplicate suppression must resist both saturation blackhole DoS and offline pre-image collision poisoning:

1. **Filter Dimensions:** Dual-generation rotating banks ($2 \times 4096\text{ bits} = 1024\text{ bytes}$ stack-resident), $k = 3$ Kirsch-Mitzenmacher indices.
2. **Keyed Cryptographic PRF:** Per-node 128-bit CSPRNG-keyed **SipHash-2-4** over $(\text{src\_node\_id} \parallel \text{packet\_id})$.
3. **Epoch Rotation:** Active bank swaps with standby bank every `256` insertions, maintaining $< 0.5\%$ steady-state false-positive rate and eliminating permanent saturation blackholes.

---

## 5. Routing & Forwarding State Machine

When a frame is received by a node:

```text
[Incoming Frame]
       │
       ▼
 [Integrity Check] ──(Corrupted / Invalid Magic)──► [DROP_INVALID]
       │ Valid
       ▼
  [Bloom Filter]   ──(Duplicate Frame Seen)───────► [DROP_SEEN]
       │ New
       ▼
[Cache & Register]
       │
       ├─► (dst_node_id == local_id OR dst_node_id == 0xFFFFFFFF) ──► [DELIVER]
       │
       └─► (dst_node_id != local_id)
                 │
                 ├─► (hop_limit <= 1) ───────────► [DROP_EXPIRED]
                 │
                 └─► (hop_limit > 1)  ───────────► Decrement hop_limit
                                                   Reseal MAC16
                                                   [RELAY via PHY]
```

---

## 6. Physical Carrier Modalities

OZOS-Mesh frames are carrier-agnostic and map directly into the three physical transport tiers:

1. **Tier 1 Optical (Visible / Infrared):**
   - Transmitted as a 32x32 luminance matrix via computer monitor, smartphone screen, or laser diode.
   - Frame duration: 16.6ms at 60fps.
2. **Tier 2 Acoustic (Near-Ultrasound):**
   - Modulated via 18.1 - 19.8 kHz near-ultrasound using 64-FFT OFDM across 16 subcarriers.
   - Transmission duration: $< 40\text{ms}$.
3. **Tier 3 Sub-GHz RF (LoRa SX1262 / SX1276):**
   - Transmitted as an 84-byte LoRa packet (2B preamble sync + 1B packet type + 80B frame + 1B RF trailer).
   - Operational range: 5 to 15 km line-of-sight.

---

## 7. Security & Threat Mitigation

- **No ARP/DHCP/DNS Spoofing:** Because IP and MAC layers do not exist, ARP poison attacks, rogue DHCP injection, and DNS hijacking are fundamentally impossible.
- **Tripwire Integrity:** Any bit flipped in the 80-byte envelope invalidates the 16-bit MAC in $< 20\text{ns}$, dropping malformed frames prior to cryptographic payload processing.
- **End-to-End Privacy:** Intermediate relay nodes forward ciphertext envelopes with zero ability to read or tamper with encrypted payloads.

---

## 8. References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels.
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (Ed25519).
- [MISRA C:2012] Guidelines for the use of the C language in critical systems.
- [Bitcoin RFC] Bitcoin Block Header 80-Byte Wire Format Specification.
