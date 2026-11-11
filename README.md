# O.Z.O.S // MESH (Sovereign Zero-IP P2P Router)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI: Sovereign Assurance](https://github.com/LumenNull/OZOS-Mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/LumenNull/OZOS-Mesh/actions/workflows/ci.yml)
[![Standards: RFC--OZOS--MESH--80](https://img.shields.io/badge/Standards-RFC--OZOS--MESH--80-emerald.svg)](docs/RFC-OZOS-MESH-80.md)
[![Memory: Zero--Heap](https://img.shields.io/badge/Memory-Zero--Heap%20(malloc=0)-gold.svg)](include/ozos_mesh.h)
[![Wire Invariant: OZOS--80](https://img.shields.io/badge/Wire%20Format-80%20Bytes%20(OZOS--80)-purple.svg)](include/ozos_mesh.h)
[![Compliance: MISRA C](https://img.shields.io/badge/Compliance-MISRA%20C%20Ready-cyan.svg)](include/ozos_mesh.h)

> **"When central cables are severed, sovereign nodes become the network."**

---

## 1. Overview

**OZOS-Mesh** is a physical-first, zero-IP peer-to-peer mesh routing protocol and standalone daemon designed as **Leg 2 of the Sovereign Triad ("The Sovereign Triad")**. It enables uncensorable, resilient multi-hop communication across contested, offline, or air-gapped environments without relying on internet service providers, cellular base stations, or traditional TCP/IP addressing.

### The Sovereign Triad

```text
               ╔═══════════════════════════════════════╗
               ║   SOVEREIGN AGENT EYE (CENTER CORE)   ║
               ║  Autonomous Reflexes & Ephemeral Mind ║
               ╚══════════════════╦════════════════════╝
                                  ║
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
  ╔══════════════════╗     ╔══════════════════╗     ╔══════════════════╗
  ║      LEG 1       ║     ║      LEG 2       ║     ║      LEG 3       ║
  ║  O.Z.O.S Core &  ║     ║   OZOS-Mesh      ║     ║   Autonomous     ║
  ║ Ephemeral Vault  ║     ║ Sovereign P2P    ║     ║    Hardware      ║
  ║  (Memory Armor)  ║     ║ (Zero-IP Mesh)   ║     ║ (Off-Grid Solar) ║
  ╚══════════════════╝     ╚══════════════════╝     ╚══════════════════╝
```

---

## 2. Core Architectural Invariants

### 1. Zero-IP Addressing
OZOS-Mesh completely eliminates IP addresses, subnet masks, and network interface MAC tracking. Nodes are addressed strictly by a **32-bit Cryptographic Node ID** derived from the node's Ed25519 identity key. Attack surfaces such as ARP poisoning, rogue DHCP injection, and IP geofencing are mathematically neutralized.

### 2. Canonical 80-Byte Wire Frame (`OZOS-80`)
Every packet adheres strictly to the canonical 80-byte (640 bits) `OZOS-80` invariant, matching the Bitcoin block header size:

$$\text{Packet Size} = 4\text{B}_{\text{magic}} + 2\text{B}_{\text{ttl}} + 2\text{B}_{\text{flags}} + 4\text{B}_{\text{src}} + 4\text{B}_{\text{dst}} + 4\text{B}_{\text{seq}} + 58\text{B}_{\text{payload}} + 2\text{B}_{\text{mac}} = 80\text{ Bytes}$$

### 3. Zero-Heap Memory Execution (`malloc = 0`)
OZOS-Mesh guarantees zero heap allocation at runtime. All packet buffers, routing state, Bloom filters, and store-and-forward queues reside entirely within stack and static memory bounds, eliminating heap fragmentation, use-after-free vulnerabilities, and memory leaks.

### 4. Dual-Generation Keyed SipHash-2-4 Rotating Bloom Filter
To suppress broadcast storms while resisting saturation blackhole DoS and offline hash-collision censorship, each node maintains a zero-heap $2 \times 4096$-bit rotating Bloom filter keyed by a 128-bit CSPRNG SipHash-2-4 secret.

### 5. Authenticated X25519 + XSalsa20-Poly1305 Onion Enclave
Encrypted frames derive shared secrets via RFC 7748 Curve25519 (with constant-time low-order point rejection) and authenticate immutable routing headers (`src_node_id`, `dst_node_id`, `packet_id`, `flags`) inside an injective 24-byte per-packet salted AEAD nonce.

### 6. Delay-Tolerant Store-and-Forward (DTN)
In sparse or intermittent networks, nodes buffer post-decremented unexpired transit frames within an ephemeral 16-frame ring queue, isolating private local deliveries and purging expired packets.

---

## 3. Wire Frame Specification

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
|                    Payload Data (58 Bytes)                    |  ...
|                                                               | [74-77]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tripwire MAC16        |                                 [78-79]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 4. Quickstart & Compilation

### Build on POSIX / Linux / macOS / MinGW (`Makefile`)
```bash
make
make test
make mutation
```

### Build on Windows (`MSVC` / `GCC` / `Clang`)
```cmd
build.bat
```

---

## 5. Command-Line Interface, Physical Carriers & Headless Daemon

### 1. Launch Headless Zero-Heap Background Daemon & OS Boot Autostart
```cmd
ozos-mesh start --acoustic
ozos-mesh install-autostart --acoustic
ozos-mesh status
ozos-mesh stop
```

### 2. Enumerate & Transmit Over Physical Carriers (`18.1-19.8 kHz` Ultrasonic / `SLIP-84` UART)
```cmd
ozos-mesh phy-ports
ozos-mesh tx-acoustic <FRAME_HEX> --wav ultrasonic_burst.wav
ozos-mesh rx-acoustic --wav ultrasonic_burst.wav 0xC0C00003 --sender-pk <HEX> --local-sk <HEX>
ozos-mesh tx-serial COM3 <FRAME_HEX> --baud 115200
```

### 3. Inject Live `OZOS-80` Frame into Resident Background Daemon
```cmd
ozos-mesh inject <FRAME_HEX>
```

### 4. Generate Sovereign X25519 Identity & Encapsulate E2EE Frame
```cmd
ozos-mesh keygen
ozos-mesh pack 0xA11CE001 0xC0C00003 "SOVEREIGN_MESSAGE" 5 --peer-pk <HEX> --sender-sk <HEX>
```

### 5. Forward Incoming Frame & Multi-Hop Benchmark
```cmd
ozos-mesh forward <FRAME_HEX> 0xB0B00002 --sender-pk <HEX> --local-sk <HEX>
ozos-mesh sim-multihop
```

---

## 6. Multi-Hop Verification Benchmark

Executing `ozos-mesh sim-multihop` confirms end-to-end operation across 3 simulated nodes:

```text
=================================================================
  O.Z.O.S // MULTI-HOP SOVEREIGN MESH BENCHMARK (A -> B -> C)
  Topology: Node A (0xA11CE001) -> Node B Relay -> Node C (0xC0C00003)
=================================================================

[STEP 1: ALICE EMISSION]
  * Alice transmits 80-byte OZOS-80 frame destined for Charlie...
  * Payload: 'SOVEREIGN_MESH_P2P_SECRET_2026'
  * Initial Hop Limit: 3 | Tripwire MAC: 0x489C

[STEP 2: BOB RELAY DISPATCH]
  * Bob intercepts frame. Destination (0xC0C00003) != Bob (0xB0B00002).
  * Action: [RELAY] -> Decremented Hop Limit: 2
  * Resealed MAC16: 0x4AC1
  * Frame stored in Bob's DTN cache (depth=1) and Bloom filter.

[STEP 3: CHARLIE DESTINATION DELIVERY]
  * Charlie receives frame. Destination (0xC0C00003) == Charlie (0xC0C00003).
  * Action: [DELIVER] -> Local Delivery Verified 100%!
  * Recovered Secret: 'SOVEREIGN_MESH_P2P_SECRET_2026'

[STEP 4: ANTI-STORM BLOOM FILTER DUPLICATE SUPPRESSION]
  * Re-injected packet into Bob: Bloom Filter detected prior receipt!
  * Action: [DROP_SEEN] -> Duplicate instantly dropped! Zero Broadcast Storm.

[STEP 5: ANTI-ZOMBIE TTL EXCLUSION]
  * Hop limit reached threshold (TTL <= 1): Action: [DROP_EXPIRED] -> Purged.

=================================================================
  BENCHMARK PASSED 100%: SOVEREIGN MULTI-HOP MESH VERIFIED!
=================================================================
```

---

## 7. Automated & Adversarial Test Suites

```cmd
python tests/test_mesh_network.py
python tests/sim_mesh_topology.py
python tests/live_mesh_demo.py
python tests/mutation_test.py
```

- `test_mesh_network.py`: 11/11 hardened tests verifying E2EE routing, SipHash Bloom replay rejection, Poly1305 Header AAD anti-spoofing, ANSI sanitization, headless daemon IPC, 18.1-19.8 kHz ultrasonic WAV roundtrip, and OS boot autostart lifecycle.
- `sim_mesh_topology.py`: Multi-node linear graph simulation validating seamless transmission across 10 independent relay hops.
- `mutation_test.py`: Automated adversarial mutation testing achieving a 10/10 (100.0%) kill score across cryptographic, CRC-16, TTL, SipHash Bloom, SLIP-84 UART, and ultrasonic PHY invariants.

---

## 8. Physical Transport Modalities

OZOS-Mesh envelopes map seamlessly onto physical layer transports:

| Modality | Frequency / Spectrum | Baud / Bitrate | Range |
| :--- | :--- | :--- | :--- |
| **Tier 1 Optical** | Visible Screen / IR (32x32 Glyph) | 60 fps (16.6ms/frame) | Line-of-sight (0 - 5 m) |
| **Tier 2 Acoustic** | 18.1 - 19.8 kHz Near-Ultrasound | 16-Tone Dual-Rail @ 48 kHz | Room-scale (0 - 15 m) |
| **Tier 3 Sub-GHz RF** | 433 / 868 / 915 MHz (SLIP-84 UART / LoRa) | 115200 UART / SF7-SF12 | Long-range (5 - 15 km) |

---

## 9. Roadmap to Leg 3 (Autonomous Hardware)

- [x] Canonical 80-Byte wire envelope (`OZOS-80`).
- [x] Dual-Generation $2 \times 4096$-Bit Keyed SipHash-2-4 Rotating Bloom Filter.
- [x] Store-and-Forward Delay-Tolerant Network (DTN) ring queue.
- [x] Zero-Heap C99 SLIP-84 Hardware UART & 18.1-19.8 kHz Near-Ultrasound Modem (`include/ozos_mesh_phy.h`).
- [x] Headless Background Daemon, OS Boot Autostart & Cross-Platform GitHub Actions CI.
- [ ] ESP32-S3 / STM32 bare-metal SPI driver for Semtech SX1262 LoRa radio.
- [ ] Solar MPPT power telemetry and battery sleep-wake cycle integration.

---

## 10. License

Released under the [MIT License](LICENSE).  
Copyright (c) 2026 ZeroLab & The Sovereign Citizens of Humankind.
