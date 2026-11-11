# OZOS-Mesh Architecture: Leg 2 of the Sovereign Triad

## 1. Architectural Role in the Sovereign Triad

The **Sovereign Triad ("The Chan Vac")** establishes a tripartite foundation for self-sovereign computing and uncensorable communications:

1. **Leg 1: Core & Ephemeral Vault (`OZOS`):** Data-at-rest protection, stack enclave, post-quantum cryptography (NIST FIPS 203), and anti-forensic memory sanitization.
2. **Leg 2: Sovereign Mesh P2P (`OZOS-Mesh`):** Zero-IP peer-to-peer opportunistic routing, broadcast storm suppression, and multi-hop transport across physical media.
3. **Leg 3: Autonomous Hardware & Off-Grid Energy (`OZOS-Hardware`):** Bare-metal microcontroller nodes (ESP32-S3, STM32, nRF52) powered by off-grid solar harvesting.
4. **The Center: Sovereign Agent Eye:** Autonomous AI reasoning with persistent long-term memory and memory consolidation.

---

## 2. Zero-IP Network Model

Traditional networks depend on centralized authorities:
- Regional Internet Registries (RIRs) assign IP blocks.
- Telecommunication ISPs assign routing prefixes and track subscriber identities.
- Centralized DNS servers resolve hostnames to IP addresses.

**OZOS-Mesh eliminates all three layers:**
- Nodes address packets using a **32-bit Cryptographic Node ID** derived directly from the node's Ed25519 identity key.
- Packets propagate across physical carriers via **opportunistic epidemic gossiping** and **store-and-forward delay-tolerant routing**.
- There are zero IP headers, zero MAC address tracking, and zero central gateways.

---

## 3. Data Flow Diagram

```text
[Node A (Source)]
       │
       ▼ (80-Byte OZOS-80 Frame)
[Physical Modem: LoRa / Acoustic / Optical]
       │
       ▼ (Over-The-Air Broadcast)
[Node B (Relay Node)]
       │
       ├─► Check Integrity (CRC16)                ──► If corrupted: DROP
       ├─► Check SipHash Bloom (2x4096-bit)       ──► If duplicate: DROP
       ├─► Check Destination                      ──► Destination != Bob
       │                                              Hop Limit > 1
       │                                              Decrement TTL & Reseal CRC16
       ▼
[Node B Rebroadcasts via SLIP-84 UART / 18.1-19.8 kHz Ultrasonic]
       │
       ▼
[Node C (Destination)]
       │
       ├─► Check Integrity (CRC16)                ──► Verified
       ├─► Check SipHash Bloom (2x4096-bit)       ──► Registered
       └─► Check Destination + Poly1305 AAD       ──► Destination == Charlie
                                                      [DELIVER to Application]
```

---

## 4. Hardware Integration Interface (Leg 3 Readiness)

`OZOS-Mesh` is designed to run directly on microcontrollers with as little as 32 KB of RAM:

| Platform | Carrier Interface | Typical Range | RAM Footprint |
| :--- | :--- | :--- | :--- |
| **PC / Laptop (x86_64)** | Speaker / Mic (OFDM Acoustic) | 0 - 15 meters | < 160 KB |
| **PC / Laptop (x86_64)** | Monitor / Webcam (32x32 Glyph)| 0 - 5 meters | < 160 KB |
| **ESP32-S3 / LoRa** | Semtech SX1262 (SPI Bus) | 5 - 15 km | ~8 KB (Static) |
| **STM32F4 / LoRa** | Semtech SX1276 (SPI Bus) | 5 - 15 km | ~8 KB (Static) |
| **nRF52840 / BLE** | 2.4 GHz BLE Coded PHY | 50 - 200 meters | ~6 KB (Static) |
