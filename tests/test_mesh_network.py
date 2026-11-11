#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
O.Z.O.S Sovereign Mesh P2P Verification Suite (Hardened v1.1.0-MESH)
Tests Zero-IP E2EE Routing, SipHash Bloom Anti-Storm, CLI Bounds, and Terminal Sanitization.
"""

import os
import sys
import tempfile
import subprocess

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def resolve_mesh_bin(base_dir):
    exe_win = os.path.join(base_dir, "ozos-mesh.exe")
    exe_posix = os.path.join(base_dir, "ozos-mesh")
    return exe_win if os.path.exists(exe_win) else exe_posix


def extract_field(stdout, key_substr):
    for line in stdout.splitlines():
        if key_substr in line:
            return line.split(":", 1)[-1].strip()
    return None


def test_mesh():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mesh_exe = resolve_mesh_bin(base_dir)

    print("======================================================================")
    print("  O.Z.O.S SOVEREIGN MESH P2P HARDENED VERIFICATION SUITE (11 TESTS)")
    print("======================================================================")

    if not os.path.exists(mesh_exe):
        print(f"Error: {mesh_exe} not found! Run build.bat or make first.")
        return 1

    with tempfile.TemporaryDirectory(prefix="ozos_mesh_test_") as state_dir:
        env = os.environ.copy()
        env["OZOS_MESH_STATE_DIR"] = state_dir
        test_reg_key = r"Software\OZOS_Mesh_UnitTest_Autostart"
        env["OZOS_MESH_AUTOSTART_REGKEY"] = test_reg_key

        def run_cli(*args):
            return subprocess.run(
                [mesh_exe, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=10,
            )

        # 1. Status & Version
        print("[TEST 1/11] Verifying status & version invariants...")
        r_stat = run_cli("status")
        assert r_stat.returncode == 0 and "SOVEREIGN MESH ROUTER STATUS" in r_stat.stdout
        r_ver = run_cli("version")
        assert r_ver.returncode == 0 and "X25519 ECDH + XSalsa20-Poly1305 AEAD" in r_ver.stdout

        # 2. Keygen & True End-to-End Encrypted Multi-Hop Routing
        print("[TEST 2/11] Verifying X25519 keygen & E2EE multi-hop pack/relay/decrypt...")
        kg_a = run_cli("keygen")
        kg_c = run_cli("keygen")
        assert kg_a.returncode == 0 and kg_c.returncode == 0
        alice_id = extract_field(kg_a.stdout, "Node ID")
        alice_pk = extract_field(kg_a.stdout, "Public Key")
        alice_sk = extract_field(kg_a.stdout, "Secret Key")
        charlie_id = extract_field(kg_c.stdout, "Node ID")
        charlie_pk = extract_field(kg_c.stdout, "Public Key")
        charlie_sk = extract_field(kg_c.stdout, "Secret Key")

        secret_text = "E2EE_SOVEREIGN_PAYLOAD_2026"
        r_pack = run_cli(
            "pack", alice_id, charlie_id, secret_text, "5",
            "--peer-pk", charlie_pk, "--sender-sk", alice_sk,
        )
        assert r_pack.returncode == 0, f"E2EE pack failed: {r_pack.stdout} {r_pack.stderr}"
        hex_e2ee = extract_field(r_pack.stdout, "Raw Frame Hex")
        assert hex_e2ee and len(hex_e2ee) == 160
        raw_bytes = bytes.fromhex(hex_e2ee)
        assert int.from_bytes(raw_bytes[6:8], "little") == 0x0001
        assert secret_text.encode("ascii") not in raw_bytes, "Plaintext leaked onto wire!"

        # Relay at Bob (0xB0B00002)
        r_relay = run_cli("forward", hex_e2ee, "0xB0B00002")
        assert r_relay.returncode == 0 and "[RELAY]" in r_relay.stdout
        relayed_hex = extract_field(r_relay.stdout, "Relayed Hex")
        assert relayed_hex and len(relayed_hex) == 160

        # Replay exact packet at Bob -> MUST be [DROP_SEEN] across CLI invocations!
        print("[TEST 3/11] Verifying persistent SipHash Bloom replay rejection across CLI runs...")
        r_replay = run_cli("forward", hex_e2ee, "0xB0B00002")
        assert r_replay.returncode == 0 and "[DROP_SEEN]" in r_replay.stdout, (
            f"Replay was NOT dropped: {r_replay.stdout}"
        )

        # Deliver & Decrypt at Charlie
        r_deliv = run_cli(
            "forward", relayed_hex, charlie_id,
            "--sender-pk", alice_pk, "--local-sk", charlie_sk,
        )
        assert r_deliv.returncode == 0 and "[DELIVER]" in r_deliv.stdout
        assert secret_text in r_deliv.stdout

        # 4. Spoofed Header AAD Forgery Rejection (CRC-16 recomputed by attacker)
        print("[TEST 4/11] Verifying Poly1305 Header AAD blocks CRC-16 source spoofing...")
        forged = bytearray(bytes.fromhex(relayed_hex))
        forged[8:12] = (0xDEADBEEF).to_bytes(4, "little")
        crc = 0xFFFF
        for b in forged[:78]:
            crc ^= b
            for _ in range(8):
                crc = ((crc >> 1) ^ 0x8408) if (crc & 1) else (crc >> 1)
        forged[78:80] = crc.to_bytes(2, "little")
        r_forged = run_cli(
            "forward", forged.hex(), charlie_id,
            "--sender-pk", alice_pk, "--local-sk", charlie_sk, "--stateless",
        )
        assert r_forged.returncode != 0 and "[DROP_AUTH_FAIL]" in r_forged.stdout

        # Also verify outer Link CRC-16 rejects 1-bit wire corruption before routing
        corrupt = bytearray(bytes.fromhex(relayed_hex))
        corrupt[25] ^= 0x01
        r_corrupt = run_cli("forward", corrupt.hex(), "0xB0B00002", "--stateless")
        assert r_corrupt.returncode != 0 and "[DROP_INVALID]" in r_corrupt.stdout

        # 5. Cleartext Beacon Honest Flags & Unique CSPRNG Sequence IDs
        print("[TEST 5/11] Verifying cleartext beacon flags=0x0000 & non-colliding CSPRNG packet_id...")
        b1 = run_cli("pack", "0xA11CE001", "0xC0C00003", "BEACON_ONE", "4")
        b2 = run_cli("pack", "0xA11CE001", "0xC0C00003", "BEACON_TWO", "4")
        raw_b1 = bytes.fromhex(extract_field(b1.stdout, "Raw Frame Hex"))
        raw_b2 = bytes.fromhex(extract_field(b2.stdout, "Raw Frame Hex"))
        assert int.from_bytes(raw_b1[6:8], "little") == 0x0000
        assert raw_b1[16:20] != raw_b2[16:20], "Sequence ID collision detected!"

        # 6. CLI Integer Underflow & Boundary Rejection
        print("[TEST 6/11] Verifying strict rejection of negative TTL, negative IDs, and 0...")
        assert run_cli("pack", "-1", "0xC0C00003", "MSG", "5").returncode != 0
        assert run_cli("pack", "0xA11CE001", "-1", "MSG", "5").returncode != 0
        assert run_cli("pack", "0xA11CE001", "0xC0C00003", "MSG", "-1").returncode != 0
        assert run_cli("pack", "0xA11CE001", "0xC0C00003", "MSG", "0").returncode != 0
        assert run_cli("pack", "0xA11CE001", "0xC0C00003", "MSG", "999").returncode != 0
        assert run_cli("pack", "0x00000000", "0xC0C00003", "MSG", "5").returncode != 0
        assert run_cli("pack", "0xFFFFFFFF", "0xC0C00003", "MSG", "5").returncode != 0

        # 7. Terminal ANSI Escape Sequence Sanitization
        print("[TEST 7/11] Verifying terminal ANSI escape sequence sanitization...")
        r_esc_pack = run_cli("pack", "0xA11CE001", "0xC0C00003", "\x1b[31mFAKE_ALERT\x1b[0m", "3")
        esc_hex = extract_field(r_esc_pack.stdout, "Raw Frame Hex")
        r_esc_fwd = run_cli("forward", esc_hex, "0xC0C00003", "--stateless")
        assert r_esc_fwd.returncode == 0
        assert "\x1b" not in r_esc_fwd.stdout, "Unsanitized ESC byte leaked to terminal stdout!"
        assert ".[31mFAKE_ALERT.[0m" in r_esc_fwd.stdout

        # 8. Built-in 3-Node E2EE Benchmark
        print("[TEST 8/11] Verifying sim-multihop E2EE benchmark...")
        r_sim = run_cli("sim-multihop")
        assert r_sim.returncode == 0 and "BENCHMARK PASSED 100%" in r_sim.stdout

        # 9. Headless Background Daemon Lifecycle (start -> status -> inject -> replay -> stop)
        print("[TEST 9/11] Verifying headless background daemon start/status/inject/stop...")
        try:
            r_start = run_cli("start", "--node-id", "0xD4E00009")
            assert r_start.returncode == 0 and "BACKGROUND DAEMON LAUNCHED" in r_start.stdout, r_start.stdout

            r_dstat = run_cli("status")
            assert r_dstat.returncode == 0 and "RUNNING IN BACKGROUND" in r_dstat.stdout, r_dstat.stdout
            assert "0xD4E00009" in r_dstat.stdout

            d_pack = run_cli("pack", "0xA11CE001", "0xC0C00003", "DAEMON_IPC_TEST", "4")
            d_hex = extract_field(d_pack.stdout, "Raw Frame Hex")

            r_inj1 = run_cli("inject", d_hex)
            assert r_inj1.returncode == 0 and "[RELAY]" in r_inj1.stdout, r_inj1.stdout

            r_inj2 = run_cli("inject", d_hex)
            assert r_inj2.returncode == 0 and "[DROP_SEEN]" in r_inj2.stdout, r_inj2.stdout
        finally:
            r_stop = run_cli("stop")
            assert r_stop.returncode == 0

        r_after = run_cli("status")
        assert "STANDBY" in r_after.stdout

        # 10. Physical Hardware Inventory & 18.1-19.8 kHz Ultrasonic E2EE Roundtrip
        print("[TEST 10/11] Verifying phy-ports & 18.1-19.8 kHz Ultrasonic E2EE WAV roundtrip...")
        r_ports = run_cli("phy-ports")
        assert r_ports.returncode == 0 and "PHYSICAL TRANSPORT HARDWARE INVENTORY" in r_ports.stdout

        wav_path = os.path.join(state_dir, "ultrasonic_e2ee.wav")
        r_tx_sonic = run_cli("tx-acoustic", relayed_hex, "--wav", wav_path, "--no-speaker")
        assert r_tx_sonic.returncode == 0 and os.path.exists(wav_path), r_tx_sonic.stdout

        r_rx_sonic = run_cli(
            "rx-acoustic", "--wav", wav_path, charlie_id,
            "--sender-pk", alice_pk, "--local-sk", charlie_sk, "--stateless",
        )
        assert r_rx_sonic.returncode == 0 and "[DELIVER]" in r_rx_sonic.stdout, r_rx_sonic.stdout
        assert secret_text in r_rx_sonic.stdout

        # 11. Hermetic OS Boot Autostart Registration & Removal
        print("[TEST 11/11] Verifying install-autostart & uninstall-autostart lifecycle...")
        try:
            r_auto_on = run_cli("install-autostart", "--acoustic")
            assert r_auto_on.returncode == 0, r_auto_on.stdout
            r_st_on = run_cli("status")
            assert "Boot Autostart     : ENABLED" in r_st_on.stdout, r_st_on.stdout

            r_auto_off = run_cli("uninstall-autostart")
            assert r_auto_off.returncode == 0, r_auto_off.stdout
            r_st_off = run_cli("status")
            assert "Boot Autostart     : DISABLED" in r_st_off.stdout, r_st_off.stdout
        finally:
            if sys.platform == "win32":
                import winreg
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_reg_key)
                except OSError:
                    pass

        # 12. Persistent Bloom Anti-Poisoning on Forged E2EE Frame ([DROP_AUTH_FAIL])
        print("[TEST 12/13] Verifying forged E2EE frame does not poison persistent Bloom filter...")
        r_fresh_tx = run_cli(
            "pack", alice_id, charlie_id, "AUTHENTIC_AFTER_FORGERY", "5",
            "--peer-pk", charlie_pk, "--sender-sk", alice_sk,
        )
        assert r_fresh_tx.returncode == 0, r_fresh_tx.stdout
        fresh_hex = extract_field(r_fresh_tx.stdout, "Raw Frame Hex")
        raw_fresh = bytearray(bytes.fromhex(fresh_hex))
        raw_fresh[40] ^= 0x01  # Flip 1 ciphertext bit
        # Recompute CRC-16-CCITT over first 78 bytes so Link Gatekeeper passes
        crc = 0xFFFF
        for b in raw_fresh[:78]:
            crc ^= b
            for _ in range(8):
                crc = ((crc >> 1) ^ 0x8408) if (crc & 1) else (crc >> 1)
        raw_fresh[78:80] = crc.to_bytes(2, "little")
        forged_fresh_hex = raw_fresh.hex()

        r_forged_stateful = run_cli(
            "forward", forged_fresh_hex, charlie_id,
            "--sender-pk", alice_pk, "--local-sk", charlie_sk,
        )
        assert r_forged_stateful.returncode != 0 and "[DROP_AUTH_FAIL]" in r_forged_stateful.stdout

        # Now send the genuine frame stateful (without --stateless): must NOT be dropped as [DROP_SEEN]!
        r_genuine_stateful = run_cli(
            "forward", fresh_hex, charlie_id,
            "--sender-pk", alice_pk, "--local-sk", charlie_sk,
        )
        assert r_genuine_stateful.returncode == 0 and "[DELIVER]" in r_genuine_stateful.stdout, r_genuine_stateful.stdout
        assert "AUTHENTIC_AFTER_FORGERY" in r_genuine_stateful.stdout

        # 13. Serial Port Metacharacter / Command Injection / Path Traversal & tx-serial CRC16 Gate
        print("[TEST 13/13] Verifying --serial metacharacter, path traversal & tx-serial CRC16 rejection...")
        r_bad_serial1 = run_cli("install-autostart", "--serial", "COM3\nExecStartPre=/bin/sh")
        assert r_bad_serial1.returncode != 0 and "Invalid or unsafe --serial" in r_bad_serial1.stdout
        r_bad_serial2 = run_cli("start", "--serial", "COM3\" --bad")
        assert r_bad_serial2.returncode != 0 and "Invalid or unsafe --serial" in r_bad_serial2.stdout
        r_bad_serial3 = run_cli("tx-serial", "../etc/passwd", relayed_hex)
        assert r_bad_serial3.returncode != 0 and "Invalid or unsafe serial port" in r_bad_serial3.stdout
        r_bad_serial4 = run_cli("tx-serial", "-badflag", relayed_hex)
        assert r_bad_serial4.returncode != 0 and "Invalid or unsafe serial port" in r_bad_serial4.stdout
        r_bad_serial_crc = run_cli("tx-serial", "COM99", corrupt.hex())
        assert r_bad_serial_crc.returncode != 0 and "failed outer CRC-16" in r_bad_serial_crc.stdout
        r_bad_serial_opt = run_cli("tx-serial", "COM99", relayed_hex, "--unknown-flag")
        assert r_bad_serial_opt.returncode != 0 and "Unknown or incomplete tx-serial option" in r_bad_serial_opt.stdout

    print("\n======================================================================")
    print("  ALL 13/13 HARDENED MESH P2P, DAEMON, PHY & AUTOSTART TESTS PASSED!")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(test_mesh())
