#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
O.Z.O.S Sovereign Mesh Multi-Node Topology Simulator
Simulates 10-node linear E2EE propagation and multi-hop broadcast across isolated state.
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


def run_simulation():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mesh_exe = resolve_mesh_bin(base_dir)

    print("======================================================================")
    print("  O.Z.O.S MULTI-NODE E2EE MESH TOPOLOGY SIMULATION (10-NODE GRAPH)")
    print("======================================================================")

    with tempfile.TemporaryDirectory(prefix="ozos_mesh_topo_") as state_dir:
        env = os.environ.copy()
        env["OZOS_MESH_STATE_DIR"] = state_dir

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

        kg_src = run_cli("keygen")
        kg_dst = run_cli("keygen")
        assert kg_src.returncode == 0 and kg_dst.returncode == 0

        src_node = extract_field(kg_src.stdout, "Node ID")
        src_pk = extract_field(kg_src.stdout, "Public Key")
        src_sk = extract_field(kg_src.stdout, "Secret Key")

        dst_node = extract_field(kg_dst.stdout, "Node ID")
        dst_pk = extract_field(kg_dst.stdout, "Public Key")
        dst_sk = extract_field(kg_dst.stdout, "Secret Key")

        relay_nodes = [f"0x{i:04X}1000" for i in range(2, 10)]
        ttl = len(relay_nodes) + 1

        print(f"Topology        : 10 Nodes (Source -> 8 Blind Relays -> Destination)")
        print(f"Source Node     : {src_node}")
        print(f"Destination Node: {dst_node}")
        print(f"Initial Hop TTL : {ttl} Hops")

        secret_msg = "MISSION_SOVEREIGN_MESH_10HOP"
        res = run_cli(
            "pack", src_node, dst_node, secret_msg, str(ttl),
            "--peer-pk", dst_pk, "--sender-sk", src_sk,
        )
        assert res.returncode == 0, f"pack failed: {res.stdout}"
        current_hex = extract_field(res.stdout, "Raw Frame Hex")
        assert current_hex is not None and len(current_hex) == 160

        print(f"\n[EMISSION] Node 1 ({src_node}) emitted 80-byte E2EE frame -> {current_hex[:32]}...")

        for idx, relay_node in enumerate(relay_nodes, start=1):
            res_relay = run_cli("forward", current_hex, relay_node)
            assert res_relay.returncode == 0
            assert "[RELAY]" in res_relay.stdout, f"Relay {idx} failed: {res_relay.stdout}"
            next_hex = extract_field(res_relay.stdout, "Relayed Hex")
            assert next_hex is not None and len(next_hex) == 160
            print(f"  -> Hop {idx}: Relay ({relay_node}) blindly forwarded ciphertext & resealed CRC16.")
            current_hex = next_hex

        res_dest = run_cli(
            "forward", current_hex, dst_node,
            "--sender-pk", src_pk, "--local-sk", dst_sk,
        )
        assert res_dest.returncode == 0
        assert "[DELIVER]" in res_dest.stdout
        assert secret_msg in res_dest.stdout
        print(f"\n[DESTINATION] Node 10 ({dst_node}) authenticated & decrypted payload: '{secret_msg}'")

        # Verify Multi-Hop Broadcast across 3 nodes
        res_bcast = run_cli("pack", src_node, "0xFFFFFFFF", "MESH_EMERGENCY_ALERT", "3")
        assert res_bcast.returncode == 0
        b_hex1 = extract_field(res_bcast.stdout, "Raw Frame Hex")

        b_hop1 = run_cli("forward", b_hex1, relay_nodes[0])
        assert "[DELIVER] + [RELAY]" in b_hop1.stdout
        b_hex2 = extract_field(b_hop1.stdout, "Relayed Hex")

        b_hop2 = run_cli("forward", b_hex2, relay_nodes[1])
        assert "[DELIVER] + [RELAY]" in b_hop2.stdout
        b_hex3 = extract_field(b_hop2.stdout, "Relayed Hex")

        b_hop3 = run_cli("forward", b_hex3, relay_nodes[2])
        assert "[DELIVER]" in b_hop3.stdout and "[RELAY]" not in b_hop3.stdout
        print("[BROADCAST] Multi-hop broadcast verified across 3 hops with exact TTL termination!")

    print("\n======================================================================")
    print("  TOPOLOGY SIMULATION PASSED: 10-NODE E2EE & BROADCAST 100% VERIFIED!")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(run_simulation())
