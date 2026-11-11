#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  O.Z.O.S // MESH - EMPIRICAL MUTATION TESTING & FAULT INJECTION ENGINE
  Pillar 1 Conditioned Reflex (Mull-Inspired C99 & CLI Invariant Kill Gate)
=============================================================================

Injects synthetic security defects (mutants) into include/ozos_mesh.h and
src/main.c, recompiles the binaries, and verifies that the automated security
test suites IMMEDIATELY FAIL (Kill Score = 100%). Any surviving mutant proves
a false-positive ("Fake Pass") test gap and fails the build.
"""

import os
import sys
import subprocess

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HEADER_PATH = os.path.join(REPO_ROOT, "include", "ozos_mesh.h")
PHY_HEADER_PATH = os.path.join(REPO_ROOT, "include", "ozos_mesh_phy.h")
MAIN_C_PATH = os.path.join(REPO_ROOT, "src", "main.c")

IS_WIN = sys.platform == "win32"
BUILD_CMD = ["cmd", "/c", "build.bat"] if IS_WIN else ["make"]
C_TEST_BIN = os.path.join(REPO_ROOT, "test_security_hardening.exe" if IS_WIN else "test_security_hardening")
PY_TEST_CMD = [sys.executable, os.path.join(REPO_ROOT, "tests", "test_mesh_network.py")]

MUTANTS = [
    {
        "id": "MUT-01-BYPASS-CRC16-INTEGRITY",
        "description": "Force outer Link CRC-16 gatekeeper to accept corrupted frames",
        "file": HEADER_PATH,
        "target": "return (frame->tripwire_mac == ozos_mesh_calculate_mac(frame));",
        "replacement": "return true; /* MUTANT: BYPASS CRC16 */",
        "runner": PY_TEST_CMD,
    },
    {
        "id": "MUT-02-DISABLE-BLOOM-DUPLICATE-DROP",
        "description": "Disable SipHash-2-4 Bloom filter duplicate detection in router",
        "file": HEADER_PATH,
        "target": "if (bf && ozos_mesh_bloom_test(bf, frame->packet_id, frame->src_node_id)) {",
        "replacement": "if (false && bf && ozos_mesh_bloom_test(bf, frame->packet_id, frame->src_node_id)) {",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-03-DISABLE-BLOOM-EPOCH-ROTATION",
        "description": "Disable Dual-Generation Bloom rotation causing permanent blackhole DoS",
        "file": HEADER_PATH,
        "target": "if (bf->active_count >= OZOS_BLOOM_ROTATE_THRESHOLD) {",
        "replacement": "if (false && bf->active_count >= OZOS_BLOOM_ROTATE_THRESHOLD) {",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-04-DISABLE-X25519-LOW-ORDER-GUARD",
        "description": "Disable RFC 7748 constant-time all-zero shared secret rejection",
        "file": HEADER_PATH,
        "target": "if (crypto_verify_32(raw_dh, zero32) == 0) {",
        "replacement": "if (false && crypto_verify_32(raw_dh, zero32) == 0) {",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-05-STATIC-NONCE-REGRESSION",
        "description": "Force constant zero salt in Onion AEAD (reintroducing Two-Time Pad)",
        "file": HEADER_PATH,
        "target": "randombytes(salt, sizeof(salt));",
        "replacement": "memset(salt, 0x42, sizeof(salt)); /* MUTANT: STATIC SALT */",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-06-STRIP-HEADER-AAD-BINDING",
        "description": "Zero out src_node_id in 24-byte AAD nonce allowing source spoofing",
        "file": HEADER_PATH,
        "target": "ozos_le32_write(nonce + 8,  src_node_id);",
        "replacement": "ozos_le32_write(nonce + 8,  0U); /* MUTANT: UNBOUND SRC AAD */",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-07-DTN-CACHE-EXPIRED-ZOMBIE",
        "description": "Reintroduce premature DTN caching of expired TTL=1 frames",
        "file": HEADER_PATH,
        "target": "if (frame->hop_limit <= 1U || frame->hop_limit > OZOS_MESH_MAX_TTL) {\n        return OZOS_MESH_ACTION_DROP_EXPIRED;\n    }",
        "replacement": "if (frame->hop_limit <= 1U || frame->hop_limit > OZOS_MESH_MAX_TTL) {\n        if (cache) ozos_mesh_cache_push(cache, frame);\n        return OZOS_MESH_ACTION_DROP_EXPIRED;\n    }",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-08-TERMINAL-ESCAPE-PASSTHROUGH",
        "description": "Bypass printable ASCII sanitizer allowing raw ESC terminal injection",
        "file": MAIN_C_PATH,
        "target": "putchar((ch >= 0x20U && ch <= 0x7EU) ? (int)ch : '.');",
        "replacement": "putchar((int)ch); /* MUTANT: RAW ESCAPE LEAK */",
        "runner": PY_TEST_CMD,
    },
    {
        "id": "MUT-09-CORRUPT-SLIP84-STUFFING",
        "description": "Break RFC 1055 SLIP 0xC0 byte-stuffing on UART physical layer",
        "file": PHY_HEADER_PATH,
        "target": "out_slip[pos++] = OZOS_SLIP_ESC_END;",
        "replacement": "out_slip[pos++] = OZOS_SLIP_END; /* MUTANT: BROKEN SLIP ESCAPE */",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-10-INVERT-SONIC-BIT-POLARITY",
        "description": "Invert 18.1-19.8 kHz dual-rail Goertzel bit comparator",
        "file": PHY_HEADER_PATH,
        "target": "if (e1 > e0) {",
        "replacement": "if (e0 > e1) { /* MUTANT: INVERTED ULTRASONIC POLARITY */",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-11-PRE-BLOOM-TTL-POISON",
        "description": "Reintroduce pre-TTL SipHash Bloom filter insertion on expired packets",
        "file": HEADER_PATH,
        "target": "if (bf && ozos_mesh_bloom_test(bf, frame->packet_id, frame->src_node_id)) {\n        return OZOS_MESH_ACTION_DROP_SEEN;\n    }",
        "replacement": "if (bf && ozos_mesh_bloom_test(bf, frame->packet_id, frame->src_node_id)) {\n        return OZOS_MESH_ACTION_DROP_SEEN;\n    }\n    if (bf) { ozos_mesh_bloom_add(bf, frame->packet_id, frame->src_node_id); } /* MUTANT: PRE-TTL BLOOM POISON */",
        "runner": [C_TEST_BIN],
    },
    {
        "id": "MUT-12-WAV-DATA-CHUNK-BYPASS",
        "description": "Treat arbitrary non-PCM RIFF chunk ('JUNK') as audio 'data' chunk",
        "file": PHY_HEADER_PATH,
        "target": "} else if (memcmp(chdr, \"data\", 4U) == 0) {",
        "replacement": "} else if (1) { /* MUTANT: ACCEPT ANY RIFF CHUNK AS DATA */",
        "runner": [C_TEST_BIN],
    },
]


def resolve_build_env():
    env = os.environ.copy()
    if not IS_WIN:
        return env
    vcvars_candidates = [
        r"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    ]
    for vc in vcvars_candidates:
        if os.path.exists(vc):
            res = subprocess.run(
                f'"{vc}" >nul && set',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        env[k] = v
            break
    return env


BUILD_ENV = resolve_build_env()


def run_build():
    return subprocess.run(
        BUILD_CMD,
        cwd=REPO_ROOT,
        env=BUILD_ENV,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def main():
    print("======================================================================")
    print("  O.Z.O.S // MESH MULL-STYLE MUTATION TESTING ENGINE (12 MUTANTS)")
    print("======================================================================")

    # Baseline build & clean verification
    base_build = run_build()
    if base_build.returncode != 0:
        print(f"[FATAL] Baseline build failed:\n{base_build.stdout}\n{base_build.stderr}")
        return 1

    killed = 0
    survived = []

    for m in MUTANTS:
        fpath = m["file"]
        with open(fpath, "r", encoding="utf-8") as f:
            original = f.read()

        if m["target"] not in original:
            print(f"[ERROR] Target snippet not found for {m['id']} in {fpath}")
            return 1

        mutated = original.replace(m["target"], m["replacement"], 1)
        try:
            with open(fpath, "w", encoding="utf-8", newline="\n") as f:
                f.write(mutated)

            b_res = run_build()
            if b_res.returncode != 0:
                print(f"  [KILLED @ COMPILE] {m['id']}: {m['description']}")
                killed += 1
                continue

            t_res = subprocess.run(
                m["runner"],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if t_res.returncode != 0:
                print(f"  [KILLED @ RUNTIME] {m['id']}: {m['description']}")
                killed += 1
            else:
                print(f"  [SURVIVED - FAKE PASS!] {m['id']}: {m['description']}")
                survived.append(m["id"])
        finally:
            with open(fpath, "w", encoding="utf-8", newline="\n") as f:
                f.write(original)

    # Restore pristine baseline binaries
    restore_res = run_build()
    if restore_res.returncode != 0:
        print("[FATAL] Failed to restore baseline build after mutation run!")
        return 1

    total = len(MUTANTS)
    score = (killed * 100.0) / total
    print("----------------------------------------------------------------------")
    print(f"  MUTATION SCORE: {killed}/{total} KILLED ({score:.1f}%)")
    print("======================================================================")

    if survived:
        print(f"FAILED: Surviving mutants detected: {survived}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
