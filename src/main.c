/**
 * =============================================================================
 *   O.Z.O.S // SOVEREIGN MESH P2P DAEMON (ozos-mesh)
 *   Zero-IP Multi-Hop Physical Mesh Relay & Background Epidemic DTN Daemon
 *   Version: 1.3.0-MESH (Physical Transport, Autostart & Daemon Edition)
 *   Architecture: x86_64 / ARM64 / Embedded C99 (Zero-Heap Malloc=0)
 *   License: MIT | Copyright (c) 2026 LumenNull
 * =============================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <direct.h>
#define OZOS_MKDIR(p) _mkdir(p)
#define OZOS_PATH_SEP '\\'
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#define OZOS_MKDIR(p) mkdir((p), 0700)
#define OZOS_PATH_SEP '/'
#endif

#include "ozos_mesh.h"
#include "ozos_mesh_phy.h"

static ozos_sonic_mic_rx_t g_daemon_mic;
static int16_t g_sonic_pcm_buf[OZOS_SONIC_BURST_SAMPLES];
static int16_t g_sonic_wav_rx_buf[OZOS_SONIC_RX_RING_SAMPLES];

static volatile sig_atomic_t g_daemon_stop = 0;

static void handle_termination_signal(int sig) {
    (void)sig;
    g_daemon_stop = 1;
}

static void sleep_millis(uint32_t ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    (void)nanosleep(&ts, NULL);
#endif
}

static uint32_t current_pid_u32(void) {
#if defined(_WIN32)
    return (uint32_t)GetCurrentProcessId();
#else
    return (uint32_t)getpid();
#endif
}

static bool is_pid_alive(uint32_t pid) {
    if (pid == 0U) return false;
#if defined(_WIN32)
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    DWORD exit_code = 0;
    BOOL ok = GetExitCodeProcess(h, &exit_code);
    CloseHandle(h);
    return (ok && exit_code == STILL_ACTIVE);
#else
    if (kill((pid_t)pid, 0) == 0) return true;
    return (errno == EPERM);
#endif
}

static bool atomic_replace_file(const char* tmp_path, const char* dst_path) {
#if defined(_WIN32)
    return MoveFileExA(tmp_path, dst_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(tmp_path, dst_path) == 0;
#endif
}

/* =============================================================================
   1. HEX ENCODING, STRICT UNSIGNED PARSING & TERMINAL SANITIZATION
   ============================================================================= */

static void hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0U; i < len; ++i) {
        out[i * 2U]      = hex_chars[(in[i] >> 4) & 0x0FU];
        out[i * 2U + 1U] = hex_chars[in[i] & 0x0FU];
    }
    out[len * 2U] = '\0';
}

static bool hex_decode(const char* in, uint8_t* out, size_t out_len) {
    if (!in || !out) return false;
    size_t in_len = strlen(in);
    if (in_len != out_len * 2U) return false;

    for (size_t i = 0U; i < out_len; ++i) {
        char c1 = in[i * 2U];
        char c2 = in[i * 2U + 1U];
        uint8_t v1 = 0U, v2 = 0U;

        if (c1 >= '0' && c1 <= '9') v1 = (uint8_t)(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') v1 = (uint8_t)(c1 - 'a' + 10);
        else if (c1 >= 'A' && c1 <= 'F') v1 = (uint8_t)(c1 - 'A' + 10);
        else return false;

        if (c2 >= '0' && c2 <= '9') v2 = (uint8_t)(c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') v2 = (uint8_t)(c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F') v2 = (uint8_t)(c2 - 'A' + 10);
        else return false;

        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    return true;
}

static bool parse_hex_u32(const char* s, uint32_t* out_val, bool allow_broadcast) {
    if (!s || !out_val || s[0] == '\0') return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    size_t len = strlen(s);
    if (len == 0U || len > 8U) return false;

    uint32_t acc = 0U;
    for (size_t i = 0U; i < len; ++i) {
        char c = s[i];
        uint32_t digit = 0U;
        if (c >= '0' && c <= '9') digit = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uint32_t)(c - 'A' + 10);
        else return false;
        acc = (acc << 4) | digit;
    }

    if (acc == 0U) return false;
    if (acc == OZOS_MESH_BROADCAST_ID && !allow_broadcast) return false;

    *out_val = acc;
    return true;
}

static bool parse_ttl_u16(const char* s, uint16_t* out_ttl) {
    if (!s || !out_ttl || s[0] == '\0') return false;
    size_t len = strlen(s);
    if (len > 3U) return false;

    uint32_t acc = 0U;
    for (size_t i = 0U; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        acc = (acc * 10U) + (uint32_t)(s[i] - '0');
    }

    if (acc < 1U || acc > OZOS_MESH_MAX_TTL) return false;
    *out_ttl = (uint16_t)acc;
    return true;
}

static bool parse_u32_bounded(const char* s, uint32_t min_v, uint32_t max_v, uint32_t* out_v) {
    if (!s || !out_v || s[0] == '\0') return false;
    size_t len = strlen(s);
    if (len > 9U) return false;
    uint32_t acc = 0U;
    for (size_t i = 0U; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        acc = (acc * 10U) + (uint32_t)(s[i] - '0');
    }
    if (acc < min_v || acc > max_v) return false;
    *out_v = acc;
    return true;
}

static void print_sanitized_ascii(const uint8_t* buf, size_t max_len, bool stop_at_nul) {
    for (size_t i = 0U; i < max_len; ++i) {
        uint8_t ch = buf[i];
        if (stop_at_nul && ch == 0U) break;
        putchar((ch >= 0x20U && ch <= 0x7EU) ? (int)ch : '.');
    }
    putchar('\n');
}

/* =============================================================================
   2. ZERO-HEAP STATE DIRECTORY, PERSISTENT BLOOM & DAEMON TELEMETRY
   ============================================================================= */

#define OZOS_STATE_FILE_MAGIC     0x4F5A4246U /* "OZBF" */
#define OZOS_TELEMETRY_FILE_MAGIC 0x4F5A4433U /* "OZD3" */

typedef struct {
    uint32_t magic;
    uint32_t node_id;
    ozos_mesh_bloom_t bloom;
    uint8_t sha512_seal[64];
} ozos_persisted_bloom_t;

typedef struct {
    uint32_t magic;
    uint32_t pid;
    uint32_t node_id;
    uint32_t poll_ms;
    uint32_t serial_baud;
    uint8_t  serial_active;
    uint8_t  acoustic_rx_active;
    uint8_t  acoustic_relay_active;
    uint8_t  reserved_pad;
    uint64_t started_epoch;
    uint64_t heartbeat_epoch;
    uint64_t frames_received;
    uint64_t frames_relayed;
    uint64_t frames_delivered;
    uint64_t frames_dropped_seen;
    uint64_t frames_dropped_expired;
    uint64_t frames_dropped_invalid;
    uint32_t dtn_cache_depth;
    uint32_t bloom_epochs;
    uint8_t  node_pk[32];
    char     serial_port[64];
    char     last_action[96];
    uint8_t  sha512_seal[64];
} ozos_daemon_telemetry_t;

static bool resolve_state_dir(char out_dir[512]) {
    const char* env_dir = getenv("OZOS_MESH_STATE_DIR");
    if (env_dir && env_dir[0] != '\0') {
        size_t n = strlen(env_dir);
        if (n >= 460U) return false;
        memcpy(out_dir, env_dir, n + 1U);
        (void)OZOS_MKDIR(out_dir);
        return true;
    }

#if defined(_WIN32)
    const char* home = getenv("USERPROFILE");
    if (!home || home[0] == '\0') home = getenv("TEMP");
#else
    const char* home = getenv("HOME");
    if (!home || home[0] == '\0') home = "/tmp";
#endif
    if (!home || home[0] == '\0') home = ".";

    char ozos_root[480];
    int w1 = snprintf(ozos_root, sizeof(ozos_root), "%s%c.ozos", home, OZOS_PATH_SEP);
    if (w1 <= 0 || (size_t)w1 >= sizeof(ozos_root)) return false;
    (void)OZOS_MKDIR(ozos_root);

    int w2 = snprintf(out_dir, 512U, "%s%cmesh", ozos_root, OZOS_PATH_SEP);
    if (w2 <= 0 || (size_t)w2 >= 480U) return false;
    (void)OZOS_MKDIR(out_dir);
    return true;
}

static bool build_state_file_path(const char* filename, char out_path[576]) {
    char dir[512];
    if (!resolve_state_dir(dir)) return false;
    int written = snprintf(out_path, 576U, "%s%c%s", dir, OZOS_PATH_SEP, filename);
    return (written > 0 && (size_t)written < 576U);
}

static bool build_node_state_path(uint32_t local_id, char out_path[576]) {
    char fname[48];
    (void)snprintf(fname, sizeof(fname), "node_%08X.bf", local_id);
    return build_state_file_path(fname, out_path);
}

static void load_or_init_node_bloom(uint32_t local_id, ozos_mesh_bloom_t* bf) {
    char path[576];
    if (!build_node_state_path(local_id, path)) {
        ozos_mesh_bloom_init(bf);
        return;
    }

    FILE* fp = fopen(path, "rb");
    if (!fp) {
        ozos_mesh_bloom_init(bf);
        return;
    }

    ozos_persisted_bloom_t rec;
    size_t rd = fread(&rec, 1U, sizeof(rec), fp);
    fclose(fp);

    if (rd != sizeof(rec) || rec.magic != OZOS_STATE_FILE_MAGIC || rec.node_id != local_id) {
        ozos_mesh_zeroize(&rec, sizeof(rec));
        ozos_mesh_bloom_init(bf);
        return;
    }

    uint8_t digest[64];
    crypto_hash(digest, (const uint8_t*)&rec, sizeof(rec) - 64U);
    bool valid = (crypto_verify_32(digest, rec.sha512_seal) == 0) &&
                 (crypto_verify_32(digest + 32, rec.sha512_seal + 32) == 0);
    ozos_mesh_zeroize(digest, sizeof(digest));

    if (!valid || rec.bloom.active_idx > 1U || rec.bloom.active_count > OZOS_BLOOM_ROTATE_THRESHOLD) {
        ozos_mesh_zeroize(&rec, sizeof(rec));
        ozos_mesh_bloom_init(bf);
        return;
    }

    *bf = rec.bloom;
    ozos_mesh_zeroize(&rec, sizeof(rec));
}

static void save_node_bloom(uint32_t local_id, const ozos_mesh_bloom_t* bf) {
    char path[576];
    char tmp_path[576];
    char tmp_name[48];
    if (!build_node_state_path(local_id, path)) return;
    (void)snprintf(tmp_name, sizeof(tmp_name), "node_%08X.tmp", local_id);
    if (!build_state_file_path(tmp_name, tmp_path)) return;

    ozos_persisted_bloom_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.magic = OZOS_STATE_FILE_MAGIC;
    rec.node_id = local_id;
    rec.bloom = *bf;
    crypto_hash(rec.sha512_seal, (const uint8_t*)&rec, sizeof(rec) - 64U);

    FILE* fp = fopen(tmp_path, "wb");
    if (fp) {
        size_t wr = fwrite(&rec, 1U, sizeof(rec), fp);
        fclose(fp);
        if (wr == sizeof(rec)) {
            (void)atomic_replace_file(tmp_path, path);
        } else {
            (void)remove(tmp_path);
        }
    }
    ozos_mesh_zeroize(&rec, sizeof(rec));
}

static bool write_daemon_telemetry(const ozos_daemon_telemetry_t* src) {
    char final_path[576];
    char tmp_path[576];
    if (!build_state_file_path("daemon_telemetry.bin", final_path)) return false;
    if (!build_state_file_path("daemon_telemetry.tmp", tmp_path)) return false;

    ozos_daemon_telemetry_t copy = *src;
    copy.magic = OZOS_TELEMETRY_FILE_MAGIC;
    crypto_hash(copy.sha512_seal, (const uint8_t*)&copy, sizeof(copy) - 64U);

    FILE* fp = fopen(tmp_path, "wb");
    if (!fp) return false;
    size_t wr = fwrite(&copy, 1U, sizeof(copy), fp);
    fclose(fp);
    if (wr != sizeof(copy)) {
        (void)remove(tmp_path);
        return false;
    }
    return atomic_replace_file(tmp_path, final_path);
}

static bool read_live_daemon_telemetry(ozos_daemon_telemetry_t* out_tel) {
    char final_path[576];
    if (!build_state_file_path("daemon_telemetry.bin", final_path)) return false;

    FILE* fp = fopen(final_path, "rb");
    if (!fp) return false;
    ozos_daemon_telemetry_t rec;
    size_t rd = fread(&rec, 1U, sizeof(rec), fp);
    fclose(fp);
    if (rd != sizeof(rec) || rec.magic != OZOS_TELEMETRY_FILE_MAGIC) return false;

    uint8_t digest[64];
    crypto_hash(digest, (const uint8_t*)&rec, sizeof(rec) - 64U);
    bool valid = (crypto_verify_32(digest, rec.sha512_seal) == 0) &&
                 (crypto_verify_32(digest + 32, rec.sha512_seal + 32) == 0);
    ozos_mesh_zeroize(digest, sizeof(digest));
    if (!valid) return false;

    if (!is_pid_alive(rec.pid)) return false;

    *out_tel = rec;
    return true;
}

/* =============================================================================
   2B. OS BOOT AUTOSTART REGISTRATION (Win32 HKCU Run / POSIX systemd --user)
   ============================================================================= */

static void resolve_autostart_target(char out_key_or_path[512]) {
#if defined(_WIN32)
    const char* custom_key = getenv("OZOS_MESH_AUTOSTART_REGKEY");
    if (custom_key && custom_key[0] != '\0') {
        (void)snprintf(out_key_or_path, 512U, "%s", custom_key);
    } else {
        (void)snprintf(out_key_or_path, 512U, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    }
#else
    const char* env_dir = getenv("OZOS_MESH_STATE_DIR");
    if (env_dir && env_dir[0] != '\0') {
        (void)snprintf(out_key_or_path, 512U, "%.480s/ozos-mesh.service", env_dir);
    } else {
        const char* home = getenv("HOME");
        if (!home || home[0] == '\0') home = "/tmp";
        char cfg[400];
        (void)snprintf(cfg, sizeof(cfg), "%.350s/.config", home);
        (void)OZOS_MKDIR(cfg);
        (void)snprintf(cfg, sizeof(cfg), "%.350s/.config/systemd", home);
        (void)OZOS_MKDIR(cfg);
        (void)snprintf(cfg, sizeof(cfg), "%.350s/.config/systemd/user", home);
        (void)OZOS_MKDIR(cfg);
        (void)snprintf(out_key_or_path, 512U, "%.440s/.config/systemd/user/ozos-mesh.service", home);
    }
#endif
}

static bool query_autostart_enabled(char out_cmd[512]) {
    char target[512];
    resolve_autostart_target(target);
    if (out_cmd) out_cmd[0] = '\0';
#if defined(_WIN32)
    HKEY h_key = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, target, 0, KEY_READ, &h_key) != ERROR_SUCCESS) {
        return false;
    }
    BYTE buf[512];
    DWORD buf_len = sizeof(buf) - 1U;
    DWORD val_type = 0;
    LONG rc = RegQueryValueExA(h_key, "OZOS-Mesh", NULL, &val_type, buf, &buf_len);
    RegCloseKey(h_key);
    if (rc != ERROR_SUCCESS || val_type != REG_SZ) {
        return false;
    }
    buf[buf_len] = '\0';
    if (out_cmd) {
        (void)snprintf(out_cmd, 512U, "%s", (const char*)buf);
    }
    return true;
#else
    FILE* fp = fopen(target, "rb");
    if (!fp) return false;
    fclose(fp);
    if (out_cmd) {
        (void)snprintf(out_cmd, 512U, "%s", target);
    }
    return true;
#endif
}

static bool is_safe_serial_port_arg(const char* s) {
    if (!s || s[0] == '\0' || s[0] == '-') return false;
    if (strstr(s, "..") != NULL) return false;
    size_t len = strlen(s);
    if (len == 0U || len > 60U) return false;
    for (size_t i = 0U; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        bool ok = ((c >= 'A' && c <= 'Z') ||
                   (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') ||
                   c == '_' || c == '-' || c == '.' || c == '/' || c == '\\' || c == ':');
        if (!ok) return false;
    }
    return true;
}

static int cmd_install_autostart(int argc, char* argv[]) {
    char extra_opts[256];
    extra_opts[0] = '\0';
    size_t pos = 0U;
    int i = 2;
    while (i < argc) {
        if (strcmp(argv[i], "--node-id") == 0 && (i + 1) < argc) {
            uint32_t tmp_id = 0U;
            if (!parse_hex_u32(argv[i + 1], &tmp_id, false)) {
                printf("Error: Invalid --node-id '%s'.\n", argv[i + 1]);
                return 1;
            }
            int w = snprintf(extra_opts + pos, sizeof(extra_opts) - pos, " --node-id 0x%08X", tmp_id);
            if (w > 0 && pos + (size_t)w < sizeof(extra_opts)) pos += (size_t)w;
            i += 2;
        } else if (strcmp(argv[i], "--serial") == 0 && (i + 1) < argc) {
            if (!is_safe_serial_port_arg(argv[i + 1])) {
                printf("Error: Invalid or unsafe --serial port '%s'.\n", argv[i + 1]);
                return 1;
            }
            int w = snprintf(extra_opts + pos, sizeof(extra_opts) - pos, " --serial %s", argv[i + 1]);
            if (w > 0 && pos + (size_t)w < sizeof(extra_opts)) pos += (size_t)w;
            i += 2;
        } else if (strcmp(argv[i], "--baud") == 0 && (i + 1) < argc) {
            uint32_t tmp_baud = 0U;
            if (!parse_u32_bounded(argv[i + 1], 1200U, 2000000U, &tmp_baud)) {
                printf("Error: Invalid --baud '%s'.\n", argv[i + 1]);
                return 1;
            }
            int w = snprintf(extra_opts + pos, sizeof(extra_opts) - pos, " --baud %u", tmp_baud);
            if (w > 0 && pos + (size_t)w < sizeof(extra_opts)) pos += (size_t)w;
            i += 2;
        } else if (strcmp(argv[i], "--acoustic") == 0 || strcmp(argv[i], "--acoustic-relay") == 0) {
            int w = snprintf(extra_opts + pos, sizeof(extra_opts) - pos, " %s", argv[i]);
            if (w > 0 && pos + (size_t)w < sizeof(extra_opts)) pos += (size_t)w;
            i += 1;
        } else {
            printf("Error: Unknown or unsafe autostart option '%s'.\n", argv[i]);
            return 1;
        }
    }

    char target[512];
    resolve_autostart_target(target);

#if defined(_WIN32)
    char exe_path[512];
    DWORD n = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    if (n == 0 || n >= sizeof(exe_path)) {
        printf("Error: Unable to resolve executable path.\n");
        return 1;
    }
    char reg_val[768];
    (void)snprintf(reg_val, sizeof(reg_val), "\"%s\" start%s", exe_path, extra_opts);

    HKEY h_key = NULL;
    DWORD disp = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, target, 0, NULL, 0, KEY_SET_VALUE, NULL, &h_key, &disp) != ERROR_SUCCESS) {
        printf("Error: Failed to open HKCU\\%s.\n", target);
        return 1;
    }
    LONG rc = RegSetValueExA(h_key, "OZOS-Mesh", 0, REG_SZ, (const BYTE*)reg_val, (DWORD)(strlen(reg_val) + 1U));
    RegCloseKey(h_key);
    if (rc != ERROR_SUCCESS) {
        printf("Error: Failed to write OZOS-Mesh autostart registry value.\n");
        return 1;
    }
    printf("=================================================================\n");
    printf("  O.Z.O.S // BOOT AUTOSTART ENABLED\n");
    printf("=================================================================\n");
    printf("* Registry Key : HKCU\\%s\\OZOS-Mesh\n", target);
    printf("* Boot Command : %s\n", reg_val);
    printf("=================================================================\n");
    return 0;
#else
    char exe_buf[480];
    ssize_t rl = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1U);
    if (rl > 0) {
        exe_buf[rl] = '\0';
    } else {
        (void)snprintf(exe_buf, sizeof(exe_buf), "%.470s", argv[0]);
    }
    FILE* fp = fopen(target, "wb");
    if (!fp) {
        printf("Error: Failed to write systemd unit '%s'.\n", target);
        return 1;
    }
    fprintf(fp,
        "[Unit]\n"
        "Description=O.Z.O.S Sovereign Zero-IP Mesh P2P Daemon\n"
        "After=default.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s daemon%s\n"
        "Restart=on-failure\n\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        exe_buf, extra_opts);
    fclose(fp);
    printf("=================================================================\n");
    printf("  O.Z.O.S // BOOT AUTOSTART UNIT INSTALLED\n");
    printf("=================================================================\n");
    printf("* Systemd Unit : %s\n", target);
    printf("=================================================================\n");
    return 0;
#endif
}

static int cmd_uninstall_autostart(void) {
    char target[512];
    resolve_autostart_target(target);
#if defined(_WIN32)
    HKEY h_key = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, target, 0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS) {
        (void)RegDeleteValueA(h_key, "OZOS-Mesh");
        RegCloseKey(h_key);
    }
#else
    (void)remove(target);
#endif
    printf("Removed O.Z.O.S Mesh boot autostart registration.\n");
    return 0;
}

/* =============================================================================
   3. CLI & BACKGROUND DAEMON COMMAND IMPLEMENTATIONS
   ============================================================================= */

static void print_usage(void) {
    printf("=================================================================\n");
    printf("  O.Z.O.S // SOVEREIGN MESH P2P NODE (ozos-mesh v1.3.0-MESH)\n");
    printf("  Zero-IP Physical Mesh Router, Ultrasonic & LoRa UART Daemon\n");
    printf("  Leg 2 of the Sovereign Triad Protocol Suite\n");
    printf("=================================================================\n\n");
    printf("Available Operational Commands:\n");
    printf("  ozos-mesh start [--node-id <hex>] [--serial <COMx>] [--baud <N>] [--acoustic]\n");
    printf("                                                   - Launch silent background Mesh daemon\n");
    printf("  ozos-mesh stop                                   - Gracefully stop background Mesh daemon\n");
    printf("  ozos-mesh status                                 - Live background daemon & PHY telemetry\n");
    printf("  ozos-mesh inject <frame_hex>                     - Dispatch 80B frame into live daemon\n");
    printf("  ozos-mesh phy-ports                              - Enumerate live UART/LoRa & ultrasonic I/O\n");
    printf("  ozos-mesh tx-acoustic <frame_hex> [--wav <file>] [--no-speaker]\n");
    printf("                                                   - Transmit 18.1-19.8 kHz ultrasonic burst\n");
    printf("  ozos-mesh rx-acoustic --wav <file> <local_id> [--sender-pk <hex> --local-sk <hex>] [--stateless]\n");
    printf("                                                   - Demodulate 18.1-19.8 kHz ultrasonic WAV\n");
    printf("  ozos-mesh tx-serial <port> <frame_hex> [--baud <N>]\n");
    printf("                                                   - Transmit SLIP-84 frame over COM/UART\n");
    printf("  ozos-mesh install-autostart [--acoustic] [--serial <port>]\n");
    printf("                                                   - Register OS boot background autostart\n");
    printf("  ozos-mesh uninstall-autostart                    - Remove OS boot background autostart\n");
    printf("  ozos-mesh keygen                                 - Generate X25519 keypair & Node ID\n");
    printf("  ozos-mesh pack <src_id> <dst_id> <msg> [ttl] [--peer-pk <hex> --sender-sk <hex>]\n");
    printf("  ozos-mesh forward <frame_hex> <local_id> [--sender-pk <hex> --local-sk <hex>] [--stateless]\n");
    printf("  ozos-mesh reset-state <local_id>                 - Purge persisted Bloom state for a node\n");
    printf("  ozos-mesh sim-multihop                           - Execute 3-Node E2EE Multi-Hop Benchmark\n");
    printf("  ozos-mesh version                                - Print protocol & wire specifications\n");
    printf("=================================================================\n");
}

static int cmd_version(void) {
    printf("=================================================================\n");
    printf("  O.Z.O.S // SOVEREIGN MESH P2P SPECIFICATION (v1.3.0-MESH)\n");
    printf("=================================================================\n");
    printf("* Protocol Name     : OZOS-Mesh Sovereign P2P Router\n");
    printf("* Wire Format       : Canonical OZOS-80 (Exactly 80 Bytes / 640 Bits, Little-Endian)\n");
    printf("* Alignment Parity  : Bitcoin Block Header Invariant\n");
    printf("* Memory Model      : Zero Heap Malloc (malloc = 0), Volatile Stack Zeroization\n");
    printf("* Anti-Storm Engine : Dual-Generation 2x4096-bit SipHash-2-4 Rotating Bloom Filter\n");
    printf("* Cache Architecture: Store-and-Forward DTN Ring Queue (Depth: 16 Post-TTL Frames)\n");
    printf("* Link Checksum     : Outer 16-bit CRC-16 Pre-Filter + Inner Poly1305 Header AAD\n");
    printf("* Confidentiality   : X25519 ECDH + XSalsa20-Poly1305 AEAD (RFC 7748 Hardened)\n");
    printf("* Physical Carriers : SLIP-84 UART/LoRa + 18.1-19.8 kHz Dual-Rail Ultrasonic Modem\n");
    printf("* Compliance        : MISRA C99 / High-Assurance Bare-Metal Ready\n");
    printf("=================================================================\n");
    return 0;
}

static int cmd_status(void) {
    ozos_daemon_telemetry_t tel;
    bool daemon_live = read_live_daemon_telemetry(&tel);
    char autostart_cmd[512];
    bool autostart_on = query_autostart_enabled(autostart_cmd);

    printf("=================================================================\n");
    printf("  O.Z.O.S // SOVEREIGN MESH ROUTER STATUS\n");
    printf("  Protocol: OZOS-80 Mesh Invariant | Addressing: Cryptographic Node ID\n");
    printf("=================================================================\n\n");

    printf("[1] BACKGROUND DAEMON RUNTIME:\n");
    if (daemon_live) {
        uint64_t now_s = (uint64_t)time(NULL);
        uint64_t uptime = (now_s >= tel.started_epoch) ? (now_s - tel.started_epoch) : 0ULL;
        char pk_hex[65];
        hex_encode(tel.node_pk, 32U, pk_hex);
        printf("  * Daemon State       : RUNNING IN BACKGROUND (Headless Zero-Heap)\n");
        printf("  * OS Process PID     : %u\n", tel.pid);
        printf("  * Sovereign Node ID  : 0x%08X\n", tel.node_id);
        printf("  * Node X25519 PubKey : %.32s...\n", pk_hex);
        printf("  * Uptime / Poll Rate : %llu sec (Poll: %u ms)\n",
               (unsigned long long)uptime, tel.poll_ms);
        printf("  * Physical Carriers  : IPC=ACTIVE | UART=%s | Ultrasonic-RX=%s\n",
               tel.serial_active ? tel.serial_port : "STANDBY",
               tel.acoustic_rx_active ? "ACTIVE (18.1-19.8 kHz)" : "STANDBY");
        printf("  * Boot Autostart     : %s\n", autostart_on ? "ENABLED" : "DISABLED");
        printf("  * Traffic Counters   : RX=%llu | RELAY=%llu | DELIVER=%llu\n",
               (unsigned long long)tel.frames_received,
               (unsigned long long)tel.frames_relayed,
               (unsigned long long)tel.frames_delivered);
        printf("  * Shield Drops       : DUP=%llu | EXPIRED=%llu | INVALID=%llu\n",
               (unsigned long long)tel.frames_dropped_seen,
               (unsigned long long)tel.frames_dropped_expired,
               (unsigned long long)tel.frames_dropped_invalid);
        printf("  * Live Memory State  : DTN Ring=%u/%u | Bloom Epochs=%u\n",
               tel.dtn_cache_depth, OZOS_CACHE_CAPACITY, tel.bloom_epochs);
        printf("  * Last Event         : %s\n\n", tel.last_action);
    } else {
        printf("  * Daemon State       : STANDBY (CLI Mode - run 'ozos-mesh start' for background)\n");
        printf("  * Boot Autostart     : %s\n\n", autostart_on ? "ENABLED" : "DISABLED");
    }

    printf("[2] ROUTING & TOPOLOGY INVARIANTS:\n");
    printf("  * Network Addressing : Zero-IP / 32-bit Cryptographic Public Key ID\n");
    printf("  * Wire Format        : Exactly 80 Bytes (OZOS-80 Aligned)\n");
    printf("  * Hop Limit Bounds   : Default %u / Max %u Hops (Anti-Zombie Ceiling)\n",
           OZOS_MESH_DEFAULT_TTL, OZOS_MESH_MAX_TTL);
    printf("  * Anti-Storm Shield  : Dual-Gen 2x%u-bit Keyed SipHash-2-4 Rotating Bloom\n",
           OZOS_BLOOM_BANK_BITS);
    printf("  * Ring Buffer Depth  : %u Ephemeral Frames (Zero-Heap Malloc=0)\n\n",
           OZOS_CACHE_CAPACITY);

    printf("[STATUS] Sovereign Mesh Engine: %s\n",
           daemon_live ? "DAEMON ACTIVE & LISTENING IN BACKGROUND" : "ACTIVE & LISTENING");
    printf("=================================================================\n");
    return 0;
}

static void load_or_create_daemon_identity(uint32_t override_id, uint32_t* out_id, uint8_t out_pk[32]) {
    char id_path[576];
    if (build_state_file_path("daemon_identity.pub", id_path)) {
        FILE* fp = fopen(id_path, "rb");
        if (fp) {
            uint8_t buf[100];
            size_t rd = fread(buf, 1U, sizeof(buf), fp);
            fclose(fp);
            if (rd == sizeof(buf)) {
                uint8_t digest[64];
                crypto_hash(digest, buf, 36U);
                bool seal_ok = (crypto_verify_32(digest, buf + 36) == 0) &&
                               (crypto_verify_32(digest + 32, buf + 68) == 0);
                ozos_mesh_zeroize(digest, sizeof(digest));
                if (seal_ok) {
                    uint32_t saved_id = ozos_le32_read(buf);
                    memcpy(out_pk, buf + 4, 32U);
                    if (saved_id != 0U && saved_id != OZOS_MESH_BROADCAST_ID) {
                        *out_id = (override_id != 0U) ? override_id : saved_id;
                        return;
                    }
                }
            }
        }
    }

    uint8_t ephemeral_sk[32];
    ozos_mesh_keygen(out_pk, ephemeral_sk);
    ozos_mesh_zeroize(ephemeral_sk, sizeof(ephemeral_sk));

    uint32_t derived = ozos_mesh_node_id_from_pk(out_pk);
    *out_id = (override_id != 0U) ? override_id : derived;

    if (build_state_file_path("daemon_identity.pub", id_path)) {
        uint8_t buf[100];
        ozos_le32_write(buf, *out_id);
        memcpy(buf + 4, out_pk, 32U);
        crypto_hash(buf + 36, buf, 36U);
        FILE* fp = fopen(id_path, "wb");
        if (fp) {
            if (fwrite(buf, 1U, sizeof(buf), fp) != sizeof(buf)) {
                fclose(fp);
                (void)remove(id_path);
                return;
            }
            fclose(fp);
        }
    }
}

static void daemon_dispatch_wire_frame(
    const uint8_t wire_in[OZOS_MESH_FRAME_SIZE],
    const char* ingress_tag,
    uint32_t local_id,
    ozos_mesh_bloom_t* bf,
    ozos_mesh_cache_t* cache,
    ozos_daemon_telemetry_t* tel,
    const char* tx_path,
    ozos_serial_port_t* sp,
    bool acoustic_relay
) {
    ozos_mesh_frame_t frame;
    ozos_mesh_frame_decode(wire_in, &frame);
    ozos_mesh_action_t act = ozos_mesh_process_frame(&frame, local_id, bf, cache);

    if (act == OZOS_MESH_ACTION_DELIVER) {
        tel->frames_delivered++;
        (void)snprintf(tel->last_action, sizeof(tel->last_action),
                       "[DELIVER] (%s) From 0x%08X Seq 0x%08X",
                       ingress_tag, frame.src_node_id, frame.packet_id);
    } else if (act == OZOS_MESH_ACTION_DELIVER_AND_RELAY || act == OZOS_MESH_ACTION_RELAY) {
        if (act == OZOS_MESH_ACTION_DELIVER_AND_RELAY) {
            tel->frames_delivered++;
        }
        tel->frames_relayed++;

        uint8_t wire_out[OZOS_MESH_FRAME_SIZE];
        char out_hex[161];
        ozos_mesh_frame_encode(&frame, wire_out);
        hex_encode(wire_out, sizeof(wire_out), out_hex);

        FILE* f_tx = fopen(tx_path, "wb");
        if (f_tx) {
            if (fwrite(out_hex, 1U, 160U, f_tx) != 160U) {
                fclose(f_tx);
            } else {
                fclose(f_tx);
            }
        }
        if (sp && sp->is_open) {
            (void)ozos_serial_send_frame(sp, wire_out);
        }
        if (acoustic_relay) {
            ozos_sonic_modulate_frame(wire_out, g_sonic_pcm_buf);
            (void)ozos_sonic_play_hardware(g_sonic_pcm_buf, OZOS_SONIC_BURST_SAMPLES);
        }

        if (act == OZOS_MESH_ACTION_DELIVER_AND_RELAY) {
            (void)snprintf(tel->last_action, sizeof(tel->last_action),
                           "[DELIVER+RELAY] (%s) Broadcast Seq 0x%08X (TTL->%u)",
                           ingress_tag, frame.packet_id, frame.hop_limit);
        } else {
            (void)snprintf(tel->last_action, sizeof(tel->last_action),
                           "[RELAY] (%s) 0x%08X->0x%08X (TTL->%u)",
                           ingress_tag, frame.src_node_id, frame.dst_node_id, frame.hop_limit);
        }
    } else if (act == OZOS_MESH_ACTION_DROP_SEEN) {
        tel->frames_dropped_seen++;
        (void)snprintf(tel->last_action, sizeof(tel->last_action),
                       "[DROP_SEEN] (%s) Suppressed duplicate Seq 0x%08X",
                       ingress_tag, frame.packet_id);
    } else if (act == OZOS_MESH_ACTION_DROP_EXPIRED) {
        tel->frames_dropped_expired++;
        (void)snprintf(tel->last_action, sizeof(tel->last_action),
                       "[DROP_EXPIRED] (%s) Purged zombie Seq 0x%08X",
                       ingress_tag, frame.packet_id);
    } else {
        tel->frames_dropped_invalid++;
        (void)snprintf(tel->last_action, sizeof(tel->last_action),
                       "[DROP_INVALID] (%s) Corrupted Link CRC16 / Header", ingress_tag);
    }
    save_node_bloom(local_id, bf);
}

static int cmd_daemon(int argc, char* argv[]) {
    uint32_t override_id = 0U;
    uint32_t poll_ms = 100U;
    const char* opt_serial = NULL;
    uint32_t opt_baud = 115200U;
    bool opt_acoustic = false;
    bool opt_acoustic_relay = false;

    int i = 2;
    while (i < argc) {
        if (strcmp(argv[i], "--node-id") == 0 && (i + 1) < argc) {
            if (!parse_hex_u32(argv[i + 1], &override_id, false)) {
                fprintf(stderr, "Error: Invalid --node-id '%s'.\n", argv[i + 1]);
                return 1;
            }
            i += 2;
        } else if (strcmp(argv[i], "--poll-ms") == 0 && (i + 1) < argc) {
            if (!parse_u32_bounded(argv[i + 1], 20U, 5000U, &poll_ms)) {
                fprintf(stderr, "Error: Invalid --poll-ms '%s' (20..5000).\n", argv[i + 1]);
                return 1;
            }
            i += 2;
        } else if (strcmp(argv[i], "--serial") == 0 && (i + 1) < argc) {
            if (!is_safe_serial_port_arg(argv[i + 1])) {
                fprintf(stderr, "Error: Invalid or unsafe --serial port '%s'.\n", argv[i + 1]);
                return 1;
            }
            opt_serial = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "--baud") == 0 && (i + 1) < argc) {
            if (!parse_u32_bounded(argv[i + 1], 1200U, 2000000U, &opt_baud)) {
                fprintf(stderr, "Error: Invalid --baud '%s'.\n", argv[i + 1]);
                return 1;
            }
            i += 2;
        } else if (strcmp(argv[i], "--acoustic") == 0) {
            opt_acoustic = true;
            i += 1;
        } else if (strcmp(argv[i], "--acoustic-relay") == 0) {
            opt_acoustic = true;
            opt_acoustic_relay = true;
            i += 1;
        } else {
            fprintf(stderr, "Error: Unknown daemon option '%s'.\n", argv[i]);
            return 1;
        }
    }

    char state_dir_raw[512];
    if (!resolve_state_dir(state_dir_raw)) {
        fprintf(stderr, "Error: Failed to resolve ~/.ozos/mesh state directory.\n");
        return 1;
    }

#if defined(_WIN32)
    uint64_t fnv = 1469598103934665603ULL;
    for (const char* p = state_dir_raw; *p != '\0'; ++p) {
        unsigned char ch = (unsigned char)*p;
        if (ch >= 'A' && ch <= 'Z') ch = (unsigned char)(ch + ('a' - 'A'));
        if (ch == '/') ch = '\\';
        fnv ^= (uint64_t)ch;
        fnv *= 1099511628211ULL;
    }
    char mutex_name[96];
    (void)snprintf(mutex_name, sizeof(mutex_name), "Local\\OZOS_Mesh_Daemon_%08X%08X",
                   (unsigned int)(fnv >> 32U), (unsigned int)(fnv & 0xFFFFFFFFULL));
    HANDLE h_daemon_mutex = CreateMutexA(NULL, FALSE, mutex_name);
    if (h_daemon_mutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(h_daemon_mutex);
        return 0;
    }
#endif

    ozos_daemon_telemetry_t existing;
    if (read_live_daemon_telemetry(&existing) && existing.pid != current_pid_u32()) {
        fprintf(stderr, "Daemon already running (PID %u, Node 0x%08X).\n", existing.pid, existing.node_id);
#if defined(_WIN32)
        if (h_daemon_mutex != NULL) CloseHandle(h_daemon_mutex);
#endif
        return 0;
    }

    char stop_path[576];
    char rx_path[576];
    char tx_path[576];
    char ack_path[576];
    char ack_tmp[576];
    if (!build_state_file_path("daemon.stop", stop_path) ||
        !build_state_file_path("rx_frame.hex", rx_path) ||
        !build_state_file_path("tx_relay.hex", tx_path) ||
        !build_state_file_path("last_dispatch.txt", ack_path) ||
        !build_state_file_path("last_dispatch.tmp", ack_tmp)) {
        fprintf(stderr, "Error: Failed to initialize ~/.ozos/mesh state paths.\n");
#if defined(_WIN32)
        if (h_daemon_mutex != NULL) CloseHandle(h_daemon_mutex);
#endif
        return 1;
    }
    (void)remove(stop_path);

#if !defined(_WIN32)
    (void)umask(0077);
#endif
    signal(SIGINT, handle_termination_signal);
    signal(SIGTERM, handle_termination_signal);

    uint32_t local_id = 0U;
    uint8_t node_pk[32];
    load_or_create_daemon_identity(override_id, &local_id, node_pk);

    ozos_mesh_bloom_t bf;
    ozos_mesh_cache_t cache;
    load_or_init_node_bloom(local_id, &bf);
    ozos_mesh_cache_init(&cache);

    ozos_serial_port_t serial_dev;
    ozos_serial_init(&serial_dev);
    if (opt_serial != NULL) {
        (void)ozos_serial_open(&serial_dev, opt_serial, opt_baud);
    }

    bool mic_active = false;
    if (opt_acoustic) {
        mic_active = ozos_sonic_mic_open(&g_daemon_mic);
    }

    ozos_daemon_telemetry_t tel;
    memset(&tel, 0, sizeof(tel));
    tel.pid = current_pid_u32();
    tel.node_id = local_id;
    tel.poll_ms = poll_ms;
    tel.serial_baud = opt_baud;
    tel.serial_active = serial_dev.is_open ? 1U : 0U;
    tel.acoustic_rx_active = mic_active ? 1U : 0U;
    tel.acoustic_relay_active = opt_acoustic_relay ? 1U : 0U;
    if (serial_dev.is_open) {
        (void)snprintf(tel.serial_port, sizeof(tel.serial_port), "%.48s@%u", serial_dev.port_name, opt_baud);
    }
    tel.started_epoch = (uint64_t)time(NULL);
    tel.heartbeat_epoch = tel.started_epoch;
    tel.bloom_epochs = bf.rotation_epochs;
    memcpy(tel.node_pk, node_pk, 32U);
    (void)snprintf(tel.last_action, sizeof(tel.last_action), "DAEMON_BOOT_LISTENING");
    (void)write_daemon_telemetry(&tel);

    uint32_t ticks = 0U;
    while (!g_daemon_stop) {
        FILE* f_stop = fopen(stop_path, "rb");
        if (f_stop) {
            fclose(f_stop);
            (void)remove(stop_path);
            break;
        }

        bool state_dirty = false;

        /* Channel 1: Atomic IPC Spool */
        FILE* f_rx = fopen(rx_path, "rb");
        if (f_rx) {
            char hex_buf[192];
            memset(hex_buf, 0, sizeof(hex_buf));
            size_t rd = fread(hex_buf, 1U, sizeof(hex_buf) - 1U, f_rx);
            fclose(f_rx);
            (void)remove(rx_path);

            while (rd > 0U && (hex_buf[rd - 1U] == '\n' || hex_buf[rd - 1U] == '\r' ||
                               hex_buf[rd - 1U] == ' '  || hex_buf[rd - 1U] == '\t')) {
                hex_buf[--rd] = '\0';
            }

            tel.frames_received++;
            uint8_t wire_in[OZOS_MESH_FRAME_SIZE];
            if (!hex_decode(hex_buf, wire_in, sizeof(wire_in))) {
                tel.frames_dropped_invalid++;
                (void)snprintf(tel.last_action, sizeof(tel.last_action),
                               "[DROP_INVALID/IPC] Malformed hex length (%zu chars)", rd);
            } else {
                daemon_dispatch_wire_frame(
                    wire_in, "IPC", local_id, &bf, &cache, &tel, tx_path,
                    &serial_dev, opt_acoustic_relay
                );
            }

            FILE* f_ack = fopen(ack_tmp, "wb");
            if (f_ack) {
                (void)fprintf(f_ack, "%s\n", tel.last_action);
                fclose(f_ack);
                (void)atomic_replace_file(ack_tmp, ack_path);
            }
            state_dirty = true;
        }

        /* Channel 2: Hardware Serial UART / USB-LoRa SLIP-84 */
        if (serial_dev.is_open) {
            uint8_t uart_wire[OZOS_MESH_FRAME_SIZE];
            while (ozos_serial_poll_frame(&serial_dev, uart_wire)) {
                tel.frames_received++;
                daemon_dispatch_wire_frame(
                    uart_wire, "UART", local_id, &bf, &cache, &tel, tx_path,
                    &serial_dev, opt_acoustic_relay
                );
                state_dirty = true;
            }
        }

        /* Channel 3: Near-Ultrasound 18.1-19.8 kHz Microphone Demodulator */
        if (mic_active) {
            uint8_t sonic_wire[OZOS_MESH_FRAME_SIZE];
            if (ozos_sonic_mic_poll_frame(&g_daemon_mic, sonic_wire)) {
                tel.frames_received++;
                daemon_dispatch_wire_frame(
                    sonic_wire, "SONIC", local_id, &bf, &cache, &tel, tx_path,
                    &serial_dev, opt_acoustic_relay
                );
                state_dirty = true;
            }
        }

        if (state_dirty) {
            tel.dtn_cache_depth = (uint32_t)cache.count;
            tel.bloom_epochs = bf.rotation_epochs;
            tel.heartbeat_epoch = (uint64_t)time(NULL);
            (void)write_daemon_telemetry(&tel);
        }

        sleep_millis(poll_ms);
        ticks++;
        if ((ticks * poll_ms) >= 2000U) {
            ticks = 0U;
            uint64_t now_ep = (uint64_t)time(NULL);

            /* Self-healing hardware watchdog: auto-recover unplugged UART or suspended Audio DMA */
            if (opt_serial != NULL && !serial_dev.is_open) {
                if (ozos_serial_open(&serial_dev, opt_serial, opt_baud)) {
                    (void)snprintf(tel.serial_port, sizeof(tel.serial_port), "%.48s@%u", serial_dev.port_name, opt_baud);
                }
            }
            tel.serial_active = serial_dev.is_open ? 1U : 0U;

#if defined(_WIN32)
            if (opt_acoustic && ozos_sonic_mic_needs_recovery(&g_daemon_mic, now_ep)) {
                ozos_sonic_mic_close(&g_daemon_mic);
                mic_active = ozos_sonic_mic_open(&g_daemon_mic);
            }
#endif
            tel.acoustic_rx_active = mic_active ? 1U : 0U;

            tel.heartbeat_epoch = now_ep;
            tel.dtn_cache_depth = (uint32_t)cache.count;
            tel.bloom_epochs = bf.rotation_epochs;
            (void)write_daemon_telemetry(&tel);
        }
    }

    if (mic_active) {
        ozos_sonic_mic_close(&g_daemon_mic);
    }
    ozos_serial_close(&serial_dev);

    save_node_bloom(local_id, &bf);
    ozos_mesh_zeroize(&bf, sizeof(bf));
    ozos_mesh_zeroize(&cache, sizeof(cache));

    char tel_path[576];
    if (build_state_file_path("daemon_telemetry.bin", tel_path)) {
        (void)remove(tel_path);
    }
#if defined(_WIN32)
    if (h_daemon_mutex != NULL) {
        CloseHandle(h_daemon_mutex);
    }
#endif
    return 0;
}

static int cmd_start(int argc, char* argv[]) {
    ozos_daemon_telemetry_t existing;
    if (read_live_daemon_telemetry(&existing)) {
        printf("O.Z.O.S Mesh Daemon is already running in background (PID: %u | Node ID: 0x%08X).\n",
               existing.pid, existing.node_id);
        return 0;
    }

    /* Validate forwarded daemon arguments before spawning */
    int check_i = 2;
    while (check_i < argc) {
        if (strcmp(argv[check_i], "--node-id") == 0 && (check_i + 1) < argc) {
            uint32_t tmp_id = 0U;
            if (!parse_hex_u32(argv[check_i + 1], &tmp_id, false)) {
                printf("Error: Invalid --node-id '%s'.\n", argv[check_i + 1]);
                return 1;
            }
            check_i += 2;
        } else if (strcmp(argv[check_i], "--serial") == 0 && (check_i + 1) < argc) {
            if (!is_safe_serial_port_arg(argv[check_i + 1])) {
                printf("Error: Invalid or unsafe --serial port '%s'.\n", argv[check_i + 1]);
                return 1;
            }
            check_i += 2;
        } else if (strcmp(argv[check_i], "--baud") == 0 && (check_i + 1) < argc) {
            uint32_t tmp_baud = 0U;
            if (!parse_u32_bounded(argv[check_i + 1], 1200U, 2000000U, &tmp_baud)) {
                printf("Error: Invalid --baud '%s'.\n", argv[check_i + 1]);
                return 1;
            }
            check_i += 2;
        } else if (strcmp(argv[check_i], "--acoustic") == 0 || strcmp(argv[check_i], "--acoustic-relay") == 0) {
            check_i += 1;
        } else {
            printf("Error: Unknown start option '%s'.\n", argv[check_i]);
            return 1;
        }
    }

#if defined(_WIN32)
    char exe_path[512];
    DWORD n = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    if (n == 0 || n >= sizeof(exe_path)) {
        printf("Error: Unable to resolve executable path.\n");
        return 1;
    }

    char cmdline[896];
    int cpos = snprintf(cmdline, sizeof(cmdline), "\"%s\" daemon", exe_path);
    for (int k = 2; k < argc && cpos > 0 && (size_t)cpos < sizeof(cmdline) - 64U; ++k) {
        int w = snprintf(cmdline + cpos, sizeof(cmdline) - (size_t)cpos, " \"%s\"", argv[k]);
        if (w > 0) cpos += w;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        exe_path,
        cmdline,
        NULL,
        NULL,
        FALSE,
        DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        NULL,
        NULL,
        &si,
        &pi
    );
    if (!ok) {
        printf("Error: Failed to spawn detached background daemon (Win32 error %lu).\n", GetLastError());
        return 1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
#else
    pid_t pid = fork();
    if (pid < 0) {
        printf("Error: fork() failed.\n");
        return 1;
    }
    if (pid == 0) {
        (void)setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            if (dup2(devnull, STDIN_FILENO) < 0 ||
                dup2(devnull, STDOUT_FILENO) < 0 ||
                dup2(devnull, STDERR_FILENO) < 0) {
                close(devnull);
                _exit(1);
            }
            if (devnull > 2) close(devnull);
        }
        char daemon_cmd_buf[] = "daemon";
        char* d_argv[16];
        int d_argc = 0;
        d_argv[d_argc++] = argv[0];
        d_argv[d_argc++] = daemon_cmd_buf;
        for (int k = 2; k < argc && d_argc < 15; ++k) {
            d_argv[d_argc++] = argv[k];
        }
        d_argv[d_argc] = NULL;
        return cmd_daemon(d_argc, d_argv);
    }
#endif

    for (int wait_i = 0; wait_i < 25; ++wait_i) {
        sleep_millis(80U);
        if (read_live_daemon_telemetry(&existing)) {
            printf("=================================================================\n");
            printf("  O.Z.O.S // BACKGROUND DAEMON LAUNCHED SUCCESSFULLY\n");
            printf("=================================================================\n");
            printf("* Daemon PID      : %u (Headless / Zero Console Window)\n", existing.pid);
            printf("* Sovereign ID    : 0x%08X\n", existing.node_id);
            printf("* Carriers Active : IPC=ON | UART=%s | Ultrasonic=%s\n",
                   existing.serial_active ? existing.serial_port : "OFF",
                   existing.acoustic_rx_active ? "ON (18.1-19.8 kHz)" : "OFF");
            printf("* Memory Footprint: Zero-Heap Stack Enclave (malloc = 0)\n");
            printf("=================================================================\n");
            return 0;
        }
    }

    printf("Warning: Background process spawned; awaiting initial telemetry seal.\n");
    return 0;
}

static int cmd_stop(void) {
    ozos_daemon_telemetry_t existing;
    if (!read_live_daemon_telemetry(&existing)) {
        printf("O.Z.O.S Mesh Daemon is not currently running.\n");
        return 0;
    }

    char stop_path[576];
    if (!build_state_file_path("daemon.stop", stop_path)) {
        printf("Error: Failed to resolve state directory.\n");
        return 1;
    }

    FILE* fp = fopen(stop_path, "wb");
    if (fp) {
        if (fwrite("STOP\n", 1U, 5U, fp) != 5U) {
            fclose(fp);
            return 1;
        }
        fclose(fp);
    }

    for (int i = 0; i < 30; ++i) {
        sleep_millis(80U);
        if (!is_pid_alive(existing.pid)) {
            printf("Stopped O.Z.O.S Mesh Background Daemon (PID %u) cleanly.\n", existing.pid);
            return 0;
        }
    }

    printf("Stop signal written for PID %u.\n", existing.pid);
    return 0;
}

static int cmd_inject(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Error: Usage: ozos-mesh inject <160_char_frame_hex>\n");
        return 1;
    }
    uint8_t dummy[OZOS_MESH_FRAME_SIZE];
    if (!hex_decode(argv[2], dummy, sizeof(dummy))) {
        printf("Error: Invalid 80-byte mesh frame hex string.\n");
        return 1;
    }

    ozos_daemon_telemetry_t existing;
    if (!read_live_daemon_telemetry(&existing)) {
        printf("Error: No active background daemon found. Run 'ozos-mesh start' first.\n");
        return 1;
    }

    char rx_tmp[576];
    char rx_path[576];
    char ack_path[576];
    if (!build_state_file_path("rx_frame.tmp", rx_tmp) ||
        !build_state_file_path("rx_frame.hex", rx_path) ||
        !build_state_file_path("last_dispatch.txt", ack_path)) {
        return 1;
    }

    (void)remove(ack_path);
    FILE* fp = fopen(rx_tmp, "wb");
    if (!fp) return 1;
    if (fwrite(argv[2], 1U, 160U, fp) != 160U) {
        fclose(fp);
        (void)remove(rx_tmp);
        return 1;
    }
    fclose(fp);
    if (!atomic_replace_file(rx_tmp, rx_path)) {
        (void)remove(rx_tmp);
        return 1;
    }

    for (int i = 0; i < 25; ++i) {
        sleep_millis(60U);
        FILE* f_ack = fopen(ack_path, "rb");
        if (f_ack) {
            char result_line[128];
            memset(result_line, 0, sizeof(result_line));
            if (fgets(result_line, (int)sizeof(result_line), f_ack) == NULL) {
                result_line[0] = '\0';
            }
            fclose(f_ack);
            printf("Daemon (PID %u | Node 0x%08X) Processed Frame -> %s",
                   existing.pid, existing.node_id, result_line);
            return 0;
        }
    }

    printf("Frame queued to background daemon (PID %u).\n", existing.pid);
    return 0;
}

static int cmd_keygen(void) {
    uint8_t pk[32];
    uint8_t sk[32];
    ozos_mesh_keygen(pk, sk);
    uint32_t node_id = ozos_mesh_node_id_from_pk(pk);

    char pk_hex[65];
    char sk_hex[65];
    hex_encode(pk, 32U, pk_hex);
    hex_encode(sk, 32U, sk_hex);
    ozos_mesh_zeroize(sk, sizeof(sk));

    printf("=================================================================\n");
    printf("  O.Z.O.S // SOVEREIGN X25519 MESH IDENTITY GENERATED\n");
    printf("=================================================================\n");
    printf("* Node ID       : 0x%08X\n", node_id);
    printf("* Public Key    : %s\n", pk_hex);
    printf("* Secret Key    : %s\n", sk_hex);
    printf("=================================================================\n");
    ozos_mesh_zeroize(sk_hex, sizeof(sk_hex));
    return 0;
}

static int cmd_reset_state(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Error: Usage: ozos-mesh reset-state <local_id_hex>\n");
        return 1;
    }
    uint32_t local_id = 0U;
    if (!parse_hex_u32(argv[2], &local_id, false)) {
        printf("Error: Invalid local_id_hex.\n");
        return 1;
    }
    char path[576];
    if (build_node_state_path(local_id, path)) {
        (void)remove(path);
    }
    printf("Purged Bloom replay state for node 0x%08X.\n", local_id);
    return 0;
}

static int cmd_pack(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Error: Missing parameters. Usage: ozos-mesh pack <src_id_hex> <dst_id_hex> <msg> [ttl] [--peer-pk <hex> --sender-sk <hex>]\n");
        return 1;
    }

    uint32_t src_id = 0U;
    uint32_t dst_id = 0U;
    if (!parse_hex_u32(argv[2], &src_id, false)) {
        printf("Error: Invalid source Node ID '%s' (must be non-zero 32-bit hex, not broadcast).\n", argv[2]);
        return 1;
    }
    if (!parse_hex_u32(argv[3], &dst_id, true)) {
        printf("Error: Invalid destination Node ID '%s' (must be non-zero 32-bit hex).\n", argv[3]);
        return 1;
    }
    if (src_id == dst_id) {
        printf("Error: Source Node ID and Destination Node ID must differ.\n");
        return 1;
    }

    const char* msg = argv[4];
    uint16_t ttl = OZOS_MESH_DEFAULT_TTL;
    int opt_idx = 5;

    if (argc >= 6 && strncmp(argv[5], "--", 2U) != 0) {
        if (!parse_ttl_u16(argv[5], &ttl)) {
            printf("Error: Invalid TTL '%s' (must be integer in 1..%u).\n", argv[5], OZOS_MESH_MAX_TTL);
            return 1;
        }
        opt_idx = 6;
    }

    const char* peer_pk_hex = NULL;
    const char* sender_sk_hex = NULL;
    while (opt_idx < argc) {
        if (strcmp(argv[opt_idx], "--peer-pk") == 0 && (opt_idx + 1) < argc) {
            peer_pk_hex = argv[opt_idx + 1];
            opt_idx += 2;
        } else if (strcmp(argv[opt_idx], "--sender-sk") == 0 && (opt_idx + 1) < argc) {
            sender_sk_hex = argv[opt_idx + 1];
            opt_idx += 2;
        } else {
            printf("Error: Unknown or incomplete option '%s'.\n", argv[opt_idx]);
            return 1;
        }
    }

    if ((peer_pk_hex != NULL) != (sender_sk_hex != NULL)) {
        printf("Error: Both --peer-pk and --sender-sk are required for encrypted packing.\n");
        return 1;
    }

    ozos_mesh_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.magic = OZOS_MAGIC_MESH_FRAME;
    frame.hop_limit = ttl;
    frame.src_node_id = src_id;
    frame.dst_node_id = dst_id;

    while (frame.packet_id == 0U) {
        uint8_t pid_buf[4];
        randombytes(pid_buf, sizeof(pid_buf));
        frame.packet_id = ozos_le32_read(pid_buf);
    }

    size_t len = strlen(msg);

    if (peer_pk_hex && sender_sk_hex) {
        if (len > OZOS_MESH_MAX_CRYPTO_PLAIN) {
            printf("Error: Encrypted payload exceeds %u-byte single-frame AEAD limit.\n", OZOS_MESH_MAX_CRYPTO_PLAIN);
            return 1;
        }
        uint8_t peer_pk[32];
        uint8_t sender_sk[32];
        if (!hex_decode(peer_pk_hex, peer_pk, 32U) || !hex_decode(sender_sk_hex, sender_sk, 32U)) {
            ozos_mesh_zeroize(sender_sk, sizeof(sender_sk));
            printf("Error: Invalid 64-character hex key for --peer-pk or --sender-sk.\n");
            return 1;
        }
        bool ok = ozos_mesh_frame_encrypt(&frame, (const uint8_t*)msg, len, peer_pk, sender_sk);
        ozos_mesh_zeroize(sender_sk, sizeof(sender_sk));
        if (!ok) {
            printf("Error: Cryptographic encapsulation failed (rejected low-order or self key).\n");
            return 1;
        }
    } else {
        frame.flags = OZOS_MESH_FLAG_CLEARTEXT;
        if (len > OZOS_MESH_PAYLOAD_SIZE) {
            len = OZOS_MESH_PAYLOAD_SIZE;
        }
        if (len > 0U) {
            memcpy(frame.payload, msg, len);
        }
        ozos_mesh_seal(&frame);
    }

    uint8_t wire_bytes[OZOS_MESH_FRAME_SIZE];
    ozos_mesh_frame_encode(&frame, wire_bytes);

    char hex[161];
    hex_encode(wire_bytes, sizeof(wire_bytes), hex);

    printf("=================================================================\n");
    printf("  O.Z.O.S // MESH FRAME ENCAPSULATION\n");
    printf("=================================================================\n");
    printf("* Frame Size    : %u Bytes (OZOS-80 Binary Aligned)\n", OZOS_MESH_FRAME_SIZE);
    printf("* Source Node   : 0x%08X\n", src_id);
    printf("* Dest Node     : 0x%08X\n", dst_id);
    printf("* Packet Seq ID : 0x%08X\n", frame.packet_id);
    printf("* Security Mode : %s (Flags: 0x%04X)\n",
           (frame.flags & OZOS_MESH_FLAG_ENCRYPTED) ? "X25519-XSalsa20-Poly1305 E2EE" : "CLEARTEXT BEACON",
           frame.flags);
    printf("* Hop Limit     : %u Hops\n", ttl);
    printf("* Link CRC16    : 0x%04X\n", frame.tripwire_mac);
    printf("* Raw Frame Hex : %s\n", hex);
    printf("=================================================================\n");
    return 0;
}

static int cmd_forward(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Error: Missing parameters. Usage: ozos-mesh forward <frame_hex> <local_id_hex> [--sender-pk <hex> --local-sk <hex>] [--stateless]\n");
        return 1;
    }

    const char* frame_hex = argv[2];
    uint32_t local_id = 0U;
    if (!parse_hex_u32(argv[3], &local_id, false)) {
        printf("Error: Invalid local Node ID '%s' (must be non-zero 32-bit hex, not broadcast).\n", argv[3]);
        return 1;
    }

    const char* sender_pk_hex = NULL;
    const char* local_sk_hex = NULL;
    bool stateless = false;

    int opt_idx = 4;
    while (opt_idx < argc) {
        if (strcmp(argv[opt_idx], "--sender-pk") == 0 && (opt_idx + 1) < argc) {
            sender_pk_hex = argv[opt_idx + 1];
            opt_idx += 2;
        } else if (strcmp(argv[opt_idx], "--local-sk") == 0 && (opt_idx + 1) < argc) {
            local_sk_hex = argv[opt_idx + 1];
            opt_idx += 2;
        } else if (strcmp(argv[opt_idx], "--stateless") == 0) {
            stateless = true;
            opt_idx += 1;
        } else {
            printf("Error: Unknown or incomplete option '%s'.\n", argv[opt_idx]);
            return 1;
        }
    }

    if ((sender_pk_hex != NULL) != (local_sk_hex != NULL)) {
        printf("Error: Both --sender-pk and --local-sk are required for E2EE decryption.\n");
        return 1;
    }

    uint8_t wire_in[OZOS_MESH_FRAME_SIZE];
    if (!hex_decode(frame_hex, wire_in, sizeof(wire_in))) {
        printf("Error: Invalid 80-byte mesh frame hex string.\n");
        return 1;
    }

    ozos_mesh_frame_t frame;
    ozos_mesh_frame_decode(wire_in, &frame);
    ozos_mesh_frame_t incoming_snapshot = frame;

    ozos_mesh_bloom_t bf;
    ozos_mesh_cache_t cache;
    ozos_mesh_cache_init(&cache);

    if (stateless) {
        ozos_mesh_bloom_init(&bf);
    } else {
        load_or_init_node_bloom(local_id, &bf);
    }

    ozos_mesh_action_t action = ozos_mesh_process_frame(&frame, local_id, &bf, &cache);

    printf("=================================================================\n");
    printf("  O.Z.O.S // MESH ROUTING DISPATCH RESULT\n");
    printf("=================================================================\n");
    printf("* Local Node ID : 0x%08X\n", local_id);
    printf("* Target Node ID: 0x%08X\n", frame.dst_node_id);
    printf("* Source Node ID: 0x%08X\n", frame.src_node_id);
    printf("* Packet Seq ID : 0x%08X\n", frame.packet_id);

    if (action == OZOS_MESH_ACTION_DELIVER || action == OZOS_MESH_ACTION_DELIVER_AND_RELAY) {
        if (action == OZOS_MESH_ACTION_DELIVER) {
            printf("* Action Taken  : [DELIVER] Packet reached destination! Delivering to local node.\n");
        } else {
            printf("* Action Taken  : [DELIVER] + [RELAY] Multi-hop broadcast delivered locally & relayed!\n");
        }

        if (incoming_snapshot.flags & OZOS_MESH_FLAG_ENCRYPTED) {
            if (sender_pk_hex && local_sk_hex) {
                uint8_t sender_pk[32];
                uint8_t local_sk[32];
                uint8_t plain[OZOS_MESH_MAX_CRYPTO_PLAIN + 1U];
                size_t plain_len = 0U;

                if (!hex_decode(sender_pk_hex, sender_pk, 32U) || !hex_decode(local_sk_hex, local_sk, 32U)) {
                    ozos_mesh_zeroize(local_sk, sizeof(local_sk));
                    ozos_mesh_zeroize(&bf, sizeof(bf));
                    printf("* Crypto Status : [DROP_AUTH_FAIL] Invalid key hex encoding.\n");
                    return 1;
                }
                bool dec_ok = ozos_mesh_frame_decrypt(
                    plain, sizeof(plain), &plain_len,
                    &incoming_snapshot, sender_pk, local_sk
                );
                ozos_mesh_zeroize(local_sk, sizeof(local_sk));
                if (!dec_ok) {
                    ozos_mesh_zeroize(plain, sizeof(plain));
                    ozos_mesh_zeroize(&bf, sizeof(bf));
                    printf("* Crypto Status : [DROP_AUTH_FAIL] Poly1305 AEAD tag or header AAD verification failed!\n");
                    return 1;
                }
                printf("* Payload Text  : ");
                print_sanitized_ascii(plain, plain_len, false);
                ozos_mesh_zeroize(plain, sizeof(plain));
            } else {
                printf("* Payload State : [ENCRYPTED_ENVELOPE] 58-byte E2EE ciphertext (provide keys to open).\n");
            }
        } else {
            printf("* Payload Text  : ");
            print_sanitized_ascii(incoming_snapshot.payload, OZOS_MESH_PAYLOAD_SIZE, true);
        }

        if (action == OZOS_MESH_ACTION_DELIVER_AND_RELAY) {
            uint8_t wire_out[OZOS_MESH_FRAME_SIZE];
            char new_hex[161];
            ozos_mesh_frame_encode(&frame, wire_out);
            hex_encode(wire_out, sizeof(wire_out), new_hex);
            printf("* Remaining Hops: %u\n", frame.hop_limit);
            printf("* Resealed CRC16: 0x%04X\n", frame.tripwire_mac);
            printf("* Relayed Hex   : %s\n", new_hex);
        }
    } else if (action == OZOS_MESH_ACTION_RELAY) {
        uint8_t wire_out[OZOS_MESH_FRAME_SIZE];
        char new_hex[161];
        ozos_mesh_frame_encode(&frame, wire_out);
        hex_encode(wire_out, sizeof(wire_out), new_hex);
        printf("* Action Taken  : [RELAY] Forwarding to next hop. Remaining Hops: %u\n", frame.hop_limit);
        printf("* Resealed CRC16: 0x%04X\n", frame.tripwire_mac);
        printf("* Relayed Hex   : %s\n", new_hex);
    } else if (action == OZOS_MESH_ACTION_DROP_SEEN) {
        printf("* Action Taken  : [DROP_SEEN] Duplicate or self-reflected packet suppressed by SipHash Bloom.\n");
    } else if (action == OZOS_MESH_ACTION_DROP_EXPIRED) {
        printf("* Action Taken  : [DROP_EXPIRED] Hop limit expired or exceeded ceiling. Anti-Zombie purge.\n");
    } else {
        ozos_mesh_zeroize(&bf, sizeof(bf));
        printf("* Action Taken  : [DROP_INVALID] Link CRC16 corrupted or malformed header invariants.\n");
        printf("=================================================================\n");
        return 1;
    }

    if (!stateless &&
        (action == OZOS_MESH_ACTION_DELIVER ||
         action == OZOS_MESH_ACTION_DELIVER_AND_RELAY ||
         action == OZOS_MESH_ACTION_RELAY)) {
        save_node_bloom(local_id, &bf);
    }
    ozos_mesh_zeroize(&bf, sizeof(bf));

    printf("=================================================================\n");
    return 0;
}

static int cmd_sim_multihop(void) {
    printf("=================================================================\n");
    printf("  O.Z.O.S // MULTI-HOP SOVEREIGN E2EE MESH BENCHMARK (A -> B -> C)\n");
    printf("=================================================================\n\n");

    uint8_t alice_pk[32], alice_sk[32];
    uint8_t charlie_pk[32], charlie_sk[32];
    ozos_mesh_keygen(alice_pk, alice_sk);
    ozos_mesh_keygen(charlie_pk, charlie_sk);

    uint32_t node_a_id = ozos_mesh_node_id_from_pk(alice_pk);
    uint32_t node_b_id = 0xB0B00002U;
    uint32_t node_c_id = ozos_mesh_node_id_from_pk(charlie_pk);
    if (node_c_id == node_a_id) node_c_id ^= 0x00000001U;
    if (node_b_id == node_a_id || node_b_id == node_c_id) node_b_id = 0xB0B00003U;

    ozos_mesh_frame_t frame_a;
    memset(&frame_a, 0, sizeof(frame_a));
    frame_a.magic = OZOS_MAGIC_MESH_FRAME;
    frame_a.hop_limit = 3U;
    frame_a.src_node_id = node_a_id;
    frame_a.dst_node_id = node_c_id;
    frame_a.packet_id = 0xCAFE0001U;

    const char* secret_msg = "SOVEREIGN_MESH_P2P_SECRET_2026";
    if (!ozos_mesh_frame_encrypt(&frame_a, (const uint8_t*)secret_msg, strlen(secret_msg), charlie_pk, alice_sk)) {
        ozos_mesh_zeroize(alice_sk, sizeof(alice_sk));
        ozos_mesh_zeroize(charlie_sk, sizeof(charlie_sk));
        printf("  [FAIL] Alice failed to encrypt E2EE Onion Frame!\n");
        return 1;
    }
    ozos_mesh_zeroize(alice_sk, sizeof(alice_sk));

    printf("[STEP 1: ALICE E2EE EMISSION]\n");
    printf("  * Alice (0x%08X) -> Charlie (0x%08X) via X25519 + XSalsa20-Poly1305\n", node_a_id, node_c_id);
    printf("  * Initial Hop Limit: %u | Outer Link CRC16: 0x%04X\n\n", frame_a.hop_limit, frame_a.tripwire_mac);

    ozos_mesh_bloom_t bob_bloom;
    ozos_mesh_cache_t bob_cache;
    ozos_mesh_bloom_init(&bob_bloom);
    ozos_mesh_cache_init(&bob_cache);

    printf("[STEP 2: BOB BLIND RELAY DISPATCH]\n");
    ozos_mesh_action_t act_b = ozos_mesh_process_frame(&frame_a, node_b_id, &bob_bloom, &bob_cache);
    if (act_b != OZOS_MESH_ACTION_RELAY || bob_cache.count != 1U || bob_cache.slots[0].hop_limit != 2U) {
        ozos_mesh_zeroize(charlie_sk, sizeof(charlie_sk));
        printf("  [FAIL] Bob relay or post-decrement DTN cache invariant failed!\n");
        return 1;
    }
    printf("  * Action: [RELAY] -> Decremented Hop Limit: %u | Resealed CRC16: 0x%04X\n",
           frame_a.hop_limit, frame_a.tripwire_mac);
    printf("  * DTN Cache Depth: %zu (Cached Hop Limit Verified = %u)\n\n",
           bob_cache.count, bob_cache.slots[0].hop_limit);

    ozos_mesh_bloom_t charlie_bloom;
    ozos_mesh_cache_t charlie_cache;
    ozos_mesh_bloom_init(&charlie_bloom);
    ozos_mesh_cache_init(&charlie_cache);

    printf("[STEP 3: CHARLIE AUTHENTICATED DECRYPTION]\n");
    ozos_mesh_action_t act_c = ozos_mesh_process_frame(&frame_a, node_c_id, &charlie_bloom, &charlie_cache);
    if (act_c != OZOS_MESH_ACTION_DELIVER || charlie_cache.count != 0U) {
        ozos_mesh_zeroize(charlie_sk, sizeof(charlie_sk));
        printf("  [FAIL] Charlie delivery or private-frame DTN isolation failed!\n");
        return 1;
    }

    uint8_t recovered[OZOS_MESH_MAX_CRYPTO_PLAIN + 1U];
    size_t rec_len = 0U;
    bool dec_ok = ozos_mesh_frame_decrypt(recovered, sizeof(recovered), &rec_len, &frame_a, alice_pk, charlie_sk);
    ozos_mesh_zeroize(charlie_sk, sizeof(charlie_sk));
    if (!dec_ok || rec_len != strlen(secret_msg) || memcmp(recovered, secret_msg, rec_len) != 0) {
        ozos_mesh_zeroize(recovered, sizeof(recovered));
        printf("  [FAIL] Charlie Poly1305 authentication / decryption failed!\n");
        return 1;
    }
    printf("  * Action: [DELIVER] -> Poly1305 Header AAD & Ciphertext Verified 100%%!\n");
    printf("  * Recovered Secret: '%s'\n\n", (const char*)recovered);
    ozos_mesh_zeroize(recovered, sizeof(recovered));

    printf("[STEP 4: SIPHASH BLOOM FILTER DUPLICATE SUPPRESSION]\n");
    ozos_mesh_action_t act_b_dup = ozos_mesh_process_frame(&frame_a, node_b_id, &bob_bloom, &bob_cache);
    if (act_b_dup != OZOS_MESH_ACTION_DROP_SEEN) {
        printf("  [FAIL] Bob failed to suppress duplicate packet!\n");
        return 1;
    }
    printf("  * Action: [DROP_SEEN] -> Duplicate suppressed in O(1) time.\n\n");

    printf("[STEP 5: ANTI-ZOMBIE TTL EXCLUSION & DTN ISOLATION]\n");
    frame_a.hop_limit = 1U;
    frame_a.packet_id = 0xDEADBEEFU;
    ozos_mesh_seal(&frame_a);
    ozos_mesh_action_t act_b_exp = ozos_mesh_process_frame(&frame_a, node_b_id, &bob_bloom, &bob_cache);
    if (act_b_exp != OZOS_MESH_ACTION_DROP_EXPIRED || bob_cache.count != 1U) {
        printf("  [FAIL] Expired zombie frame leaked into DTN cache!\n");
        return 1;
    }
    printf("  * Action: [DROP_EXPIRED] -> Zombie frame purged; DTN cache unpolluted (depth=%zu).\n\n",
           bob_cache.count);

    printf("=================================================================\n");
    printf("  BENCHMARK PASSED 100%%: SOVEREIGN E2EE MULTI-HOP MESH VERIFIED!\n");
    printf("=================================================================\n");
    return 0;
}

static int cmd_phy_ports(void) {
    ozos_phy_print_hardware_inventory();
    return 0;
}

static int cmd_tx_acoustic(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Error: Usage: ozos-mesh tx-acoustic <frame_hex> [--wav <out.wav>] [--no-speaker]\n");
        return 1;
    }

    uint8_t wire80[OZOS_MESH_FRAME_SIZE];
    if (!hex_decode(argv[2], wire80, sizeof(wire80))) {
        printf("Error: Invalid 160-character OZOS-80 frame hex.\n");
        return 1;
    }
    ozos_mesh_frame_t check_f;
    ozos_mesh_frame_decode(wire80, &check_f);
    if (!ozos_mesh_verify_integrity(&check_f)) {
        printf("Error: Frame failed outer CRC-16 integrity verification.\n");
        return 1;
    }

    const char* wav_out = NULL;
    bool use_speaker = true;
    int idx = 3;
    while (idx < argc) {
        if (strcmp(argv[idx], "--wav") == 0 && (idx + 1) < argc) {
            wav_out = argv[idx + 1];
            idx += 2;
        } else if (strcmp(argv[idx], "--no-speaker") == 0) {
            use_speaker = false;
            idx += 1;
        } else {
            printf("Error: Unknown tx-acoustic option '%s'.\n", argv[idx]);
            return 1;
        }
    }

    ozos_sonic_modulate_frame(wire80, g_sonic_pcm_buf);

    if (wav_out != NULL) {
        if (!ozos_phy_wav_write(wav_out, g_sonic_pcm_buf, OZOS_SONIC_BURST_SAMPLES)) {
            printf("Error: Failed to write ultrasonic RIFF-WAV file '%s'.\n", wav_out);
            return 1;
        }
    }

    bool played = false;
    if (use_speaker) {
        played = ozos_sonic_play_hardware(g_sonic_pcm_buf, OZOS_SONIC_BURST_SAMPLES);
    }

    printf("=================================================================\n");
    printf("  O.Z.O.S // NEAR-ULTRASOUND 18.1-19.8 kHz EMISSION COMPLETE\n");
    printf("=================================================================\n");
    printf("* Carrier Band  : 18,100 Hz - 19,800 Hz (16 Orthogonal Tones + 2 Pilots)\n");
    printf("* PCM Geometry  : %u Samples @ 48,000 Hz Mono 16-bit (1.08 sec)\n", OZOS_SONIC_BURST_SAMPLES);
    printf("* WAV Output    : %s\n", wav_out ? wav_out : "(None)");
    printf("* Speaker TX    : %s\n", use_speaker ? (played ? "TRANSMITTED LIVE" : "NO AUDIO ENDPOINT") : "SKIPPED (--no-speaker)");
    printf("=================================================================\n");
    return 0;
}

static int cmd_rx_acoustic(int argc, char* argv[]) {
    if (argc < 5 || strcmp(argv[2], "--wav") != 0) {
        printf("Error: Usage: ozos-mesh rx-acoustic --wav <in.wav> <local_id_hex> [--sender-pk <hex> --local-sk <hex>] [--stateless]\n");
        return 1;
    }

    const char* wav_in = argv[3];
    size_t n_samples = 0U;
    if (!ozos_phy_wav_read(wav_in, g_sonic_wav_rx_buf, OZOS_SONIC_RX_RING_SAMPLES, &n_samples)) {
        printf("Error: Unable to read 48kHz 16-bit mono WAV '%s'.\n", wav_in);
        return 1;
    }

    uint8_t wire80[OZOS_MESH_FRAME_SIZE];
    size_t consumed = 0U;
    if (!ozos_sonic_demodulate_stream(g_sonic_wav_rx_buf, n_samples, wire80, &consumed)) {
        printf("Error: [SONIC_DEMOD_FAIL] No valid 18.1-19.8 kHz OZOS-80 frame detected.\n");
        return 1;
    }

    char frame_hex[161];
    hex_encode(wire80, sizeof(wire80), frame_hex);

    /* Delegate directly into hardened cmd_forward routing & AEAD pipeline */
    char forward_cmd_buf[] = "forward";
    char* fwd_argv[12];
    int fwd_argc = 0;
    fwd_argv[fwd_argc++] = argv[0];
    fwd_argv[fwd_argc++] = forward_cmd_buf;
    fwd_argv[fwd_argc++] = frame_hex;
    for (int k = 4; k < argc && fwd_argc < 11; ++k) {
        fwd_argv[fwd_argc++] = argv[k];
    }
    fwd_argv[fwd_argc] = NULL;
    return cmd_forward(fwd_argc, fwd_argv);
}

static int cmd_tx_serial(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Error: Usage: ozos-mesh tx-serial <port> <frame_hex> [--baud <N>]\n");
        return 1;
    }

    const char* port = argv[2];
    if (!is_safe_serial_port_arg(port)) {
        printf("Error: Invalid or unsafe serial port '%s'.\n", port);
        return 1;
    }
    uint8_t wire80[OZOS_MESH_FRAME_SIZE];
    if (!hex_decode(argv[3], wire80, sizeof(wire80))) {
        printf("Error: Invalid 160-character OZOS-80 frame hex.\n");
        return 1;
    }
    ozos_mesh_frame_t check_f;
    ozos_mesh_frame_decode(wire80, &check_f);
    if (!ozos_mesh_verify_integrity(&check_f)) {
        printf("Error: Frame failed outer CRC-16 integrity verification.\n");
        return 1;
    }

    uint32_t baud = 115200U;
    int idx = 4;
    while (idx < argc) {
        if (strcmp(argv[idx], "--baud") == 0 && (idx + 1) < argc) {
            if (!parse_u32_bounded(argv[idx + 1], 1200U, 2000000U, &baud)) {
                printf("Error: Invalid --baud '%s'.\n", argv[idx + 1]);
                return 1;
            }
            idx += 2;
        } else {
            printf("Error: Unknown or incomplete tx-serial option '%s'.\n", argv[idx]);
            return 1;
        }
    }

    ozos_serial_port_t sp;
    if (!ozos_serial_open(&sp, port, baud)) {
        printf("Error: Could not open hardware serial port '%s' @ %u baud.\n", port, baud);
        return 1;
    }
    bool sent = ozos_serial_send_frame(&sp, wire80);
    ozos_serial_close(&sp);
    if (!sent) {
        printf("Error: Hardware UART write failed on '%s'.\n", port);
        return 1;
    }

    printf("Transmitted SLIP-84 OZOS-80 frame over %s @ %u baud.\n", port, baud);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    const char* cmd = argv[1];
    if (strcmp(cmd, "status") == 0) {
        return cmd_status();
    } else if (strcmp(cmd, "start") == 0) {
        return cmd_start(argc, argv);
    } else if (strcmp(cmd, "stop") == 0) {
        return cmd_stop();
    } else if (strcmp(cmd, "daemon") == 0) {
        return cmd_daemon(argc, argv);
    } else if (strcmp(cmd, "inject") == 0) {
        return cmd_inject(argc, argv);
    } else if (strcmp(cmd, "phy-ports") == 0) {
        return cmd_phy_ports();
    } else if (strcmp(cmd, "tx-acoustic") == 0) {
        return cmd_tx_acoustic(argc, argv);
    } else if (strcmp(cmd, "rx-acoustic") == 0) {
        return cmd_rx_acoustic(argc, argv);
    } else if (strcmp(cmd, "tx-serial") == 0) {
        return cmd_tx_serial(argc, argv);
    } else if (strcmp(cmd, "install-autostart") == 0) {
        return cmd_install_autostart(argc, argv);
    } else if (strcmp(cmd, "uninstall-autostart") == 0) {
        return cmd_uninstall_autostart();
    } else if (strcmp(cmd, "keygen") == 0) {
        return cmd_keygen();
    } else if (strcmp(cmd, "pack") == 0) {
        return cmd_pack(argc, argv);
    } else if (strcmp(cmd, "forward") == 0) {
        return cmd_forward(argc, argv);
    } else if (strcmp(cmd, "reset-state") == 0) {
        return cmd_reset_state(argc, argv);
    } else if (strcmp(cmd, "sim-multihop") == 0) {
        return cmd_sim_multihop();
    } else if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        return cmd_version();
    } else {
        print_usage();
        return 1;
    }
}
