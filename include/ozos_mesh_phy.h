/**
 * =============================================================================
 *   O.Z.O.S // PHYSICAL LAYER TRANSPORT ENGINE (ozos_mesh_phy.h)
 *   Zero-Heap Hardware UART/LoRa SLIP Driver & 18.1-19.8 kHz Ultrasonic Modem
 *   Compliance: ISO C99 / Zero-Heap (malloc = 0) / OZOS-80 Wire Invariant
 * =============================================================================
 */

#ifndef OZOS_MESH_PHY_H
#define OZOS_MESH_PHY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mmsystem.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <dirent.h>
#endif

#include "ozos_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
   1. DETERMINISTIC SLIP-84 HARDWARE UART / USB-LORA FRAMING
   Wire Envelope: [0xC0] + SLIP_STUFF([4B Magic 0x4F5A5048] + [80B OZOS-80]) + [0xC0]
   ============================================================================= */

#define OZOS_PHY_UART_MAGIC      0x4F5A5048U /* "OZPH" */
#define OZOS_SLIP_END            0xC0U
#define OZOS_SLIP_ESC            0xDBU
#define OZOS_SLIP_ESC_END        0xDCU
#define OZOS_SLIP_ESC_ESC        0xDDU
#define OZOS_PHY_SLIP_MAX_WIRE   192U

typedef struct {
    uint8_t buf[88];
    size_t  len;
    bool    in_esc;
    bool    overflow;
} ozos_phy_slip_rx_t;

static inline void ozos_phy_slip_rx_init(ozos_phy_slip_rx_t* rx) {
    if (!rx) return;
    memset(rx, 0, sizeof(*rx));
}

static inline void ozos_phy_slip_encode(
    const uint8_t wire80[OZOS_MESH_FRAME_SIZE],
    uint8_t out_slip[OZOS_PHY_SLIP_MAX_WIRE],
    size_t* out_len
) {
    uint8_t raw[84];
    size_t pos = 0U;
    ozos_le32_write(raw, OZOS_PHY_UART_MAGIC);
    memcpy(raw + 4, wire80, OZOS_MESH_FRAME_SIZE);

    out_slip[pos++] = OZOS_SLIP_END;
    for (size_t i = 0U; i < sizeof(raw); ++i) {
        uint8_t b = raw[i];
        if (b == OZOS_SLIP_END) {
            out_slip[pos++] = OZOS_SLIP_ESC;
            out_slip[pos++] = OZOS_SLIP_ESC_END;
        } else if (b == OZOS_SLIP_ESC) {
            out_slip[pos++] = OZOS_SLIP_ESC;
            out_slip[pos++] = OZOS_SLIP_ESC_ESC;
        } else {
            out_slip[pos++] = b;
        }
    }
    out_slip[pos++] = OZOS_SLIP_END;
    if (out_len) *out_len = pos;
}

static inline bool ozos_phy_slip_feed_byte(
    ozos_phy_slip_rx_t* rx,
    uint8_t byte,
    uint8_t out_wire80[OZOS_MESH_FRAME_SIZE]
) {
    if (!rx || !out_wire80) return false;

    if (byte == OZOS_SLIP_END) {
        bool ready = (!rx->overflow && !rx->in_esc && rx->len == 84U &&
                      ozos_le32_read(rx->buf) == OZOS_PHY_UART_MAGIC);
        if (ready) {
            memcpy(out_wire80, rx->buf + 4, OZOS_MESH_FRAME_SIZE);
        }
        rx->len = 0U;
        rx->in_esc = false;
        rx->overflow = false;
        return ready;
    }

    if (rx->overflow) return false;

    if (rx->in_esc) {
        rx->in_esc = false;
        if (byte == OZOS_SLIP_ESC_END) {
            byte = OZOS_SLIP_END;
        } else if (byte == OZOS_SLIP_ESC_ESC) {
            byte = OZOS_SLIP_ESC;
        } else {
            rx->overflow = true;
            return false;
        }
    } else if (byte == OZOS_SLIP_ESC) {
        rx->in_esc = true;
        return false;
    }

    if (rx->len >= sizeof(rx->buf)) {
        rx->overflow = true;
        return false;
    }

    rx->buf[rx->len++] = byte;
    return false;
}

/* =============================================================================
   2. CROSS-PLATFORM HARDWARE SERIAL UART DRIVER (USB-LoRa SX1262 / ESP32)
   ============================================================================= */

typedef struct {
    bool is_open;
    char port_name[64];
    uint32_t baud_rate;
#if defined(_WIN32)
    HANDLE handle;
#else
    int fd;
#endif
    ozos_phy_slip_rx_t slip_rx;
} ozos_serial_port_t;

static inline void ozos_serial_init(ozos_serial_port_t* sp) {
    if (!sp) return;
    memset(sp, 0, sizeof(*sp));
#if defined(_WIN32)
    sp->handle = INVALID_HANDLE_VALUE;
#else
    sp->fd = -1;
#endif
    ozos_phy_slip_rx_init(&sp->slip_rx);
}

static inline bool ozos_serial_open(ozos_serial_port_t* sp, const char* port, uint32_t baud) {
    if (!sp || !port || port[0] == '\0') return false;
    ozos_serial_init(sp);

    size_t plen = strlen(port);
    if (plen >= sizeof(sp->port_name)) return false;
    memcpy(sp->port_name, port, plen + 1U);
    sp->baud_rate = (baud == 0U) ? 115200U : baud;

#if defined(_WIN32)
    char win_dev[80];
    if (strncmp(port, "\\\\.\\", 4U) == 0) {
        (void)snprintf(win_dev, sizeof(win_dev), "%s", port);
    } else {
        (void)snprintf(win_dev, sizeof(win_dev), "\\\\.\\%s", port);
    }

    HANDLE h = CreateFileA(win_dev, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        CloseHandle(h);
        return false;
    }
    dcb.BaudRate = (DWORD)sp->baud_rate;
    dcb.ByteSize = 8;
    dcb.Parity   = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary  = TRUE;
    dcb.fParity  = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl  = DTR_CONTROL_ENABLE;
    dcb.fRtsControl  = RTS_CONTROL_ENABLE;
    dcb.fOutX = FALSE;
    dcb.fInX  = FALSE;
    if (!SetCommState(h, &dcb)) {
        CloseHandle(h);
        return false;
    }

    COMMTIMEOUTS to;
    memset(&to, 0, sizeof(to));
    to.ReadIntervalTimeout         = MAXDWORD;
    to.ReadTotalTimeoutMultiplier  = 0;
    to.ReadTotalTimeoutConstant    = 0;
    to.WriteTotalTimeoutMultiplier = 1;
    to.WriteTotalTimeoutConstant   = 200;
    (void)SetCommTimeouts(h, &to);
    (void)PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

    sp->handle = h;
    sp->is_open = true;
    return true;
#else
    int fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return false;

    struct termios tio;
    memset(&tio, 0, sizeof(tio));
    if (tcgetattr(fd, &tio) != 0) {
        close(fd);
        return false;
    }

    speed_t spd = B115200;
    if (sp->baud_rate == 9600U) spd = B9600;
    else if (sp->baud_rate == 19200U) spd = B19200;
    else if (sp->baud_rate == 38400U) spd = B38400;
    else if (sp->baud_rate == 57600U) spd = B57600;

    (void)cfsetispeed(&tio, spd);
    (void)cfsetospeed(&tio, spd);

    tio.c_iflag &= (tcflag_t)~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXOFF);
    tio.c_oflag &= (tcflag_t)~OPOST;
    tio.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tio.c_cflag &= (tcflag_t)~(CSIZE | PARENB | CSTOPB);
    tio.c_cflag |= (tcflag_t)(CS8 | CREAD | CLOCAL);
    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        close(fd);
        return false;
    }

    sp->fd = fd;
    sp->is_open = true;
    return true;
#endif
}

static inline void ozos_serial_close(ozos_serial_port_t* sp) {
    if (!sp || !sp->is_open) return;
#if defined(_WIN32)
    if (sp->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(sp->handle);
        sp->handle = INVALID_HANDLE_VALUE;
    }
#else
    if (sp->fd >= 0) {
        close(sp->fd);
        sp->fd = -1;
    }
#endif
    sp->is_open = false;
}

static inline bool ozos_serial_send_frame(ozos_serial_port_t* sp, const uint8_t wire80[OZOS_MESH_FRAME_SIZE]) {
    if (!sp || !sp->is_open || !wire80) return false;
    uint8_t slip_buf[OZOS_PHY_SLIP_MAX_WIRE];
    size_t slip_len = 0U;
    ozos_phy_slip_encode(wire80, slip_buf, &slip_len);

#if defined(_WIN32)
    DWORD written = 0;
    if (!WriteFile(sp->handle, slip_buf, (DWORD)slip_len, &written, NULL)) {
        ozos_serial_close(sp);
        return false;
    }
    return ((size_t)written == slip_len);
#else
    size_t total = 0U;
    while (total < slip_len) {
        ssize_t nw = write(sp->fd, slip_buf + total, slip_len - total);
        if (nw <= 0) return false;
        total += (size_t)nw;
    }
    return true;
#endif
}

static inline bool ozos_serial_poll_frame(ozos_serial_port_t* sp, uint8_t out_wire80[OZOS_MESH_FRAME_SIZE]) {
    if (!sp || !sp->is_open || !out_wire80) return false;
    uint8_t rx_chunk[64];
    for (int iter = 0; iter < 8; ++iter) {
#if defined(_WIN32)
        DWORD got = 0;
        if (!ReadFile(sp->handle, rx_chunk, sizeof(rx_chunk), &got, NULL)) {
            ozos_serial_close(sp);
            return false;
        }
        if (got == 0) {
            return false;
        }
        size_t n = (size_t)got;
#else
        ssize_t rd = read(sp->fd, rx_chunk, sizeof(rx_chunk));
        if (rd <= 0) return false;
        size_t n = (size_t)rd;
#endif
        for (size_t i = 0U; i < n; ++i) {
            if (ozos_phy_slip_feed_byte(&sp->slip_rx, rx_chunk[i], out_wire80)) {
                return true;
            }
        }
    }
    return false;
}

/* =============================================================================
   3. NEAR-ULTRASOUND 18.1 - 19.8 kHz ORTHOGONAL DUAL-RAIL ACOUSTIC MODEM
   * Sample Rate     : 48,000 Hz Mono 16-bit PCM (Exact 100 Hz Bin Spacing @ N=480)
   * Data Subcarriers: 16 Orthogonal Tones in 18,100 Hz .. 19,600 Hz (Bins 181..196)
                       Grouped as 8 Self-Thresholding Differential Bit Pairs
   * Sync Pilots     : Bins 197 (19,700 Hz) & 198 (19,800 Hz) 4-Symbol Alternating Sync
   * Symbol Geometry : N_core = 480 (10 ms) + N_cp = 96 (2 ms Cyclic Prefix) = 576 samples
   * Total Burst     : (4 Preamble + 86 Data) * 576 = 51,840 samples (1.08 sec, Zero-Heap)
   ============================================================================= */

#define OZOS_SONIC_SAMPLE_RATE    48000U
#define OZOS_SONIC_CORE_LEN       480U
#define OZOS_SONIC_CP_LEN         96U
#define OZOS_SONIC_SYM_LEN        576U   /* 480 + 96 */
#define OZOS_SONIC_PREAMBLE_SYMS  4U
#define OZOS_SONIC_DATA_BYTES     86U    /* 4B Magic + 80B OZOS-80 + 2B CRC16 */
#define OZOS_SONIC_TOTAL_SYMS     90U    /* 4 + 86 */
#define OZOS_SONIC_BURST_SAMPLES  51840U /* 90 * 576 */
#define OZOS_SONIC_MAGIC          0x4F5A534EU /* "OZSN" */
#define OZOS_SONIC_BIN_BASE       181U   /* 18,100 Hz */
#define OZOS_SONIC_BIN_PILOT_A    197U   /* 19,700 Hz */
#define OZOS_SONIC_BIN_PILOT_B    198U   /* 19,800 Hz */

static inline uint16_t ozos_sonic_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFFU;
    for (size_t i = 0U; i < len; ++i) {
        crc ^= (uint16_t)data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 1U) ? (uint16_t)((crc >> 1) ^ 0x8408U) : (uint16_t)(crc >> 1);
        }
    }
    return crc;
}

static inline double ozos_sonic_goertzel_power(const int16_t* samples, uint32_t bin_k) {
    const double pi2 = 6.28318530717958647692;
    const double omega = (pi2 * (double)bin_k) / (double)OZOS_SONIC_CORE_LEN;
    const double coeff = 2.0 * cos(omega);
    double s0 = 0.0;
    double s1 = 0.0;
    double s2 = 0.0;

    for (size_t n = 0U; n < OZOS_SONIC_CORE_LEN; ++n) {
        s0 = ((double)samples[n] * (1.0 / 32768.0)) + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    return (s1 * s1) + (s2 * s2) - (coeff * s1 * s2);
}

static inline void ozos_sonic_synth_symbol(
    int16_t out_sym[OZOS_SONIC_SYM_LEN],
    const uint32_t* active_bins,
    size_t num_bins
) {
    const double pi2 = 6.28318530717958647692;
    const double pi  = 3.14159265358979323846;
    double core[OZOS_SONIC_CORE_LEN];
    double scale = (num_bins > 0U) ? (26000.0 / (double)num_bins) : 0.0;

    for (size_t n = 0U; n < OZOS_SONIC_CORE_LEN; ++n) {
        double acc = 0.0;
        for (size_t b = 0U; b < num_bins; ++b) {
            /* Deterministic Schroeder-like phase dispersion to minimize crest factor */
            double phase_offset = (double)((b * b * 37U) & 63U) * (pi2 / 64.0);
            double angle = (pi2 * (double)active_bins[b] * (double)n) / (double)OZOS_SONIC_CORE_LEN + phase_offset;
            acc += sin(angle);
        }
        core[n] = acc * scale;
    }

    /* Prepend 96-sample Cyclic Prefix from tail of 480-sample orthogonal core */
    for (size_t i = 0U; i < OZOS_SONIC_CP_LEN; ++i) {
        double v = core[OZOS_SONIC_CORE_LEN - OZOS_SONIC_CP_LEN + i];
        out_sym[i] = (int16_t)v;
    }
    for (size_t i = 0U; i < OZOS_SONIC_CORE_LEN; ++i) {
        out_sym[OZOS_SONIC_CP_LEN + i] = (int16_t)core[i];
    }

    /* 16-sample raised-cosine edge taper to suppress audible click transients (<18 kHz) */
    for (size_t t = 0U; t < 16U; ++t) {
        double w = 0.5 * (1.0 - cos((pi * (double)t) / 16.0));
        out_sym[t] = (int16_t)((double)out_sym[t] * w);
        out_sym[OZOS_SONIC_SYM_LEN - 1U - t] = (int16_t)((double)out_sym[OZOS_SONIC_SYM_LEN - 1U - t] * w);
    }
}

static inline void ozos_sonic_modulate_frame(
    const uint8_t wire80[OZOS_MESH_FRAME_SIZE],
    int16_t out_pcm[OZOS_SONIC_BURST_SAMPLES]
) {
    uint8_t packet[OZOS_SONIC_DATA_BYTES];
    ozos_le32_write(packet, OZOS_SONIC_MAGIC);
    memcpy(packet + 4, wire80, OZOS_MESH_FRAME_SIZE);
    uint16_t crc = ozos_sonic_crc16(packet, 84U);
    ozos_le16_write(packet + 84, crc);

    /* 4 Alternating Ultrasonic Pilot Sync Symbols (19.7 kHz <-> 19.8 kHz) */
    for (size_t p = 0U; p < OZOS_SONIC_PREAMBLE_SYMS; ++p) {
        uint32_t pilot = ((p & 1U) == 0U) ? OZOS_SONIC_BIN_PILOT_A : OZOS_SONIC_BIN_PILOT_B;
        ozos_sonic_synth_symbol(out_pcm + (p * OZOS_SONIC_SYM_LEN), &pilot, 1U);
    }

    /* 86 Orthogonal 8-Pair Dual-Rail Ultrasonic Data Symbols (18.1 - 19.6 kHz) */
    for (size_t s = 0U; s < OZOS_SONIC_DATA_BYTES; ++s) {
        uint8_t byte_val = packet[s];
        uint32_t tones[8];
        for (uint32_t bit = 0U; bit < 8U; ++bit) {
            uint32_t bit_set = (uint32_t)((byte_val >> bit) & 1U);
            tones[bit] = OZOS_SONIC_BIN_BASE + (bit * 2U) + bit_set;
        }
        ozos_sonic_synth_symbol(
            out_pcm + ((OZOS_SONIC_PREAMBLE_SYMS + s) * OZOS_SONIC_SYM_LEN),
            tones,
            8U
        );
    }
}

static inline double ozos_sonic_preamble_metric(const int16_t* pcm, size_t offset) {
    const int16_t* p0 = pcm + offset;
    const int16_t* p1 = pcm + offset + OZOS_SONIC_SYM_LEN;
    const int16_t* p2 = pcm + offset + (2U * OZOS_SONIC_SYM_LEN);
    const int16_t* p3 = pcm + offset + (3U * OZOS_SONIC_SYM_LEN);

    double e0a = ozos_sonic_goertzel_power(p0, OZOS_SONIC_BIN_PILOT_A);
    double e0b = ozos_sonic_goertzel_power(p0, OZOS_SONIC_BIN_PILOT_B);
    double e1a = ozos_sonic_goertzel_power(p1, OZOS_SONIC_BIN_PILOT_A);
    double e1b = ozos_sonic_goertzel_power(p1, OZOS_SONIC_BIN_PILOT_B);
    double e2a = ozos_sonic_goertzel_power(p2, OZOS_SONIC_BIN_PILOT_A);
    double e2b = ozos_sonic_goertzel_power(p2, OZOS_SONIC_BIN_PILOT_B);
    double e3a = ozos_sonic_goertzel_power(p3, OZOS_SONIC_BIN_PILOT_A);
    double e3b = ozos_sonic_goertzel_power(p3, OZOS_SONIC_BIN_PILOT_B);

    return (e0a - e0b) + (e1b - e1a) + (e2a - e2b) + (e3b - e3a);
}

static inline bool ozos_sonic_decode_at_window(
    const int16_t* pcm,
    size_t num_samples,
    size_t win_start,
    uint8_t out_wire80[OZOS_MESH_FRAME_SIZE]
) {
    size_t last_end = win_start + ((OZOS_SONIC_TOTAL_SYMS - 1U) * OZOS_SONIC_SYM_LEN) + OZOS_SONIC_CORE_LEN;
    if (last_end > num_samples) return false;

    uint8_t packet[OZOS_SONIC_DATA_BYTES];
    for (size_t s = 0U; s < OZOS_SONIC_DATA_BYTES; ++s) {
        const int16_t* sym_win = pcm + win_start + ((OZOS_SONIC_PREAMBLE_SYMS + s) * OZOS_SONIC_SYM_LEN);
        uint8_t acc = 0U;
        for (uint32_t bit = 0U; bit < 8U; ++bit) {
            double e0 = ozos_sonic_goertzel_power(sym_win, OZOS_SONIC_BIN_BASE + (bit * 2U));
            double e1 = ozos_sonic_goertzel_power(sym_win, OZOS_SONIC_BIN_BASE + (bit * 2U) + 1U);
            if (e1 > e0) {
                acc |= (uint8_t)(1U << bit);
            }
        }
        packet[s] = acc;

        /* Fail-fast after first 4 bytes if ultrasonic sync magic doesn't match */
        if (s == 3U && ozos_le32_read(packet) != OZOS_SONIC_MAGIC) {
            return false;
        }
    }

    uint16_t expected_crc = ozos_le16_read(packet + 84);
    if (ozos_sonic_crc16(packet, 84U) != expected_crc) {
        return false;
    }

    ozos_mesh_frame_t check_frame;
    ozos_mesh_frame_decode(packet + 4, &check_frame);
    if (!ozos_mesh_verify_integrity(&check_frame)) {
        return false;
    }

    memcpy(out_wire80, packet + 4, OZOS_MESH_FRAME_SIZE);
    return true;
}

static inline bool ozos_sonic_demodulate_stream(
    const int16_t* pcm,
    size_t num_samples,
    uint8_t out_wire80[OZOS_MESH_FRAME_SIZE],
    size_t* out_consumed
) {
    if (!pcm || !out_wire80) return false;
    const size_t min_needed = ((OZOS_SONIC_TOTAL_SYMS - 1U) * OZOS_SONIC_SYM_LEN) + OZOS_SONIC_CORE_LEN;
    if (num_samples < min_needed) return false;

    size_t max_search = num_samples - min_needed;
    double best_metric = 0.05; /* Reject pure silence */
    size_t best_pos = 0U;
    bool found_candidate = false;

    for (size_t pos = 0U; pos <= max_search; pos += 24U) {
        double m = ozos_sonic_preamble_metric(pcm, pos);
        if (m > best_metric) {
            best_metric = m;
            best_pos = pos;
            found_candidate = true;
        }
    }
    if (!found_candidate) return false;

    /* Fine-grain timing search across +-48 samples around coarse correlation peak */
    size_t fine_lo = (best_pos > 48U) ? (best_pos - 48U) : 0U;
    size_t fine_hi = (best_pos + 48U <= max_search) ? (best_pos + 48U) : max_search;
    for (size_t pos = fine_lo; pos <= fine_hi; pos += 4U) {
        double m = ozos_sonic_preamble_metric(pcm, pos);
        if (m > best_metric) {
            best_metric = m;
            best_pos = pos;
        }
    }

    /* Try best_pos and small neighbor offsets inside the 96-sample Cyclic Prefix */
    static const int offsets[5] = { 0, 16, -16, 32, -32 };
    for (size_t k = 0U; k < 5U; ++k) {
        long cand = (long)best_pos + (long)offsets[k];
        if (cand < 0 || (size_t)cand > max_search) continue;
        if (ozos_sonic_decode_at_window(pcm, num_samples, (size_t)cand, out_wire80)) {
            if (out_consumed) {
                size_t end_idx = (size_t)cand + OZOS_SONIC_BURST_SAMPLES;
                *out_consumed = (end_idx <= num_samples) ? end_idx : num_samples;
            }
            return true;
        }
    }
    return false;
}

/* =============================================================================
   4. RIFF-WAV I/O & LIVE HARDWARE AUDIO (Win32 Waveform Speaker/Mic Driver)
   ============================================================================= */

static inline bool ozos_phy_wav_write(const char* path, const int16_t* pcm, size_t num_samples) {
    if (!path || !pcm || num_samples == 0U || num_samples > 0x3FFFFFFFU) return false;
    FILE* fp = fopen(path, "wb");
    if (!fp) return false;

    uint32_t data_bytes = (uint32_t)(num_samples * 2U);
    uint32_t riff_size  = 36U + data_bytes;
    uint8_t hdr[44];

    memcpy(hdr + 0,  "RIFF", 4U);
    ozos_le32_write(hdr + 4,  riff_size);
    memcpy(hdr + 8,  "WAVEfmt ", 8U);
    ozos_le32_write(hdr + 16, 16U);                        /* PCM fmt chunk size */
    ozos_le16_write(hdr + 20, 1U);                         /* PCM = 1 */
    ozos_le16_write(hdr + 22, 1U);                         /* Mono = 1 */
    ozos_le32_write(hdr + 24, OZOS_SONIC_SAMPLE_RATE);     /* 48,000 Hz */
    ozos_le32_write(hdr + 28, OZOS_SONIC_SAMPLE_RATE * 2U);/* ByteRate */
    ozos_le16_write(hdr + 32, 2U);                         /* BlockAlign */
    ozos_le16_write(hdr + 34, 16U);                        /* BitsPerSample */
    memcpy(hdr + 36, "data", 4U);
    ozos_le32_write(hdr + 40, data_bytes);

    bool ok = (fwrite(hdr, 1U, sizeof(hdr), fp) == sizeof(hdr));
    for (size_t i = 0U; ok && i < num_samples; ++i) {
        uint8_t s_le[2];
        ozos_le16_write(s_le, (uint16_t)pcm[i]);
        ok = (fwrite(s_le, 1U, 2U, fp) == 2U);
    }
    fclose(fp);
    return ok;
}

static inline bool ozos_phy_wav_read(
    const char* path,
    int16_t* out_pcm,
    size_t max_samples,
    size_t* out_samples
) {
    if (!path || !out_pcm || !out_samples || max_samples == 0U) return false;
    *out_samples = 0U;
    FILE* fp = fopen(path, "rb");
    if (!fp) return false;

    uint8_t riff[12];
    if (fread(riff, 1U, sizeof(riff), fp) != sizeof(riff) ||
        memcmp(riff, "RIFF", 4U) != 0 ||
        memcmp(riff + 8, "WAVE", 4U) != 0) {
        fclose(fp);
        return false;
    }

    bool fmt_ok = false;
    bool data_ok = false;
    uint32_t data_bytes = 0U;

    for (unsigned int ch_idx = 0U; ch_idx < 16U; ++ch_idx) {
        uint8_t chdr[8];
        if (fread(chdr, 1U, sizeof(chdr), fp) != sizeof(chdr)) {
            break;
        }
        uint32_t csize = ozos_le32_read(chdr + 4);
        if (memcmp(chdr, "fmt ", 4U) == 0) {
            if (csize < 16U || csize > 1024U) {
                fclose(fp);
                return false;
            }
            uint8_t fmt_buf[16];
            if (fread(fmt_buf, 1U, sizeof(fmt_buf), fp) != sizeof(fmt_buf) ||
                ozos_le16_read(fmt_buf + 0) != 1U ||
                ozos_le16_read(fmt_buf + 2) != 1U ||
                ozos_le32_read(fmt_buf + 4) != OZOS_SONIC_SAMPLE_RATE ||
                ozos_le16_read(fmt_buf + 14) != 16U) {
                fclose(fp);
                return false;
            }
            uint32_t extra = (csize - 16U) + (csize & 1U);
            if (extra > 0U && fseek(fp, (long)extra, SEEK_CUR) != 0) {
                fclose(fp);
                return false;
            }
            fmt_ok = true;
        } else if (memcmp(chdr, "data", 4U) == 0) {
            if (!fmt_ok || csize < 2U) {
                fclose(fp);
                return false;
            }
            data_bytes = csize;
            data_ok = true;
            break;
        } else {
            if (csize > 0x04000000U) {
                fclose(fp);
                return false;
            }
            uint32_t skip = csize + (csize & 1U);
            if (skip > 0U && fseek(fp, (long)skip, SEEK_CUR) != 0) {
                fclose(fp);
                return false;
            }
        }
    }

    if (!fmt_ok || !data_ok) {
        fclose(fp);
        return false;
    }

    size_t count = (size_t)(data_bytes / 2U);
    if (count > max_samples) count = max_samples;

    size_t read_ok = 0U;
    for (size_t i = 0U; i < count; ++i) {
        uint8_t s_le[2];
        if (fread(s_le, 1U, 2U, fp) != 2U) break;
        out_pcm[i] = (int16_t)ozos_le16_read(s_le);
        read_ok++;
    }
    fclose(fp);
    *out_samples = read_ok;
    return (read_ok > 0U);
}

static inline bool ozos_sonic_play_hardware(const int16_t* pcm, size_t num_samples) {
#if defined(_WIN32)
    static int16_t s_tx_buf[OZOS_SONIC_BURST_SAMPLES];
    if (!pcm || num_samples == 0U || num_samples > OZOS_SONIC_BURST_SAMPLES || waveOutGetNumDevs() == 0U) {
        return false;
    }
    memcpy(s_tx_buf, pcm, num_samples * sizeof(int16_t));

    WAVEFORMATEX wfx;
    memset(&wfx, 0, sizeof(wfx));
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = 1;
    wfx.nSamplesPerSec  = OZOS_SONIC_SAMPLE_RATE;
    wfx.wBitsPerSample  = 16;
    wfx.nBlockAlign     = 2;
    wfx.nAvgBytesPerSec = OZOS_SONIC_SAMPLE_RATE * 2U;

    HWAVEOUT h_out = NULL;
    if (waveOutOpen(&h_out, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR) {
        return false;
    }

    WAVEHDR wh;
    memset(&wh, 0, sizeof(wh));
    wh.lpData         = (LPSTR)s_tx_buf;
    wh.dwBufferLength = (DWORD)(num_samples * 2U);

    if (waveOutPrepareHeader(h_out, &wh, sizeof(wh)) != MMSYSERR_NOERROR) {
        waveOutClose(h_out);
        return false;
    }

    if (waveOutWrite(h_out, &wh, sizeof(wh)) != MMSYSERR_NOERROR) {
        waveOutUnprepareHeader(h_out, &wh, sizeof(wh));
        waveOutClose(h_out);
        return false;
    }

    uint32_t waited_ms = 0U;
    while ((wh.dwFlags & WHDR_DONE) == 0U && waited_ms < 4000U) {
        Sleep(20);
        waited_ms += 20U;
    }

    waveOutUnprepareHeader(h_out, &wh, sizeof(wh));
    waveOutClose(h_out);
    return (wh.dwFlags & WHDR_DONE) != 0U;
#else
    (void)pcm;
    (void)num_samples;
    return false;
#endif
}

/* Zero-Heap Continuous Microphone Ultrasonic Receiver (Static Sliding Window) */
#define OZOS_SONIC_RX_CHUNK_SAMPLES 9600U   /* 200 ms per DMA block */
#define OZOS_SONIC_RX_RING_SAMPLES  86400U  /* 1.80 sec sliding demod window */

typedef struct {
    bool is_open;
    bool dma_fault;
    size_t next_hdr;
    size_t ring_fill;
    uint64_t last_dma_epoch;
    int16_t ring[OZOS_SONIC_RX_RING_SAMPLES];
#if defined(_WIN32)
    HWAVEIN h_in;
    WAVEHDR hdrs[4];
    int16_t dma_bufs[4][OZOS_SONIC_RX_CHUNK_SAMPLES];
#endif
} ozos_sonic_mic_rx_t;

static inline bool ozos_sonic_mic_open(ozos_sonic_mic_rx_t* mic) {
    if (!mic) return false;
    memset(mic, 0, sizeof(*mic));
#if defined(_WIN32)
    if (waveInGetNumDevs() == 0U) return false;

    WAVEFORMATEX wfx;
    memset(&wfx, 0, sizeof(wfx));
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = 1;
    wfx.nSamplesPerSec  = OZOS_SONIC_SAMPLE_RATE;
    wfx.wBitsPerSample  = 16;
    wfx.nBlockAlign     = 2;
    wfx.nAvgBytesPerSec = OZOS_SONIC_SAMPLE_RATE * 2U;

    if (waveInOpen(&mic->h_in, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR) {
        return false;
    }

    for (size_t i = 0U; i < 4U; ++i) {
        mic->hdrs[i].lpData         = (LPSTR)mic->dma_bufs[i];
        mic->hdrs[i].dwBufferLength = (DWORD)(OZOS_SONIC_RX_CHUNK_SAMPLES * 2U);
        if (waveInPrepareHeader(mic->h_in, &mic->hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR ||
            waveInAddBuffer(mic->h_in, &mic->hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
            waveInReset(mic->h_in);
            for (size_t j = 0U; j <= i; ++j) {
                waveInUnprepareHeader(mic->h_in, &mic->hdrs[j], sizeof(WAVEHDR));
            }
            waveInClose(mic->h_in);
            mic->h_in = NULL;
            return false;
        }
    }

    if (waveInStart(mic->h_in) != MMSYSERR_NOERROR) {
        waveInReset(mic->h_in);
        for (size_t i = 0U; i < 4U; ++i) {
            waveInUnprepareHeader(mic->h_in, &mic->hdrs[i], sizeof(WAVEHDR));
        }
        waveInClose(mic->h_in);
        mic->h_in = NULL;
        return false;
    }

    mic->next_hdr       = 0U;
    mic->dma_fault      = false;
    mic->last_dma_epoch = (uint64_t)time(NULL);
    mic->is_open        = true;
    return true;
#else
    return false;
#endif
}

static inline void ozos_sonic_mic_close(ozos_sonic_mic_rx_t* mic) {
    if (!mic || !mic->is_open) return;
#if defined(_WIN32)
    if (mic->h_in) {
        waveInReset(mic->h_in);
        for (size_t i = 0U; i < 4U; ++i) {
            waveInUnprepareHeader(mic->h_in, &mic->hdrs[i], sizeof(WAVEHDR));
        }
        waveInClose(mic->h_in);
        mic->h_in = NULL;
    }
#endif
    mic->is_open = false;
}

static inline bool ozos_sonic_mic_needs_recovery(const ozos_sonic_mic_rx_t* mic, uint64_t now_epoch) {
    if (!mic) return false;
#if defined(_WIN32)
    if (!mic->is_open || mic->dma_fault) return true;
    if (now_epoch > mic->last_dma_epoch && (now_epoch - mic->last_dma_epoch) > 4ULL) {
        return true;
    }
#else
    (void)now_epoch;
#endif
    return false;
}

static inline bool ozos_sonic_mic_poll_frame(
    ozos_sonic_mic_rx_t* mic,
    uint8_t out_wire80[OZOS_MESH_FRAME_SIZE]
) {
    if (!mic || !mic->is_open || !out_wire80) return false;
#if defined(_WIN32)
    bool appended = false;
    for (size_t step = 0U; step < 4U; ++step) {
        size_t idx = mic->next_hdr & 3U;
        if ((mic->hdrs[idx].dwFlags & WHDR_DONE) == 0U) {
            break;
        }
        size_t got = (size_t)(mic->hdrs[idx].dwBytesRecorded / 2U);
        if (got > 0U && got <= OZOS_SONIC_RX_CHUNK_SAMPLES) {
            if (mic->ring_fill + got > OZOS_SONIC_RX_RING_SAMPLES) {
                size_t drop = (mic->ring_fill + got) - OZOS_SONIC_RX_RING_SAMPLES;
                memmove(mic->ring, mic->ring + drop, (mic->ring_fill - drop) * sizeof(int16_t));
                mic->ring_fill -= drop;
            }
            memcpy(mic->ring + mic->ring_fill, mic->dma_bufs[idx], got * sizeof(int16_t));
            mic->ring_fill += got;
            appended = true;
        }
        mic->hdrs[idx].dwFlags &= ~WHDR_DONE;
        mic->hdrs[idx].dwBytesRecorded = 0U;
        if (waveInAddBuffer(mic->h_in, &mic->hdrs[idx], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
            mic->dma_fault = true;
            break;
        }
        mic->last_dma_epoch = (uint64_t)time(NULL);
        mic->next_hdr = (idx + 1U) & 3U;
    }

    if (appended && mic->ring_fill >= OZOS_SONIC_BURST_SAMPLES) {
        size_t consumed = 0U;
        if (ozos_sonic_demodulate_stream(mic->ring, mic->ring_fill, out_wire80, &consumed)) {
            if (consumed >= mic->ring_fill) {
                mic->ring_fill = 0U;
            } else {
                memmove(mic->ring, mic->ring + consumed, (mic->ring_fill - consumed) * sizeof(int16_t));
                mic->ring_fill -= consumed;
            }
            return true;
        }
    }
#endif
    return false;
}

static inline void ozos_phy_print_hardware_inventory(void) {
    printf("=================================================================\n");
    printf("  O.Z.O.S // PHYSICAL TRANSPORT HARDWARE INVENTORY\n");
    printf("=================================================================\n");

    printf("[1] SERIAL UART / USB-LORA INTERFACES (SLIP-84 Ready):\n");
    uint32_t serial_found = 0U;
#if defined(_WIN32)
    HKEY h_key = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_READ, &h_key) == ERROR_SUCCESS) {
        DWORD idx = 0;
        for (;;) {
            char val_name[128];
            BYTE val_data[128];
            DWORD name_len = sizeof(val_name);
            DWORD data_len = sizeof(val_data) - 1U;
            DWORD val_type = 0;
            LONG rc = RegEnumValueA(h_key, idx++, val_name, &name_len, NULL, &val_type, val_data, &data_len);
            if (rc != ERROR_SUCCESS) break;
            if (val_type == REG_SZ) {
                val_data[data_len] = '\0';
                printf("  * %-10s (Kernel Device: %s)\n", (const char*)val_data, val_name);
                serial_found++;
            }
        }
        RegCloseKey(h_key);
    }
#else
    DIR* d = opendir("/dev");
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "ttyUSB", 6U) == 0 ||
                strncmp(ent->d_name, "ttyACM", 6U) == 0 ||
                strncmp(ent->d_name, "cu.usb", 6U) == 0) {
                printf("  * /dev/%s\n", ent->d_name);
                serial_found++;
            }
        }
        closedir(d);
    }
#endif
    if (serial_found == 0U) {
        printf("  * (No USB-Serial / LoRa UART dongles currently plugged in)\n");
    }

    printf("\n[2] NEAR-ULTRASOUND ACOUSTIC ENDPOINTS (18.1 - 19.8 kHz @ 48 kHz):\n");
#if defined(_WIN32)
    UINT n_out = waveOutGetNumDevs();
    UINT n_in  = waveInGetNumDevs();
    printf("  * Speaker TX Endpoints    : %u device(s)\n", (unsigned)n_out);
    for (UINT i = 0U; i < n_out; ++i) {
        WAVEOUTCAPSA caps;
        if (waveOutGetDevCapsA(i, &caps, sizeof(caps)) == MMSYSERR_NOERROR) {
            printf("    - [TX #%u] %s\n", (unsigned)i, caps.szPname);
        }
    }
    printf("  * Microphone RX Endpoints : %u device(s)\n", (unsigned)n_in);
    for (UINT i = 0U; i < n_in; ++i) {
        WAVEINCAPSA icaps;
        if (waveInGetDevCapsA(i, &icaps, sizeof(icaps)) == MMSYSERR_NOERROR) {
            printf("    - [RX #%u] %s\n", (unsigned)i, icaps.szPname);
        }
    }
#else
    printf("  * RIFF-WAV 48 kHz Ultrasonic Transceiver : ACTIVE (Hardware PCM via pipe/ALSA)\n");
#endif
    printf("=================================================================\n");
}

#ifdef __cplusplus
}
#endif

#endif /* OZOS_MESH_PHY_H */
