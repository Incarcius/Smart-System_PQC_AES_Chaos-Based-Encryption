/*
 * node_main.c — leaf firmware entry point.
 *
 * Boot, handshake, then sample-encrypt-send at 10 Hz forever.
 *
 * ⚠ Not yet run on hardware. Every layer it calls is host-tested (114 checks);
 * what is unverified is this orchestration and the ESP-IDF calls.
 *
 *
 * Boot ordering — three constraints that are not interchangeable
 * =============================================================
 *
 *  1. **Epoch before encryption.** node_nonce_boot() increments and commits
 *     the persisted key_epoch before any frame is sealed. seq restarts at 0
 *     every boot, so without this a rebooted node reusing a session key would
 *     re-emit nonces it has already used. GCM nonce reuse is total failure,
 *     not degradation.
 *
 *  2. **RF before key generation.** The ESP32 TRNG is only fully entropic
 *     while the RF subsystem is running. Generating the ECDHE keypair before
 *     WiFi is up yields a low-entropy private key — a weakness that leaves no
 *     trace and that no test downstream can detect.
 *
 *  3. **Handshake before sampling.** No session key, nothing to seal with.
 *
 * The PSK is read from NVS, where it is written once during factory
 * provisioning. It is never transmitted and never leaves the device.
 */
#include "channel.h"
#include "cobs.h"
#include "node_frame.h"
#include "node_session.h"
#include "node_storage.h"
#include "aead_iface.h"

#ifdef ESP_PLATFORM

#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

#include <string.h>

static const char *TAG = "leaf";

#define UART_PORT        UART_NUM_1
#define UART_TX_PIN      17
#define UART_RX_PIN      16
#define UART_BAUD        115200
#define UART_BUF_SIZE    1024

#define ENDPOINT_ID      0x0001
#define SAMPLE_PERIOD_MS 100        /* 10 Hz */
#define HANDSHAKE_TIMEOUT_MS 2000

static uint8_t g_psk[NODE_PSK_LEN];
static node_session_t     g_session;
static node_nonce_guard_t g_guard;

/* ── UART framing ────────────────────────────────────────────────────────── */

static void uart_setup(void)
{
    uart_config_t cfg = {
        .baud_rate = UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, UART_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, UART_TX_PIN, UART_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
}

/* COBS-encode and write, terminated by the 0x00 delimiter. */
static void uart_send_framed(const uint8_t *buf, size_t len)
{
    uint8_t wire[COBS_ENCODED_MAX(LEAF_FRAME_MAX) + 1];
    size_t  n = cobs_encode(buf, len, wire);

    wire[n++] = 0x00;
    uart_write_bytes(UART_PORT, (const char *)wire, n);
}

/*
 * Read one delimiter-terminated frame and COBS-decode it.
 * Returns the decoded length, or -1 on timeout or a malformed frame.
 */
static long uart_recv_framed(uint8_t *out, size_t out_cap, int timeout_ms)
{
    uint8_t wire[COBS_ENCODED_MAX(LEAF_FRAME_MAX) + 1];
    size_t  n = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (esp_timer_get_time() < deadline) {
        uint8_t b;
        int got = uart_read_bytes(UART_PORT, &b, 1, pdMS_TO_TICKS(10));

        if (got != 1) continue;

        if (b == 0x00) {
            if (n == 0) continue;              /* leading or doubled delimiter */
            {
                long dec = cobs_decode(wire, n, out);
                n = 0;
                if (dec > 0 && (size_t)dec <= out_cap) return dec;
                /* Malformed: drop it and resync at the next delimiter. This
                 * is the property COBS was chosen for. */
                continue;
            }
        }

        if (n < sizeof(wire)) {
            wire[n++] = b;
        } else {
            n = 0;    /* overlong frame — drop and resync */
        }
    }
    return -1;
}

/* ── provisioning ────────────────────────────────────────────────────────── */

static int load_psk(void)
{
    nvs_handle_t h;
    size_t len = NODE_PSK_LEN;

    if (nvs_open("iiot_node", NVS_READONLY, &h) != ESP_OK) return -1;
    if (nvs_get_blob(h, "device_psk", g_psk, &len) != ESP_OK || len != NODE_PSK_LEN) {
        nvs_close(h);
        return -1;
    }
    nvs_close(h);
    return 0;
}

/* ── handshake ───────────────────────────────────────────────────────────── */

static int do_handshake(void)
{
    node_handshake_ctx_t ctx;
    uint8_t hello[NODE_HELLO_LEN];
    uint8_t ack[NODE_HELLO_ACK_LEN];
    uint8_t confirm[NODE_CONFIRM_LEN];
    uint8_t rx[LEAF_FRAME_MAX];
    long    n;

    if (node_handshake_start(&ctx, ENDPOINT_ID, g_guard.key_epoch, hello)
        != NODE_SESSION_OK) {
        ESP_LOGE(TAG, "handshake start failed");
        return -1;
    }
    uart_send_framed(hello, sizeof(hello));

    n = uart_recv_framed(rx, sizeof(rx), HANDSHAKE_TIMEOUT_MS);
    if (n != NODE_HELLO_ACK_LEN) {
        ESP_LOGW(TAG, "no HELLO_ACK (got %ld)", n);
        return -1;
    }
    memcpy(ack, rx, NODE_HELLO_ACK_LEN);

    if (node_handshake_finish(&ctx, g_psk, ack, &g_session, confirm)
        != NODE_SESSION_OK) {
        /*
         * Either the gateway does not hold this node's PSK, or something is
         * relaying between us. Both mean: do not send telemetry. Retrying is
         * correct — a MITM cannot ever succeed without the PSK, so the retry
         * loop is not a vulnerability, just a stalled node.
         */
        ESP_LOGE(TAG, "handshake failed - wrong PSK or MITM");
        return -1;
    }
    uart_send_framed(confirm, sizeof(confirm));

    ESP_LOGI(TAG, "session established, epoch %u", (unsigned)g_guard.key_epoch);
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

void app_main(void)
{
    channel_reading_t readings[NODE_MAX_CHANNELS];
    uint8_t frame[LEAF_FRAME_MAX];
    leaf_header_t h;

    ESP_LOGI(TAG, "leaf node starting");

    /* 1. Persistence, then the epoch bump. Before anything encrypts. */
    if (node_storage_init() != STORAGE_OK) {
        ESP_LOGE(TAG, "storage init failed - refusing to run");
        return;
    }
    if (node_nonce_boot(&g_guard) != NODE_SESSION_OK) {
        ESP_LOGE(TAG, "nonce guard failed - refusing to run without a fresh epoch");
        return;
    }

    if (load_psk() != 0) {
        ESP_LOGE(TAG, "no device PSK provisioned - refusing to run");
        return;
    }

    /*
     * 2. RF up before any key generation. Not optional: see the header note.
     * Even without an association, enabling the radio is what makes the TRNG
     * fully entropic.
     */
    ESP_ERROR_CHECK(esp_wifi_start());
    vTaskDelay(pdMS_TO_TICKS(100));

    uart_setup();
    aead_init();
    sensor_hal_init(NODE_CHANNELS, NODE_CHANNEL_COUNT);

    /* 3. Handshake, retrying until the gateway answers. */
    while (do_handshake() != 0) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    h.version       = LEAF_PROTO_VERSION;
    h.channel_count = (uint8_t)NODE_CHANNEL_COUNT;
    h.endpoint_id   = ENDPOINT_ID;

    for (;;) {
        TickType_t wake = xTaskGetTickCount();
        uint64_t   seq;
        long       flen;

        node_session_status_t st = node_nonce_next(&g_guard, &seq);
        if (st == NODE_SESSION_EXHAUSTED) {
            /*
             * The seq space for this epoch is spent. Rekey rather than wrap:
             * a fresh epoch means a fresh nonce space, and re-running the
             * handshake gives a fresh session key to go with it.
             */
            ESP_LOGW(TAG, "epoch exhausted, rekeying");
            node_session_wipe(&g_session);
            if (node_nonce_rekey(&g_guard) != NODE_SESSION_OK) {
                ESP_LOGE(TAG, "rekey failed - halting rather than reusing a nonce");
                return;
            }
            while (do_handshake() != 0) vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, readings);

        h.key_epoch = g_guard.key_epoch;
        h.seq       = seq;

        flen = tg_leaf_frame_seal(g_session.session_key, &h,
                                  (uint64_t)(esp_timer_get_time() / 1000),
                                  readings, NODE_CHANNEL_COUNT,
                                  frame, sizeof(frame));
        if (flen > 0) {
            uart_send_framed(frame, (size_t)flen);
        } else {
            ESP_LOGE(TAG, "seal failed: %ld", flen);
        }

        vTaskDelayUntil(&wake, pdMS_TO_TICKS(SAMPLE_PERIOD_MS));
    }
}

#endif /* ESP_PLATFORM */
