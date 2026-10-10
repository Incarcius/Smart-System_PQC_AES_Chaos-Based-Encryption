#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "aes_wrap.h"
#include "chaos_custom.h"

typedef struct {
    float   voltage;
    float   current;
    float   temperature;
    uint8_t relay_status;
} SensorPayload;

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-20s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02X ", data[i]);
    printf("\n");
}

size_t pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out) {
    size_t pad = 16 - (in_len % 16);
    memcpy(out, in, in_len);
    memset(out + in_len, (uint8_t)pad, pad);
    return in_len + pad;
}

size_t pkcs7_unpad(uint8_t *data, size_t len) {
    return len - data[len - 1];
}

int main(void) {

    // ── Store timestamp once — used by both sender and receiver ───────────
    uint64_t ts = (uint64_t)time(NULL) * 1000;

    // ── Session key (from Kyber+HKDF in real system) ──────────────────────
    uint8_t session_key[32] = {
        0xA1,0xB2,0xC3,0xD4, 0xE5,0xF6,0x07,0x18,
        0x29,0x3A,0x4B,0x5C, 0x6D,0x7E,0x8F,0x90,
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC, 0xDD,0xEE,0xFF,0x00
    };

    uint8_t iv[16] = {
        0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10
    };

    uint8_t prev_tail[8] = {0xDE,0xAD,0xBE,0xEF,0x01,0x23,0x45,0x67};

    // ── Build chaos context ────────────────────────────────────────────────
    ChaosContext ctx = {
        .session_key  = session_key,
        .counter      = 42,
        .timestamp    = ts,       // ← stored ts
        .prev_tail    = prev_tail,
        .anomaly_flag = 0
    };

    // ── Sensor reading ─────────────────────────────────────────────────────
    SensorPayload payload = {
        .voltage      = 231.4f,
        .current      = 4.72f,
        .temperature  = 38.5f,
        .relay_status = 1
    };

    printf("========= SENDER (RPi) =========\n");
    printf("Sensor: V=%.2f A=%.2f T=%.2f relay=%d | counter=%u anomaly=%d\n\n",
           payload.voltage, payload.current,
           payload.temperature, payload.relay_status,
           ctx.counter, ctx.anomaly_flag);

    // ── Serialize + pad ────────────────────────────────────────────────────
    uint8_t raw[sizeof(SensorPayload)];
    memcpy(raw, &payload, sizeof(SensorPayload));

    uint8_t padded[64];
    size_t padded_len = pkcs7_pad(raw, sizeof(SensorPayload), padded);

    // ── AES encrypt ────────────────────────────────────────────────────────
    uint8_t ciphertext[64];
    aes_encrypt(padded, padded_len, session_key, iv, ciphertext);
    print_hex("After AES", ciphertext, padded_len);

    // ── ACCM chaos mask ────────────────────────────────────────────────────
    uint8_t masked[64];
    accm_mask(&ctx, ciphertext, masked, padded_len);
    print_hex("After ACCM mask", masked, padded_len);

    // ── Update prev_tail for next message ──────────────────────────────────
    memcpy(prev_tail, masked + padded_len - 8, 8);

    // ── Simulate anomaly on next packet ───────────────────────────────────
    printf("\n--- Anomaly detected! Coupling strength shifts ---\n\n");
    ctx.anomaly_flag = 1;
    ctx.counter      = 43;
    ctx.timestamp    = ts + 100;  // 100ms later

    uint8_t masked_anomaly[64];
    accm_mask(&ctx, ciphertext, masked_anomaly, padded_len);
    print_hex("ACCM (anomaly=1)", masked_anomaly, padded_len);
    printf("(same AES ciphertext, completely different chaos stream)\n");

    // ── RECEIVER ──────────────────────────────────────────────────────────
    printf("\n========= RECEIVER (Laptop) =========\n");

    // Reset context to exactly match original sender state
    ctx.anomaly_flag = 0;
    ctx.counter      = 42;
    ctx.timestamp    = ts;        // ← same stored ts, not time(NULL) again
    memcpy(prev_tail, (uint8_t[]){0xDE,0xAD,0xBE,0xEF,0x01,0x23,0x45,0x67}, 8);
    ctx.prev_tail    = prev_tail;

    uint8_t unmasked[64];
    accm_unmask(&ctx, masked, unmasked, padded_len);
    print_hex("After unmask", unmasked, padded_len);

    uint8_t decrypted[64];
    aes_decrypt(unmasked, padded_len, session_key, iv, decrypted);

    size_t actual = pkcs7_unpad(decrypted, padded_len);

    SensorPayload recovered;
    memcpy(&recovered, decrypted, actual);
    printf("Recovered: V=%.2f A=%.2f T=%.2f relay=%d\n",
           recovered.voltage, recovered.current,
           recovered.temperature, recovered.relay_status);

    return 0;
}