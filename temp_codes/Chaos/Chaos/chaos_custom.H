#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *session_key;    // 32 bytes
    uint32_t       counter;        // message sequence number
    uint64_t       timestamp;      // unix timestamp ms
    const uint8_t *prev_tail;      // last 8 bytes of previous masked output
    uint8_t        anomaly_flag;   // 0 = normal, 1 = anomaly detected
} ChaosContext;

void accm_generate_stream(const ChaosContext *ctx, uint8_t *stream, size_t len);
void accm_mask  (const ChaosContext *ctx, const uint8_t *in, uint8_t *out, size_t len);
void accm_unmask(const ChaosContext *ctx, const uint8_t *in, uint8_t *out, size_t len);