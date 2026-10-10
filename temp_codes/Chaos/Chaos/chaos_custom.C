#include <string.h>
#include <math.h>
#include <stdint.h>
#include "chaos_custom.h"

// ─── LORENZ ──────────────────────────────────────────────────────────────────

typedef struct { double x, y, z; } Lorenz3D;

static Lorenz3D lorenz_step(Lorenz3D s, double dt) {
    double sigma = 10.0, rho = 28.0, beta = 8.0 / 3.0;
    return (Lorenz3D){
        .x = s.x + dt * sigma * (s.y - s.x),
        .y = s.y + dt * (s.x * (rho - s.z) - s.y),
        .z = s.z + dt * (s.x * s.y - beta * s.z)
    };
}

// Derive x0 and y0 from all five inputs via Lorenz
static void lorenz_derive_seeds(const ChaosContext *ctx,
                                double *out_x0, double *out_y0) {

    // Step 1: Combine all inputs into 8 bytes via XOR
    uint8_t combined[8];
    memcpy(combined, ctx->session_key, 8);

    // XOR in counter (4 bytes)
    uint8_t counter_bytes[4];
    memcpy(counter_bytes, &ctx->counter, 4);
    for (int i = 0; i < 4; i++)
        combined[i] ^= counter_bytes[i];

    // XOR in timestamp (8 bytes)
    uint8_t ts_bytes[8];
    memcpy(ts_bytes, &ctx->timestamp, 8);
    for (int i = 0; i < 8; i++)
        combined[i] ^= ts_bytes[i];

    // XOR in prev_tail (8 bytes)
    for (int i = 0; i < 8; i++)
        combined[i] ^= ctx->prev_tail[i];

    // Step 2: Map combined bytes to Lorenz initial (x, y, z)
    uint16_t raw_x, raw_y, raw_z;
    memcpy(&raw_x, combined + 0, 2);
    memcpy(&raw_y, combined + 2, 2);
    memcpy(&raw_z, combined + 4, 2);

    Lorenz3D s = {
        .x = (double)raw_x / 65535.0 * 20.0 - 10.0,   // (-10, 10)
        .y = (double)raw_y / 65535.0 * 20.0 - 10.0,   // (-10, 10)
        .z = (double)raw_z / 65535.0 * 30.0            // (0, 30)
    };

    // Step 3: Run 500 Lorenz steps — get deep into chaotic regime
    for (int i = 0; i < 500; i++)
        s = lorenz_step(s, 0.01);

    // Step 4: Extract x and y, normalize to (0, 1)
    double seed_x = (s.x + 20.0) / 40.0;
    double seed_y = (s.y + 20.0) / 40.0;

    // Guard fixed point collapse
    if (seed_x < 1e-10 || seed_x > 1.0 - 1e-10) seed_x = 0.3141;
    if (seed_y < 1e-10 || seed_y > 1.0 - 1e-10) seed_y = 0.2718;

    *out_x0 = seed_x;
    *out_y0 = seed_y;
}

// ─── ACCM: Adaptive Coupled Chaotic Map ──────────────────────────────────────

// Derive r1 and r2 from session key — each session gets unique chaotic rates
// Both must stay in (3.57, 4.0) to remain in chaotic regime
static void derive_r_values(const uint8_t *session_key,
                            double *r1, double *r2) {
    // Use bytes 8 and 9 of session key (not used in Lorenz seeding)
    uint8_t b1 = session_key[8];
    uint8_t b2 = session_key[9];

    // Map (0, 255) → (3.57, 4.0)
    // Range = 0.43, so: 3.57 + (byte/255.0) * 0.43
    *r1 = 3.57 + ((double)b1 / 255.0) * 0.43;
    *r2 = 3.57 + ((double)b2 / 255.0) * 0.43;
}

void accm_generate_stream(const ChaosContext *ctx,
                          uint8_t *stream, size_t len) {

    // Step 1: Get seeds from Lorenz
    double x, y;
    lorenz_derive_seeds(ctx, &x, &y);

    // Step 2: Get key-derived r values
    double r1, r2;
    derive_r_values(ctx->session_key, &r1, &r2);

    // Step 3: Set coupling strength based on anomaly flag
    // Normal:  ε = 0.1 → x and y weakly coupled
    // Anomaly: ε = 0.4 → x and y strongly coupled, different attractor
    double eps = ctx->anomaly_flag ? 0.4 : 0.1;

    // Step 4: Run ACCM to generate stream
    for (size_t i = 0; i < len; i++) {

        double lx = r1 * x * (1.0 - x);   // logistic term for x
        double ly = r2 * y * (1.0 - y);   // logistic term for y

        // Coupled update — each variable pulls the other
        double x_next = (1.0 - eps) * lx + eps * ly;
        double y_next = (1.0 - eps) * ly + eps * lx;

        x = x_next;
        y = y_next;

        // Guard fixed point collapse
        if (x < 1e-10 || x > 1.0 - 1e-10) x = 0.3141;
        if (y < 1e-10 || y > 1.0 - 1e-10) y = 0.2718;

        // XOR both variables → each byte depends on both states
        uint8_t bx = (uint8_t)(x * 256.0);
        uint8_t by = (uint8_t)(y * 256.0);
        stream[i] = bx ^ by;
    }
}

// ─── MASK / UNMASK ───────────────────────────────────────────────────────────

void accm_mask(const ChaosContext *ctx,
               const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t stream[len];
    accm_generate_stream(ctx, stream, len);
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ stream[i];
}

void accm_unmask(const ChaosContext *ctx,
                 const uint8_t *in, uint8_t *out, size_t len) {
    // XOR is self-inverse — identical to mask
    accm_mask(ctx, in, out, len);
}