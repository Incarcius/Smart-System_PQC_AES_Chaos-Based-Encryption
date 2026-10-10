/*
 * accm.c — ACCM v2 implementation. Integer-only; see accm.h for rationale.
 *
 * Keystream construction
 * ======================
 *
 *   hdr    = tg_header_serialize(header)                       24 B
 *   ctxbuf = hdr || prev_tail                                  32 B
 *
 *   seed   = KMACXOF256(session_key, ctxbuf, "ACCM-v2/lorenz-seed", 12)
 *   L      = lorenz_q16(seed, 500 steps)                       3 x int64
 *   expand = ctxbuf || L_be                                    56 B
 *   params = KMACXOF256(session_key, expand, "ACCM-v2/params", 20)
 *
 *   per chunk k of <= ACCM_CHUNK bytes:
 *     base = KMACXOF256(session_key, expand || be32(k), "ACCM-v2/stream", n)
 *     per byte:
 *       lx = R1 * X * (1 - X)               (Q32)
 *       ly = R2 * Y * (1 - Y)               (Q32)
 *       X' = (1-eps)*lx + eps*ly
 *       Y' = (1-eps)*ly + eps*lx
 *       stream[i] = base[i] XOR fold(X', Y')
 *
 * Why the base stream is there
 * ============================
 * The chaotic map alone does NOT produce a uniform keystream, and no amount
 * of parameter tuning makes it one. Measured over random key-derived
 * parameters (src/security/ACCM/tests/accm_stats.py, and the sweep recorded
 * in docs/PROJECT_STATUS.md):
 *
 *   - taking the top byte of each state and XORing them, as v1 did, produced
 *     entropy below 7.99 bits/byte in 100% of draws. At eps = 0.4 the two
 *     states synchronise and that XOR collapses toward zero -- 3.26 bits/byte
 *     with one value taking 36% of the output. The anomaly posture, the case
 *     that matters most, degraded the mask to almost nothing;
 *   - folding all fraction bytes instead: still 20-60% of draws below 7.99;
 *   - restricting r to Lyapunov-verified chaotic values: no better;
 *   - widening the state to Q64 to rule out fixed-point cycle shortening:
 *     no better.
 *
 * So the map is treated as what it is -- a source of adaptive, key-dependent
 * structure, not a CSPRNG. XORing it over a KMACXOF256 base stream makes the
 * result uniform by construction: XORing a uniform stream with anything
 * independent of it stays uniform, so the floor of this layer is exactly
 * KMACXOF256, whatever the map does. The chaotic component can only add, and
 * the posture still changes the stream in a way nobody can predict without
 * the session key.
 *
 * This is the same "can only add, never subtract" discipline used for the
 * Lorenz stage, which is folded back through KMAC rather than used directly.
 */
#include "accm.h"
#include "kmac.h"
#include <string.h>

/* ── Q32 fixed point for the coupled logistic pair ───────────────────────── */

#define Q32_ONE     ((uint64_t)1 << 32)
#define Q32_MARGIN  ((uint64_t)1 << 20)   /* ~0.00024 away from 0 and 1 */

/*
 * (a * b) >> 32 with a < 2^32 and b <= 2^32.
 * Max product is (2^32 - 1) * 2^32 < 2^64, so this cannot overflow uint64.
 */
static uint64_t mul_q32(uint64_t a, uint64_t b)
{
    return (a * b) >> 32;
}

/* ── Q30 rate parameters, r in [3.57, 3.999] ─────────────────────────────── */

/* round(3.570 * 2^30) */
#define R_MIN_Q30   ((uint64_t)3833258313u)
/* round(0.429 * 2^30) -- so r_max = 3.999 */
#define R_SPAN_Q30  ((uint64_t)460635243u)

static uint64_t rate_from_u16(uint16_t v)
{
    /* v * R_SPAN_Q30 <= 65535 * 4.6e8 ~= 3.0e13, well inside uint64. */
    return R_MIN_Q30 + (v * R_SPAN_Q30) / 65535u;
}

/*
 * logistic(r, x) = r * x * (1 - x), all Q32 except r which is Q30.
 *
 *   t  = x*(1-x) >> 32  ->  t <= 2^30      (max 0.25 at x = 0.5)
 *   lx = (r_q30 * t) >> 30
 *        r_q30 < 2^32 and t <= 2^30, so the product is <= ~4.6e18 < 2^64.
 */
static uint64_t logistic_q32(uint64_t r_q30, uint64_t x)
{
    uint64_t t = mul_q32(x, Q32_ONE - x);
    return (r_q30 * t) >> 30;
}

static uint64_t clamp_state(uint64_t x)
{
    if (x < Q32_MARGIN)            return Q32_MARGIN;
    if (x > Q32_ONE - Q32_MARGIN)  return Q32_ONE - Q32_MARGIN;
    return x;
}

/*
 * Fold every fraction byte of both states into one output byte, with the two
 * states sampled at different bit offsets.
 *
 * The offsets matter: v1 XORed the SAME slice of x and y, so whenever strong
 * coupling drove x toward y the output collapsed to zero. Different offsets
 * mean synchronisation no longer cancels.
 */
static uint8_t accm_extract(uint64_t x, uint64_t y)
{
    uint64_t v = x ^ (y << 7) ^ (x >> 13) ^ (y >> 19);
    return (uint8_t)(v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24));
}

/*
 * Integer literals rather than (uint64_t)(0.10 * 2^32): the whole module is
 * deliberately float-free, and a constant that depends on the compiler's
 * double rounding would reintroduce exactly the portability hazard this
 * rewrite exists to remove.
 *
 *   NORMAL     eps = 0.10  ->  429496729
 *   SUSPICIOUS eps = 0.25  -> 1073741824
 *   ANOMALY    eps = 0.40  -> 1717986918
 */
uint64_t accm_epsilon_q32(uint8_t posture)
{
    switch (posture) {
    case TG_POSTURE_SUSPICIOUS: return (uint64_t)1073741824u;
    case TG_POSTURE_ANOMALY:    return (uint64_t)1717986918u;
    case TG_POSTURE_NORMAL:
    default:                    return (uint64_t)429496729u;
    }
}

/* ── Q16 fixed-point Lorenz ──────────────────────────────────────────────── */

#define L_SHIFT      16
#define L_ONE        ((int64_t)1 << L_SHIFT)
#define L_CLAMP      ((int64_t)64 << L_SHIFT)     /* |state| <= 64.0 */
#define L_SIGMA_DT   ((int64_t)6554)              /* round(0.1   * 2^16) */
#define L_RHO        ((int64_t)28 * L_ONE)        /* 28.0                */
#define L_BETA_DT    ((int64_t)1748)              /* round(8/3*0.01*2^16)*/
#define L_DT         ((int64_t)655)               /* round(0.01  * 2^16) */
#define L_STEPS      500

/*
 * Arithmetic right shift of a negative int64 is implementation-defined in
 * ISO C, but every compiler this project targets (MSVC, GCC, Clang, xtensa
 * GCC) implements it as a floor shift, matching Python's >>. The
 * cross-language KAT in tests/ fails loudly if that ever stops holding.
 */
static int64_t l_clamp(int64_t v)
{
    if (v >  L_CLAMP) return  L_CLAMP;
    if (v < -L_CLAMP) return -L_CLAMP;
    return v;
}

/*
 * Euler integration of the Lorenz system in Q16.
 *
 * Bounds: |state| <= 64.0 = 2^22 in Q16 units, so the largest intermediate
 * product (x * (rho - z)) is under 2^22 * 2^23 = 2^45 -- far inside int64.
 */
static void lorenz_q16(const uint8_t seed[12], int64_t out[3])
{
    int64_t x, y, z;
    int     i;

    /* seed -> initial state. x,y in (-10,10); z in (0,30), in Q16. */
    {
        uint32_t rx = ((uint32_t)seed[0] << 24) | ((uint32_t)seed[1] << 16)
                    | ((uint32_t)seed[2] << 8)  |  (uint32_t)seed[3];
        uint32_t ry = ((uint32_t)seed[4] << 24) | ((uint32_t)seed[5] << 16)
                    | ((uint32_t)seed[6] << 8)  |  (uint32_t)seed[7];
        uint32_t rz = ((uint32_t)seed[8] << 24) | ((uint32_t)seed[9] << 16)
                    | ((uint32_t)seed[10] << 8) |  (uint32_t)seed[11];

        x = (int64_t)(rx % (20u * (uint32_t)L_ONE)) - 10 * L_ONE;
        y = (int64_t)(ry % (20u * (uint32_t)L_ONE)) - 10 * L_ONE;
        z = (int64_t)(rz % (30u * (uint32_t)L_ONE));
    }

    for (i = 0; i < L_STEPS; i++) {
        int64_t dx = (L_SIGMA_DT * (y - x)) >> L_SHIFT;
        int64_t dy = ((((x * (L_RHO - z)) >> L_SHIFT) - y) * L_DT) >> L_SHIFT;
        int64_t dz = (((x * y) >> L_SHIFT) * L_DT >> L_SHIFT)
                   - ((L_BETA_DT * z) >> L_SHIFT);

        x = l_clamp(x + dx);
        y = l_clamp(y + dy);
        z = l_clamp(z + dz);
    }

    out[0] = x;
    out[1] = y;
    out[2] = z;
}

/* ── parameter derivation ────────────────────────────────────────────────── */

#define ACCM_CTXBUF_LEN  (TG_HEADER_LEN + ACCM_TAIL_LEN)   /* 32 */
#define ACCM_EXPAND_LEN  (ACCM_CTXBUF_LEN + 24)            /* 56 */
#define ACCM_CHUNK       256                               /* base-stream block */

static const char CUSTOM_SEED[]   = "ACCM-v2/lorenz-seed";
static const char CUSTOM_PARAMS[] = "ACCM-v2/params";
static const char CUSTOM_STREAM[] = "ACCM-v2/stream";

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void put_be64_signed(uint8_t *p, int64_t v)
{
    uint64_t u = (uint64_t)v;      /* two's complement, well-defined */
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(u >> (56 - 8 * i));
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/* Rolling generator state for one frame. */
typedef struct {
    const uint8_t *key;
    uint8_t        expand[ACCM_EXPAND_LEN];
    uint64_t       x, y;          /* Q32 */
    uint64_t       r1, r2;        /* Q30 */
    uint64_t       eps, ome;      /* Q32 */
} accm_gen_t;

static void gen_init(const accm_ctx_t *ctx, accm_gen_t *g)
{
    uint8_t ctxbuf[ACCM_CTXBUF_LEN];
    uint8_t seed[12];
    uint8_t params[20];
    int64_t lorenz[3];
    int     i;

    tg_header_serialize(&ctx->header, ctxbuf);
    memcpy(ctxbuf + TG_HEADER_LEN, ctx->prev_tail, ACCM_TAIL_LEN);

    /* Stage 1: seed the Lorenz stage from the full session key + context. */
    kmacxof256(ctx->session_key, ACCM_KEY_LEN,
               ctxbuf, sizeof(ctxbuf),
               (const uint8_t *)CUSTOM_SEED, sizeof(CUSTOM_SEED) - 1,
               seed, sizeof(seed));

    lorenz_q16(seed, lorenz);

    /* Stage 2: fold the Lorenz state back through KMAC. Folding rather than
     * using the orbit directly is what makes the Lorenz stage unable to
     * weaken the result -- the output is 256-bit-strong regardless. */
    g->key = ctx->session_key;
    memcpy(g->expand, ctxbuf, sizeof(ctxbuf));
    for (i = 0; i < 3; i++)
        put_be64_signed(g->expand + sizeof(ctxbuf) + 8 * i, lorenz[i]);

    kmacxof256(ctx->session_key, ACCM_KEY_LEN,
               g->expand, ACCM_EXPAND_LEN,
               (const uint8_t *)CUSTOM_PARAMS, sizeof(CUSTOM_PARAMS) - 1,
               params, sizeof(params));

    g->x   = clamp_state(be64(params)      % Q32_ONE);
    g->y   = clamp_state(be64(params + 8)  % Q32_ONE);
    g->r1  = rate_from_u16((uint16_t)(((uint16_t)params[16] << 8) | params[17]));
    g->r2  = rate_from_u16((uint16_t)(((uint16_t)params[18] << 8) | params[19]));
    g->eps = accm_epsilon_q32(ctx->header.posture);
    g->ome = Q32_ONE - g->eps;
}

/* Fill `base` with chunk `index` of the KMACXOF256 base stream. */
static void gen_base_chunk(const accm_gen_t *g, uint32_t index,
                           uint8_t *base, size_t n)
{
    uint8_t data[ACCM_EXPAND_LEN + 4];

    memcpy(data, g->expand, ACCM_EXPAND_LEN);
    put_be32(data + ACCM_EXPAND_LEN, index);

    kmacxof256(g->key, ACCM_KEY_LEN,
               data, sizeof(data),
               (const uint8_t *)CUSTOM_STREAM, sizeof(CUSTOM_STREAM) - 1,
               base, n);
}

/* Advance the coupled map one step and return the chaotic byte. */
static uint8_t gen_chaos_byte(accm_gen_t *g)
{
    uint64_t lx = logistic_q32(g->r1, g->x);
    uint64_t ly = logistic_q32(g->r2, g->y);

    /* Convex combination: each term is < 2^32 and the weights sum to 1,
     * so the sum stays inside the Q32 range. */
    uint64_t xn = mul_q32(g->ome, lx) + mul_q32(g->eps, ly);
    uint64_t yn = mul_q32(g->ome, ly) + mul_q32(g->eps, lx);

    g->x = clamp_state(xn);
    g->y = clamp_state(yn);

    return accm_extract(g->x, g->y);
}

/*
 * Core: XOR `len` keystream bytes over `in` into `out`. `in` may be NULL, in
 * which case the raw keystream is written (used by accm_generate_stream).
 */
static void accm_apply(const accm_ctx_t *ctx,
                       const uint8_t *in, uint8_t *out, size_t len)
{
    accm_gen_t g;
    uint8_t    base[ACCM_CHUNK];
    uint32_t   chunk = 0;
    size_t     done = 0;

    gen_init(ctx, &g);

    while (done < len) {
        size_t n = len - done;
        size_t i;

        if (n > ACCM_CHUNK) n = ACCM_CHUNK;
        gen_base_chunk(&g, chunk, base, n);

        for (i = 0; i < n; i++) {
            uint8_t ks = base[i] ^ gen_chaos_byte(&g);
            out[done + i] = in ? (uint8_t)(in[done + i] ^ ks) : ks;
        }

        done += n;
        chunk++;
    }

    /* Do not leave a frame's base stream on the stack. */
    memset(base, 0, sizeof(base));
    memset(&g, 0, sizeof(g));
}

/* ── public API ──────────────────────────────────────────────────────────── */

void accm_init(accm_ctx_t *ctx,
               const uint8_t session_key[ACCM_KEY_LEN],
               const tg_header_t *header,
               const uint8_t prev_tail[ACCM_TAIL_LEN])
{
    ctx->session_key = session_key;
    ctx->header      = *header;
    if (prev_tail) memcpy(ctx->prev_tail, prev_tail, ACCM_TAIL_LEN);
    else           memset(ctx->prev_tail, 0, ACCM_TAIL_LEN);
}

void accm_generate_stream(const accm_ctx_t *ctx, uint8_t *stream, size_t len)
{
    accm_apply(ctx, NULL, stream, len);
}

void accm_mask(const accm_ctx_t *ctx,
               const uint8_t *in, uint8_t *out, size_t len)
{
    accm_apply(ctx, in, out, len);
}

void accm_unmask(const accm_ctx_t *ctx,
                 const uint8_t *in, uint8_t *out, size_t len)
{
    accm_apply(ctx, in, out, len);
}

void accm_chain_update(accm_ctx_t *ctx, const uint8_t *masked, size_t len)
{
    if (len >= ACCM_TAIL_LEN) {
        memcpy(ctx->prev_tail, masked + len - ACCM_TAIL_LEN, ACCM_TAIL_LEN);
    } else {
        memset(ctx->prev_tail, 0, ACCM_TAIL_LEN);
        if (len) memcpy(ctx->prev_tail + ACCM_TAIL_LEN - len, masked, len);
    }
}
