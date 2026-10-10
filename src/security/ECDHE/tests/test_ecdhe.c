/*
 * test_ecdhe.c — host tests for the X25519 leaf key agreement.
 *
 * This module previously could not be built or tested anywhere: it included
 * ESP-IDF headers unconditionally, and it called a Monocypher 3.x API that
 * the vendored 4.0.2 does not provide. It compiled for the first time in the
 * 2026-09-12 pass, so everything here is a first-time verification rather
 * than a regression guard.
 *
 * Coverage:
 *   1. RFC 7748 §6.1 known-answer vector — proves this really is X25519 and
 *      that Monocypher's internal clamping does what the header claims.
 *   2. Random-keypair agreement — both sides derive the same secret.
 *   3. Low-order peer public keys are REJECTED. This is the security check
 *      that was previously a debug-build hang and a release-build silent
 *      success.
 *   4. hal_secure_wipe() actually clears.
 *
 * Build (from repo root, MSVC shell):
 *   cl /nologo /W3 /O2 /I src\security\ECDHE\include ^
 *      /I src\security\ECDHE\vendor\monocypher ^
 *      src\security\ECDHE\src\iiot_ecdhe.c src\security\ECDHE\src\hal_port.c ^
 *      src\security\ECDHE\vendor\monocypher\monocypher.c ^
 *      src\security\ECDHE\tests\test_ecdhe.c /Fe:test_ecdhe.exe
 */
#include <stdio.h>
#include <string.h>

#include "iiot_ecdhe.h"
#include "hal_port.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                       \
    ++g_checks;                                     \
    if (!(cond)) {                                  \
        ++g_failures;                               \
        printf("  [FAIL] %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__);                        \
        printf("\n");                               \
    }                                               \
} while (0)

static void put_hex(const char *label, const uint8_t *p, size_t n)
{
    printf("    %-14s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* ── RFC 7748 §6.1 ───────────────────────────────────────────────────────── */

static const uint8_t ALICE_SK[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d, 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a, 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
};
static const uint8_t ALICE_PK[32] = {
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54, 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4, 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
};
static const uint8_t BOB_SK[32] = {
    0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b, 0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
    0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd, 0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
};
static const uint8_t BOB_PK[32] = {
    0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4, 0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
    0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d, 0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
};
static const uint8_t SHARED[32] = {
    0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1, 0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
    0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33, 0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
};

static void test_rfc7748_vector(void)
{
    uint8_t secret_a[32], secret_b[32];

    printf("== RFC 7748 section 6.1 known-answer vector ==\n");

    CHECK(iiot_ecdhe_compute_shared_secret(secret_a, ALICE_SK, BOB_PK) == IIOT_ECDHE_OK,
          "alice x bob should succeed");
    CHECK(memcmp(secret_a, SHARED, 32) == 0, "alice's shared secret mismatch");

    CHECK(iiot_ecdhe_compute_shared_secret(secret_b, BOB_SK, ALICE_PK) == IIOT_ECDHE_OK,
          "bob x alice should succeed");
    CHECK(memcmp(secret_b, SHARED, 32) == 0, "bob's shared secret mismatch");

    if (memcmp(secret_a, SHARED, 32) != 0) {
        put_hex("expected", SHARED, 32);
        put_hex("got", secret_a, 32);
    }
}

static void test_generated_keypair_agrees(void)
{
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32];
    uint8_t s_a[32], s_b[32];

    printf("== generated keypairs agree ==\n");

    iiot_ecdhe_generate_keypair(pk_a, sk_a);
    iiot_ecdhe_generate_keypair(pk_b, sk_b);

    /* The TRNG must not be producing constants. */
    CHECK(memcmp(pk_a, pk_b, 32) != 0, "two keypairs must differ");
    CHECK(memcmp(sk_a, sk_b, 32) != 0, "two secret keys must differ");

    CHECK(iiot_ecdhe_compute_shared_secret(s_a, sk_a, pk_b) == IIOT_ECDHE_OK, "A x B");
    CHECK(iiot_ecdhe_compute_shared_secret(s_b, sk_b, pk_a) == IIOT_ECDHE_OK, "B x A");
    CHECK(memcmp(s_a, s_b, 32) == 0, "both sides must derive the same secret");
}

/* ── low-order points ────────────────────────────────────────────────────── */

/*
 * The small-subgroup points from RFC 7748 §6.1 / the classic contributory-
 * behaviour test set. Each drives X25519 to an all-zero output, meaning the
 * "shared secret" carries no contribution from our private key and is fully
 * known to whoever sent the point.
 */
static const uint8_t LOW_ORDER[][32] = {
    /* order 1: zero */
    {0},
    /* order 1: one */
    {0x01},
    /* order 8 */
    {0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae, 0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
     0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd, 0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00},
    /* order 4 */
    {0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24, 0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
     0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86, 0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57},
    /* p-1, order 2 */
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
};

static void test_low_order_rejected(void)
{
    uint8_t shared[32];
    size_t n = sizeof(LOW_ORDER) / sizeof(LOW_ORDER[0]);

    printf("== low-order peer public keys rejected (%zu points) ==\n", n);

    for (size_t i = 0; i < n; i++) {
        memset(shared, 0xAA, sizeof(shared));

        iiot_ecdhe_status_t rc =
            iiot_ecdhe_compute_shared_secret(shared, ALICE_SK, LOW_ORDER[i]);

        CHECK(rc == IIOT_ECDHE_ERR_LOW_ORDER_POINT,
              "point %zu must be rejected, got %d", i, (int)rc);

        /* The output must be wiped, not left holding 0xAA or a usable value. */
        int all_zero = 1;
        for (size_t b = 0; b < 32; b++) if (shared[b] != 0) { all_zero = 0; break; }
        CHECK(all_zero, "point %zu: output must be wiped on rejection", i);
    }
}

static void test_param_validation(void)
{
    uint8_t shared[32], sk[32], pk[32];

    printf("== parameter validation ==\n");
    memset(sk, 1, sizeof(sk));
    memset(pk, 2, sizeof(pk));

    CHECK(iiot_ecdhe_compute_shared_secret(NULL, sk, pk) == IIOT_ECDHE_ERR_BAD_PARAM,
          "NULL shared_secret");
    CHECK(iiot_ecdhe_compute_shared_secret(shared, NULL, pk) == IIOT_ECDHE_ERR_BAD_PARAM,
          "NULL secret key");
    CHECK(iiot_ecdhe_compute_shared_secret(shared, sk, NULL) == IIOT_ECDHE_ERR_BAD_PARAM,
          "NULL peer public key");
}

static void test_wipe(void)
{
    uint8_t secret[32];
    int all_zero = 1;

    printf("== secure wipe ==\n");
    memset(secret, 0x5A, sizeof(secret));
    iiot_ecdhe_wipe_secret(secret);

    for (size_t i = 0; i < sizeof(secret); i++)
        if (secret[i] != 0) { all_zero = 0; break; }

    CHECK(all_zero, "wipe must clear the buffer");
}

int main(void)
{
    printf("=== X25519 ECDHE (leaf tier) tests ===\n");
    printf("    monotonic clock reads %lld us\n", (long long)hal_get_time_us());

    test_rfc7748_vector();
    test_generated_keypair_agrees();
    test_low_order_rejected();
    test_param_validation();
    test_wipe();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
