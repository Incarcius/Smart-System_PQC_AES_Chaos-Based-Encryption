
#include <stdio.h>
#include <string.h>

#include "aead_iface.h"
#include "aead_backend_select.h"
#include "test_vectors.inc"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do { \
    ++g_checks; \
    if (!(cond)) { \
        ++g_failures; \
        printf("  [FAIL] %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

static uint8_t pt_buf[512], ct_buf[512], pt2_buf[512], tag_buf[AEAD_TAG_LEN];

static void test_init(void)
{
    printf("== aead_init / state ==\n");
    CHECK(aead_init() == AEAD_OK, "init should succeed");
    CHECK(aead_backend_is_hardware() == 0, "software backend reports not-hardware");
    CHECK(strcmp(aead_backend_name(), "software-tinyAES") == 0,
          "backend name mismatch: %s", aead_backend_name());
}

static void test_vectors(void)
{
    printf("== NIST-style known-answer vectors (%d) ==\n", GCM_VECTOR_COUNT);
    for (unsigned i = 0; i < GCM_VECTOR_COUNT; ++i) {
        const gcm_vector_t *v = &gcm_vectors[i];

        aead_status_t rc = aead_encrypt(v->key, v->iv, v->aad, v->aad_len,
                                        v->pt, v->pt_len, ct_buf, tag_buf);
        CHECK(rc == AEAD_OK, "[%s] encrypt rc=%d", v->label, rc);
        if (rc == AEAD_OK) {
            CHECK(memcmp(ct_buf, v->ct, v->pt_len) == 0,
                  "[%s] ciphertext mismatch", v->label);
            CHECK(memcmp(tag_buf, v->tag, AEAD_TAG_LEN) == 0,
                  "[%s] tag mismatch", v->label);
        }

        rc = aead_decrypt(v->key, v->iv, v->aad, v->aad_len,
                          v->ct, v->pt_len, v->tag, pt2_buf);
        CHECK(rc == AEAD_OK, "[%s] decrypt rc=%d", v->label, rc);
        if (rc == AEAD_OK) {
            CHECK(memcmp(pt2_buf, v->pt, v->pt_len) == 0,
                  "[%s] decrypt->plaintext mismatch", v->label);
        }
    }
}

static void test_roundtrip_all_lengths(void)
{
    printf("== round-trip across payload / aad lengths ==\n");
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_NONCE_LEN];
    for (int i = 0; i < AEAD_KEY_LEN; ++i) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < AEAD_NONCE_LEN; ++i) iv[i] = (uint8_t)(i + 5);

    const int pt_lens[] = { 0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 255, 256, 300 };
    const int aad_lens[] = { 0, 1, 15, 16, 17, 31, 33 };

    for (unsigned pi = 0; pi < sizeof(pt_lens)/sizeof(pt_lens[0]); ++pi) {
        int pl = pt_lens[pi];
        for (unsigned ai = 0; ai < sizeof(aad_lens)/sizeof(aad_lens[0]); ++ai) {
            int al = aad_lens[ai];
            for (int i = 0; i < pl; ++i) pt_buf[i] = (uint8_t)(i * 31 + 7);
            uint8_t aad_buf[64];
            for (int i = 0; i < al; ++i) aad_buf[i] = (uint8_t)(i + 99);

            aead_status_t e = aead_encrypt(key, iv, aad_buf, al, pt_buf, pl, ct_buf, tag_buf);
            CHECK(e == AEAD_OK, "encrypt pt=%d aad=%d rc=%d", pl, al, e);
            if (e != AEAD_OK) continue;

            aead_status_t d = aead_decrypt(key, iv, aad_buf, al, ct_buf, pl, tag_buf, pt2_buf);
            CHECK(d == AEAD_OK, "decrypt pt=%d aad=%d rc=%d", pl, al, d);
            if (d == AEAD_OK) {
                CHECK(memcmp(pt2_buf, pt_buf, pl) == 0, "roundtrip mismatch pt=%d aad=%d", pl, al);
            }
        }
    }
}

static void test_tamper_detection(void)
{
    printf("== tamper detection (tag/AAD/CT/nonce/key) ==\n");
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_NONCE_LEN];
    for (int i = 0; i < AEAD_KEY_LEN; ++i) key[i] = 0xAB;
    for (int i = 0; i < AEAD_NONCE_LEN; ++i) iv[i] = 0xCD;

    size_t pl = 32, al = 8;
    for (int i = 0; i < (int)pl; ++i) pt_buf[i] = (uint8_t)(i * 3);
    uint8_t aad_buf[16];
    for (int i = 0; i < (int)al; ++i) aad_buf[i] = (uint8_t)(i + 1);

    CHECK(aead_encrypt(key, iv, aad_buf, al, pt_buf, pl, ct_buf, tag_buf) == AEAD_OK, "encrypt rc");

                     
    CHECK(aead_decrypt(key, iv, aad_buf, al, ct_buf, pl, tag_buf, pt2_buf) == AEAD_OK, "control decrypt");

                
    uint8_t bad[AEAD_TAG_LEN];
    memcpy(bad, tag_buf, AEAD_TAG_LEN); bad[7] ^= 0x01;
    CHECK(aead_decrypt(key, iv, aad_buf, al, ct_buf, pl, bad, pt2_buf) == AEAD_ERR_AUTH_FAILED,
          "flipped tag must auth-fail");

                       
    uint8_t bad_ct[64]; memcpy(bad_ct, ct_buf, pl); bad_ct[20] ^= 0x40;
    CHECK(aead_decrypt(key, iv, aad_buf, al, bad_ct, pl, tag_buf, pt2_buf) == AEAD_ERR_AUTH_FAILED,
          "flipped ct must auth-fail");

                
    uint8_t bad_aad[16]; memcpy(bad_aad, aad_buf, al); bad_aad[3] ^= 0x10;
    CHECK(aead_decrypt(key, iv, bad_aad, al, ct_buf, pl, tag_buf, pt2_buf) == AEAD_ERR_AUTH_FAILED,
          "flipped aad must auth-fail");

                       
    uint8_t bad_iv[AEAD_NONCE_LEN]; memcpy(bad_iv, iv, AEAD_NONCE_LEN); bad_iv[0] ^= 0x80;
    CHECK(aead_decrypt(key, bad_iv, aad_buf, al, ct_buf, pl, tag_buf, pt2_buf) == AEAD_ERR_AUTH_FAILED,
          "wrong nonce must auth-fail");

                     
    uint8_t bad_key[AEAD_KEY_LEN]; memcpy(bad_key, key, AEAD_KEY_LEN); bad_key[0] ^= 0x80;
    CHECK(aead_decrypt(bad_key, iv, aad_buf, al, ct_buf, pl, tag_buf, pt2_buf) == AEAD_ERR_AUTH_FAILED,
          "wrong key must auth-fail");
}

static void test_param_validation(void)
{
    printf("== parameter validation ==\n");
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_NONCE_LEN];
    memset(key, 1, sizeof(key)); memset(iv, 2, sizeof(iv));

    CHECK(aead_encrypt(NULL, iv, NULL, 0, pt_buf, 8, ct_buf, tag_buf) == AEAD_ERR_BAD_PARAM, "NULL key");
    CHECK(aead_encrypt(key, NULL, NULL, 0, pt_buf, 8, ct_buf, tag_buf) == AEAD_ERR_BAD_PARAM, "NULL iv");
    CHECK(aead_encrypt(key, iv, NULL, 0, NULL, 8, ct_buf, tag_buf) == AEAD_ERR_BAD_PARAM, "NULL pt");
    CHECK(aead_encrypt(key, iv, NULL, 8, pt_buf, 8, ct_buf, tag_buf) == AEAD_ERR_BAD_PARAM, "nul aad w/ len");
    CHECK(aead_encrypt(key, iv, NULL, 0, pt_buf, 8, NULL, tag_buf) == AEAD_ERR_BAD_PARAM, "NULL ct");
    CHECK(aead_encrypt(key, iv, NULL, 0, pt_buf, 8, ct_buf, NULL) == AEAD_ERR_BAD_PARAM, "NULL tag");
}

static void test_not_init(void)
{
    printf("== not-initialized guard ==\n");
    aead_deinit();
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_NONCE_LEN];
    memset(key, 1, sizeof(key)); memset(iv, 2, sizeof(iv));
    CHECK(aead_encrypt(key, iv, NULL, 0, pt_buf, 0, ct_buf, tag_buf) == AEAD_ERR_NOT_INIT,
          "must reject when not init");
    aead_init();
}

/*
 * The algorithm parameters are fixed, and two of them have already caused a
 * silent-wrong-algorithm bug in this module. Assert them here so the failure
 * shows up in test output as well as at compile time (gcm_core.c carries the
 * static assertions that actually block the build).
 *
 * The nonce check is the important one: gcm_core.c builds J0 as
 * IV || 0^31 || 1, which SP 800-38D defines only for a 96-bit IV. Widening
 * AEAD_NONCE_LEN keeps the code compiling and round-tripping while silently
 * producing output that is not GCM.
 */
static void test_algorithm_parameters(void)
{
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_NONCE_LEN];
    uint8_t probe_ct[16], probe_tag[AEAD_TAG_LEN];

    printf("== algorithm parameters (96-bit nonce, 256-bit key, 128-bit tag) ==\n");

    CHECK(AEAD_NONCE_LEN == 12, "nonce must be 96 bits, got %d bytes", (int)AEAD_NONCE_LEN);
    CHECK(AEAD_KEY_LEN   == 32, "key must be 256 bits, got %d bytes", (int)AEAD_KEY_LEN);
    CHECK(AEAD_TAG_LEN   == 16, "tag must be 128 bits, got %d bytes", (int)AEAD_TAG_LEN);

    /* Exactly AEAD_NONCE_LEN bytes must be consumed from the nonce buffer.
     * Two nonces differing only at byte 11 (the last one inside the 96 bits)
     * must produce different output; if the backend silently read fewer
     * bytes, these would collide. */
    memset(key, 0x2B, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(pt_buf, 0x5A, 16);

    iv[AEAD_NONCE_LEN - 1] = 0x00;
    CHECK(aead_encrypt(key, iv, NULL, 0, pt_buf, 16, ct_buf, tag_buf) == AEAD_OK,
          "encrypt with nonce byte 11 = 0x00");
    memcpy(probe_ct, ct_buf, 16);
    memcpy(probe_tag, tag_buf, AEAD_TAG_LEN);

    iv[AEAD_NONCE_LEN - 1] = 0x01;
    CHECK(aead_encrypt(key, iv, NULL, 0, pt_buf, 16, ct_buf, tag_buf) == AEAD_OK,
          "encrypt with nonce byte 11 = 0x01");

    CHECK(memcmp(probe_ct, ct_buf, 16) != 0,
          "last nonce byte must affect the keystream");
    CHECK(memcmp(probe_tag, tag_buf, AEAD_TAG_LEN) != 0,
          "last nonce byte must affect the tag");
}

int main(void)
{
    printf("=== AES-256-GCM subsystem tests ===\n");
    test_init();
    test_algorithm_parameters();
    test_vectors();
    test_roundtrip_all_lengths();
    test_tamper_detection();
    test_param_validation();
    test_not_init();

    printf("\n%u checks, %u failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}