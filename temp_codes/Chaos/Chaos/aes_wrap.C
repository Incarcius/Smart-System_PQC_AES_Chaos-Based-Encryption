#include <string.h>
#include "aes.h"
#include "aes_wrap.h"

int aes_encrypt(const uint8_t *plaintext, size_t len,
                const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext) {
    struct AES_ctx ctx;
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    AES_init_ctx_iv(&ctx, key, iv_copy);
    memcpy(ciphertext, plaintext, len);
    AES_CBC_encrypt_buffer(&ctx, ciphertext, len);
    return 0;
}

int aes_decrypt(const uint8_t *ciphertext, size_t len,
                const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    struct AES_ctx ctx;
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    AES_init_ctx_iv(&ctx, key, iv_copy);
    memcpy(plaintext, ciphertext, len);
    AES_CBC_decrypt_buffer(&ctx, plaintext, len);
    return 0;
}