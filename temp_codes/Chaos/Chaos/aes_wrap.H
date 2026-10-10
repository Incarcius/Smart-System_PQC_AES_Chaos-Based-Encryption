#pragma once
#include <stdint.h>
#include <stddef.h>

int aes_encrypt(const uint8_t *plaintext,  size_t len,
                const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext);

int aes_decrypt(const uint8_t *ciphertext, size_t len,
                const uint8_t *key, const uint8_t *iv, uint8_t *plaintext);