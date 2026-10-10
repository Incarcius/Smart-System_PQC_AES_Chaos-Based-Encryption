/*
 * node_storage.h — tiny persistence HAL for the leaf.
 *
 * Exists for exactly one reason: the AES-GCM key epoch must survive a reboot.
 *
 * The nonce is `key_epoch || seq`, and `seq` restarts at 0 every boot. If
 * key_epoch also restarted, a rebooted node reusing the same session key would
 * re-emit nonces it has already used — and GCM nonce reuse is not a
 * degradation, it is a collapse: an attacker who sees two frames under the
 * same (key, nonce) recovers the plaintext XOR and the GHASH subkey, and can
 * then forge arbitrary frames. Persisting and incrementing the epoch before
 * the first encryption is what makes that unreachable rather than unlikely.
 *
 * Two backends, selected the same way as hal_port.c:
 *   ESP_PLATFORM -> NVS
 *   host         -> a small file
 *
 * Deliberately not a general key-value store. A wider interface invites
 * storing session keys here, and flash on an ESP32 is neither encrypted by
 * default nor reliably erasable.
 */
#ifndef NODE_STORAGE_H
#define NODE_STORAGE_H

#include <stdint.h>

typedef enum {
    STORAGE_OK        =  0,
    STORAGE_ERR_IO    = -1,
    STORAGE_NOT_FOUND = -2
} storage_status_t;

/* Open the backing store. Call once at boot, before the nonce guard. */
storage_status_t node_storage_init(void);
void             node_storage_deinit(void);

/* Read a counter. Returns STORAGE_NOT_FOUND on a first-ever boot, which the
 * caller must treat as zero rather than as an error. */
storage_status_t node_storage_get_u32(const char *key, uint32_t *out);

/*
 * Write a counter, durably.
 *
 * MUST NOT return until the value is committed. A buffered write that is lost
 * to a power cut would let the next boot reuse an epoch, which is the exact
 * failure this module exists to prevent.
 */
storage_status_t node_storage_set_u32(const char *key, uint32_t value);

/* Host-only test hook: point the store at a specific file and wipe it. */
void node_storage_host_reset(const char *path);

#endif /* NODE_STORAGE_H */
