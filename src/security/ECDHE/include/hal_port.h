/**
 * @file hal_port.h
 * @brief Hardware Abstraction Layer - Layer 1 Sensor Node
 *
 * ALL hardware-specific calls live here. iiot_ecdhe.c must NEVER
 * call ESP-IDF APIs directly - it only sees this interface.
 * This is what makes the crypto core portable to the Cortex-M4/M7
 * RTU target: only this file + its .c need to be rewritten.
 */

#ifndef HAL_PORT_H
#define HAL_PORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * Backing implementation MUST be a TRNG (True Random Number
 * Generator), not a PRNG seeded from a weak source. On ESP32
 * this wraps the hardware RNG via esp_fill_random(), which is
 * continuously re-seeded by RF/thermal noise per the ESP-IDF
 * TRNG documentation (valid when RF subsystem - WiFi/BT/ADC - is
 * active; verify this precondition holds for your build).
 *
 * @param buf   Destination buffer.
 * @param len   Number of bytes to fill.
 */
void hal_trng_fill(uint8_t *buf, size_t len);

/**
 * @brief Get a monotonic timestamp in microseconds.
 *
 * Used strictly for benchmarking/latency-bound verification.
 * MUST NOT be used for anything security-relevant (no timing
 * decisions based on secret data).
 *
 * @return Microseconds since boot (monotonic, no wraparound
 *         concern within relevant benchmark windows).
 */
int64_t hal_get_time_us(void);

/**
 * @brief Hardware-level secure zeroization of a buffer.
 *
 * Wraps a volatile-safe memset to prevent the compiler from
 * optimizing away the clearing of secret key material. Exposed
 * through the HAL because on some targets this maps to a
 * dedicated secure-erase instruction/intrinsic.
 *
 * @param buf   Buffer to wipe.
 * @param len   Number of bytes to wipe.
 */
void hal_secure_wipe(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* HAL_PORT_H */