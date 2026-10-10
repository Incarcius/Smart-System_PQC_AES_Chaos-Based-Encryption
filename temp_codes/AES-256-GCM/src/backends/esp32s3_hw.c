/*
 * esp32s3_hw.c — ESP32-S3 hardware backend. INCOMPLETE STUB.
 *
 * Only the two identity functions exist. There is no aead_init(),
 * aead_encrypt(), aead_decrypt() or aead_deinit() here, so this file cannot
 * satisfy aead_iface.h on its own.
 *
 * Selecting AEAD_BACKEND_ESP32S3_HW now fails at COMPILE time with an
 * explanatory #error from aead_backend_select.h. Previously it failed at LINK
 * time with undefined references to the four missing functions, which is a
 * confusing way to find out a backend was never written.
 *
 * To build for ESP32-S3 today, use:
 *   AEAD_BACKEND_ESP32_HW   — mbedTLS; handles the variant's AES engine
 *   AEAD_BACKEND_SOFTWARE   — portable fallback
 *
 * To finish this backend, do NOT copy esp32_hw_registers.c: the ESP32-S3
 * has a different AES register map from the original ESP32, so the base
 * address, register offsets and mode encoding all need to come from the
 * ESP32-S3 Technical Reference Manual. Implement aead_raw_block_fn and reuse
 * gcm_core.c for the mode logic, then validate against tests/vectors.json on
 * real silicon — round-trip tests alone will not catch a wrong register map.
 */
#include "aead_iface.h"
#include "aead_backend_select.h"

#ifdef AEAD_BACKEND_ESP32S3_HW

int aead_backend_is_hardware(void) { return 1; }
const char *aead_backend_name(void) { return "esp32s3-hw"; }

#endif /* AEAD_BACKEND_ESP32S3_HW */
