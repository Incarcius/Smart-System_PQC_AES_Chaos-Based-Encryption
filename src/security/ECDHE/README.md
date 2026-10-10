Architectural Notes & Honest Caveats

Why "AI-Enhanced Post-Quantum" doesn't quite match this implementation — worth flagging directly since it's in your project title: X25519/Curve25519 is classical elliptic-curve Diffie-Hellman, and it is not post-quantum secure — a sufficiently large quantum computer running Shor's algorithm breaks it. If PQC is a real requirement (not just a project name), you'd want a KEM like ML-KEM (Kyber, FIPS 203) here instead, or X25519 combined in a hybrid handshake with ML-KEM. Monocypher itself doesn't ship a PQ primitive, so that would mean vendoring a separate PQC library (e.g., liboqs) alongside it. Worth deciding now whether the "PQC" framing needs to become real before this goes further, since the HAL/wrapper pattern here would carry over cleanly to a hybrid X25519+ML-KEM module.

Things I flagged inline rather than hiding:

1)The void-returning API can't propagate the "degenerate public key" error from crypto_x25519() — I made that failure mode loud in comments and via a debug-build trap, but a real product should change the signature to return int.
The Fix:
C
// iiot_ecdhe.h
int iiot_ecdhe_compute_shared_secret(uint8_t shared_secret[32], 
                                     const uint8_t my_secret_key[32], 
                                     const uint8_t their_public_key[32]);

// iiot_ecdhe.c
int iiot_ecdhe_compute_shared_secret(uint8_t shared_secret[32], 
                                     const uint8_t my_secret_key[32], 
                                     const uint8_t their_public_key[32]) {
    
    crypto_x25519(shared_secret, my_secret_key, their_public_key);
    
    // Constant-time check for a degenerate all-zero shared secret
    uint8_t trap = 0;
    for (int i = 0; i < 32; i++) {
        trap |= shared_secret[i];
    }
    
    if (trap == 0) {
        return -1; // CRITICAL: Degenerate key detected. Abort handshake.
    }
    return 0; // Success
}

2)esp_fill_random()'s entropy guarantee has a documented precondition (RF subsystem active) worth verifying against your actual power/radio-sleep configuration for an RTU-like duty cycle.
The Fix:You must explicitly activate the SAR ADC entropy source in your ESP32 HAL implementation before pulling random bytes, and disable it afterward so the ADC is freed up for your ZMPT101B voltage sensor.  C// hal_port.c (ESP32 Version)
#include "esp_random.h"
#include "bootloader_random.h" 
eg.
void hal_get_true_random(uint8_t *buffer, size_t length) {
    // 1. Force enable SAR ADC thermal noise entropy
    bootloader_random_enable(); 
    
    // 2. Safely pull true random bytes
    esp_fill_random(buffer, length); 
    
    // 3. Disable entropy source to free the ADC for voltage sensors
    bootloader_random_disable(); 
}

3)Raw X25519 output is not a KDF-derived key; that step is deliberately out of scope here and needs to be wired in before this is a complete handshake.
The Fix:You already have the solution in your architecture: the custom SP800-22 verified KDF (RXCR-Extract / KMACXOF256). You simply need to wire it so the ECDHE output is passed exclusively to the KDF.The pipeline execution in your main.c should strictly enforce this flow:iiot_ecdhe_compute_shared_secret() $\rightarrow$ outputs raw_curve_point.iiot_kdf_derive_session_key(raw_curve_point, context_string) $\rightarrow$ outputs aes_256_key.Clear raw_curve_point from stack memory using crypto_wipe().

Note: monocypher.c / monocypher.h are the upstream Monocypher sources (BSD-2-Clause / CC0 dual-licensed) — vendor them in unmodified from the official release tarball; they aren't reproduced here since they're third-party code, not something for me to regenerate.



main.c
/**
 * @file main.c
 * @brief Simulated industrial boot sequence for Layer 1 Sensor Node.
 *
 * Sequence:
 *   1. Generate local ephemeral X25519 keypair.
 *   2. Generate a simulated "peer" (Layer 2 Gateway) keypair
 *      in-process, standing in for a real network exchange.
 *   3. Derive the shared secret on the "sensor" side.
 *   4. Report wall-clock latency in milliseconds for the
 *      keygen + ECDHE compute path, to validate it against
 *      real-time RTU control-loop budgets.
 *
 * Memory-safety note: every buffer below is a fixed-size stack
 * array. No malloc/free anywhere in this file or the component.
 */

#include <stdio.h>
#include <inttypes.h>

#include "iiot_ecdhe.h"
#include "hal_port.h"

void app_main(void)
{
    /* --- Fixed-size, stack-allocated key material only. --- */
    uint8_t sensor_public[IIOT_ECDHE_KEY_LEN];
    uint8_t sensor_secret[IIOT_ECDHE_KEY_LEN];

    uint8_t gateway_public[IIOT_ECDHE_KEY_LEN];
    uint8_t gateway_secret[IIOT_ECDHE_KEY_LEN];

    uint8_t sensor_shared_secret[IIOT_ECDHE_KEY_LEN];
    uint8_t gateway_shared_secret[IIOT_ECDHE_KEY_LEN];

    printf("=== IIoT Layer 1 Sensor Node - Secure Boot Sequence ===\n");

    int64_t t_start = hal_get_time_us();

    /* Step 1: Sensor-side ephemeral keypair. */
    iiot_ecdhe_generate_keypair(sensor_public, sensor_secret);

    /* Step 2: Simulated Layer 2 Gateway keypair (stand-in for the
     * real message that would arrive over the wire). */
    iiot_ecdhe_generate_keypair(gateway_public, gateway_secret);

    /* Step 3: Each side derives the shared secret independently. */
    iiot_ecdhe_compute_shared_secret(sensor_shared_secret,
                                      sensor_secret,
                                      gateway_public);

    iiot_ecdhe_compute_shared_secret(gateway_shared_secret,
                                      gateway_secret,
                                      sensor_public);

    int64_t t_end = hal_get_time_us();

    printf("Sensor Public Key:  ");
    for (int i = 0; i < IIOT_ECDHE_KEY_LEN; i++) printf("%02x", sensor_public[i]);
    printf("\n");

    printf("Gateway Public Key: ");
    for (int i = 0; i < IIOT_ECDHE_KEY_LEN; i++) printf("%02x", gateway_public[i]);
    printf("\n");

    int match = 1;
    for (int i = 0; i < IIOT_ECDHE_KEY_LEN; i++) {
        if (sensor_shared_secret[i] != gateway_shared_secret[i]) {
            match = 0;
            break;
        }
    }

    printf("Shared secrets match: %s\n", match ? "YES" : "NO (FAULT)");

    double elapsed_ms = (double)(t_end - t_start) / 1000.0;
    printf("--------------------------------------------------------\n");
    printf("ECDHE full handshake (2x keygen + 2x DH) latency: %.3f ms\n", elapsed_ms);
    printf("--------------------------------------------------------\n");

    /* --- Wipe all secret key material before continuing boot. --- */
    iiot_ecdhe_wipe_secret(sensor_secret);
    iiot_ecdhe_wipe_secret(gateway_secret);
    iiot_ecdhe_wipe_secret(sensor_shared_secret);
    iiot_ecdhe_wipe_secret(gateway_shared_secret);

    printf("Secret key material wiped. Boot sequence complete.\n");
}




main/CMakeLists.txt
cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES iiot_ecdhe
)