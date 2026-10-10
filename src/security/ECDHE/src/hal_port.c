/**
 * @file hal_port.c
 * @brief HAL implementations. One file, three platform backends.
 *
 * Selection is automatic:
 *
 *   ESP_PLATFORM  -> ESP-IDF (ESP32 leaf node). The production leaf target.
 *   __unix__ etc. -> POSIX. This is the RPi gateway, so it is a PRODUCTION
 *                    path, not just a test convenience.
 *   _WIN32        -> Windows. Development and host tests only; no part of the
 *                    deployed system runs here.
 *
 * The module previously had only the ESP-IDF backend and included
 * esp_random.h unconditionally, which meant iiot_ecdhe.c could not be
 * compiled or tested anywhere except inside an ESP-IDF project - despite
 * iiot_ecdhe.h promising it "must compile for ANY target". It now builds and
 * is tested on the host.
 *
 * PORTING NOTE for a Cortex-M4/M7 RTU target:
 *   - hal_trng_fill()   -> TRNG peripheral read (e.g. STM32 RNG_DR polling)
 *   - hal_get_time_us() -> DWT cycle counter or a free-running hardware timer
 *   - hal_secure_wipe()  is portable C and can be reused as-is.
 */

#include "hal_port.h"

#include <stdlib.h>   /* abort() - no safe fallback if the CSPRNG fails */
#include <string.h>

/* ─────────────────────────────────────────────────────────────────────────
 * Platform detection
 * ───────────────────────────────────────────────────────────────────────── */

#if defined(ESP_PLATFORM)
  #define HAL_BACKEND_ESP_IDF 1
#elif defined(_WIN32)
  #define HAL_BACKEND_WINDOWS 1
#elif defined(__unix__) || defined(__linux__) || defined(__APPLE__)
  #define HAL_BACKEND_POSIX 1
#else
  #error "hal_port.c: unknown platform. Add a backend for this target - do NOT fall back to rand(), which is not a CSPRNG and would make every generated key predictable."
#endif

/* ─────────────────────────────────────────────────────────────────────────
 * ESP-IDF (ESP32 leaf node)
 * ───────────────────────────────────────────────────────────────────────── */
#if defined(HAL_BACKEND_ESP_IDF)

#include "esp_random.h"   /* esp_fill_random()     */
#include "esp_timer.h"    /* esp_timer_get_time()  */

void hal_trng_fill(uint8_t *buf, size_t len)
{
    /*
     * esp_fill_random() draws from the ESP32 hardware RNG.
     *
     * PRECONDITION, and it is a real one: the ESP32 TRNG is only fully
     * entropic while the RF subsystem (WiFi or BT) is enabled. With RF off it
     * degrades to a much weaker source. A leaf node that generates its ECDHE
     * keypair before bringing up WiFi would produce low-entropy secret keys.
     * Bring RF up first, or seed from a provisioned entropy source.
     */
    esp_fill_random(buf, len);
}

int64_t hal_get_time_us(void)
{
    return esp_timer_get_time();
}

/* ─────────────────────────────────────────────────────────────────────────
 * Windows (development and host tests only)
 * ───────────────────────────────────────────────────────────────────────── */
#elif defined(HAL_BACKEND_WINDOWS)

#include <windows.h>
#include <bcrypt.h>

#if defined(_MSC_VER)
  #pragma comment(lib, "bcrypt.lib")
#endif

void hal_trng_fill(uint8_t *buf, size_t len)
{
    /*
     * BCryptGenRandom with the system-preferred RNG is Windows' CSPRNG.
     *
     * There is no safe fallback if this fails, so do not invent one: wipe the
     * buffer and abort rather than proceed with predictable "key" material.
     * Silently continuing here would produce a keypair an attacker can
     * reproduce, which is worse than not starting.
     */
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) {
        hal_secure_wipe(buf, len);
        abort();
    }
}

int64_t hal_get_time_us(void)
{
    LARGE_INTEGER freq, ctr;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ctr);
    /* Scale before dividing to keep microsecond resolution. */
    return (int64_t)((ctr.QuadPart * 1000000LL) / freq.QuadPart);
}

/* ─────────────────────────────────────────────────────────────────────────
 * POSIX (RPi gateway - production path)
 * ───────────────────────────────────────────────────────────────────────── */
#elif defined(HAL_BACKEND_POSIX)

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void hal_trng_fill(uint8_t *buf, size_t len)
{
    /*
     * /dev/urandom is the correct choice on Linux: after boot-time seeding it
     * is a CSPRNG with no meaningful distinction from /dev/random, and it does
     * not block. Reading in a loop because a short read is legal.
     *
     * As on Windows, failure is fatal rather than fallback-able.
     */
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;

    if (f == NULL) {
        hal_secure_wipe(buf, len);
        abort();
    }

    while (got < len) {
        size_t n = fread(buf + got, 1, len - got, f);
        if (n == 0) {
            fclose(f);
            hal_secure_wipe(buf, len);
            abort();
        }
        got += n;
    }

    fclose(f);
}

int64_t hal_get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000);
}

#endif /* platform */

/* ─────────────────────────────────────────────────────────────────────────
 * Portable on every target
 * ───────────────────────────────────────────────────────────────────────── */

void hal_secure_wipe(void *buf, size_t len)
{
    /*
     * The volatile pointer defeats the dead-store elimination that would
     * otherwise strip a plain memset() of a buffer about to go out of scope.
     * This is the whole reason the function exists - do not "simplify" it
     * back to memset().
     */
    volatile uint8_t *p = (volatile uint8_t *)buf;

    if (buf == NULL) {
        return;
    }
    while (len--) {
        *p++ = 0U;
    }
}
