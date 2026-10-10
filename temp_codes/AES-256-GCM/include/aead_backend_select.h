/*
 * aead_backend_select.h — pick exactly one AEAD backend at build time.
 *
 * Every backend .c file wraps its entire contents in `#ifdef` on its own
 * macro, so the ones you did not select compile to nothing and can stay in
 * the build system's source list unconditionally.
 *
 * Define exactly one of:
 *
 *   AEAD_BACKEND_SOFTWARE     portable tiny-AES + gcm_core. Builds anywhere.
 *                             The reference implementation — host tests and
 *                             the Python-interop vectors run against this.
 *
 *   AEAD_BACKEND_ESP32_HW     ESP32 via mbedTLS (mbedtls_gcm_*). Uses the
 *                             ESP-IDF hardware AES driver underneath and
 *                             implements the whole AEAD itself, bypassing
 *                             gcm_core entirely.
 *
 *   AEAD_BACKEND_ESP32_REGS   ESP32 via direct AES peripheral register
 *                             access, supplying only the block function to
 *                             gcm_core. No mbedTLS dependency. Bound to the
 *                             original ESP32 register map (AES_BASE
 *                             0x3ff01000) — NOT valid on S3 or C3.
 *
 * Historical note: ESP32_HW and ESP32_REGS were both guarded by
 * AEAD_BACKEND_ESP32_HW, so compiling both produced duplicate definitions of
 * all five aead_* symbols. They are alternatives, not layers; the register
 * backend now has its own macro. See docs/PROJECT_STATUS.md §3.5.4.
 */
#ifndef AEAD_BACKEND_SELECT_H
#define AEAD_BACKEND_SELECT_H

/* ── unimplemented targets ───────────────────────────────────────────────── */

/*
 * esp32s3_hw.c and esp32c3_hw.c define only aead_backend_name() and
 * aead_backend_is_hardware(). They have no init/encrypt/decrypt/deinit, so
 * selecting one used to fail at LINK time with undefined references to the
 * functions that actually matter — a confusing way to discover an
 * unimplemented backend.
 *
 * Fail here instead, with a message that says what to do. Both parts are
 * ESP32 variants with a different AES register map from the original ESP32;
 * until someone writes them, build those boards with AEAD_BACKEND_ESP32_HW
 * (mbedTLS handles the variant differences) or AEAD_BACKEND_SOFTWARE.
 */
#if defined(AEAD_BACKEND_ESP32S3_HW)
  #error "AEAD_BACKEND_ESP32S3_HW is a stub (no encrypt/decrypt). Use AEAD_BACKEND_ESP32_HW or AEAD_BACKEND_SOFTWARE on ESP32-S3."
#endif
#if defined(AEAD_BACKEND_ESP32C3_HW)
  #error "AEAD_BACKEND_ESP32C3_HW is a stub (no encrypt/decrypt). Use AEAD_BACKEND_ESP32_HW or AEAD_BACKEND_SOFTWARE on ESP32-C3."
#endif

/* ── exactly one backend ─────────────────────────────────────────────────── */

/*
 * Each backend is reduced to a 0/1 flag first, then summed.
 *
 * The obvious one-liner --
 *     #define COUNT (defined(A) + defined(B) + defined(C))
 *     #if COUNT > 1
 * -- is undefined behaviour: the C standard does not say what `defined`
 * means when it arrives via macro expansion inside an #if. MSVC evaluates it
 * to 0 regardless of what is defined, so the guard silently passes and the
 * "no backend selected" default fires even when one was selected. GCC happens
 * to do what you meant, which is what makes the bug survive to the other
 * compiler. Expand each one in its own #if instead.
 */
#if defined(AEAD_BACKEND_SOFTWARE)
  #define AEAD_HAVE_SOFTWARE_ 1
#else
  #define AEAD_HAVE_SOFTWARE_ 0
#endif

#if defined(AEAD_BACKEND_ESP32_HW)
  #define AEAD_HAVE_ESP32_HW_ 1
#else
  #define AEAD_HAVE_ESP32_HW_ 0
#endif

#if defined(AEAD_BACKEND_ESP32_REGS)
  #define AEAD_HAVE_ESP32_REGS_ 1
#else
  #define AEAD_HAVE_ESP32_REGS_ 0
#endif

#define AEAD_BACKEND_COUNT_ \
    (AEAD_HAVE_SOFTWARE_ + AEAD_HAVE_ESP32_HW_ + AEAD_HAVE_ESP32_REGS_)

#if AEAD_BACKEND_COUNT_ > 1
  #error "More than one AEAD backend selected. They define the same symbols; pick one."
#endif

#if AEAD_BACKEND_COUNT_ == 0
  /*
   * Defaulting rather than erroring keeps `cl gcm_core.c software.c ...` and
   * other ad-hoc builds working. The diagnostic is deliberate: on an embedded
   * target, silently falling back to software AES is a large and invisible
   * performance regression.
   *
   * #warning is C23; MSVC rejects it outright in C mode, so route per
   * compiler rather than assuming the GNU extension.
   */
  #if defined(_MSC_VER)
    #pragma message("No AEAD backend selected at build time - defaulting to software fallback.")
  #else
    #warning "No AEAD backend selected at build time - defaulting to software fallback."
  #endif
  #define AEAD_BACKEND_SOFTWARE 1
#endif

#undef AEAD_BACKEND_COUNT_
#undef AEAD_HAVE_SOFTWARE_
#undef AEAD_HAVE_ESP32_HW_
#undef AEAD_HAVE_ESP32_REGS_

#endif /* AEAD_BACKEND_SELECT_H */
