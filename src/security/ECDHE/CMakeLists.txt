# ============================================================
# IIoT ECDHE Component - X25519 via Monocypher
# Leaf-tier (sensor node) key agreement.
#
# This is an ESP-IDF component registration, so it only applies
# when building the ESP32 firmware. hal_port.c also has POSIX
# and Windows backends, so the same sources build on the RPi
# gateway and on a dev host - see tests/test_ecdhe.c for the
# host build line, or tools/build_tests.bat.
#
# File naming: the sources are iiot_ecdhe.{c,h}, matching the
# include guard, the @file tags and the iiot_ecdhe_* prefix.
# They were briefly named ECDHE.{c,h}, which broke both the
# #include in the .c and the SRCS entry below.
# ============================================================

idf_component_register(
    SRCS
        "src/hal_port.c"
        "src/iiot_ecdhe.c"
        "vendor/monocypher/monocypher.c"
    INCLUDE_DIRS
        "include"
        "vendor/monocypher"
    REQUIRES
        esp_timer
        esp_hw_support
)

# ------------------------------------------------------------
# Compiler flags: -O3 for constant-time crypto perf.
# NOTE: -O3 does not compromise Monocypher's constant-time
# guarantees (no secret-dependent branches/indexing in source),
# but avoid LTO across this TU boundary without re-verifying
# the disassembly - aggressive inlining across files can in
# principle perturb the timing profile.
# ------------------------------------------------------------
target_compile_options(${COMPONENT_LIB} PRIVATE
    -O3
    -Wall
    -Wextra
)

# Monocypher is C99, no exceptions, no RTTI concerns (pure C)
target_compile_options(${COMPONENT_LIB} PRIVATE
    -std=c99
)
