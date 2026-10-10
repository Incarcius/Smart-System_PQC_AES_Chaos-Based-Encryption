# ============================================================
# IIoT leaf node - ESP-IDF component
#
# The host build does NOT go through this file; tools/build_tests.bat compiles
# the same sources directly with the host sensor HAL and host storage backend.
# Only sensor_hal_esp32.c and node_main.c are target-only, and both are guarded
# by #ifdef ESP_PLATFORM so listing them here is harmless on any build.
#
# sensor_hal_host.c is deliberately NOT listed: linking both HALs would give
# duplicate definitions of sensor_hal_read().
# ============================================================

idf_component_register(
    SRCS
        "src/cobs.c"
        "src/channel.c"
        "src/channel_config.c"
        "src/node_frame.c"
        "src/node_storage.c"
        "src/node_session.c"
        "src/sensor_hal_esp32.c"
        "src/node_main.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        driver              # SPI, GPIO, UART
        esp_timer
        esp_wifi            # RF up before TRNG use - see node_main.c
        nvs_flash           # persisted key_epoch and the device PSK
        iiot_ecdhe          # X25519 leaf key agreement
        rxcr_kmac_kdf       # session-key derivation
        aes_gcm             # aead_iface backend
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -O2)

# ------------------------------------------------------------
# Provisioning, before first boot:
#
#   nvs namespace "iiot_node"
#     device_psk   32-byte blob   shared with the gateway, never transmitted
#     key_epoch    u32            created automatically on first boot
#
# A node without device_psk refuses to run rather than falling back to an
# unauthenticated handshake.
# ------------------------------------------------------------
