cmake_minimum_required(VERSION 3.16)
project(aes256_gcm C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

#
# Shared GCM core + software backend (host-testable).
# The software backend exercises the same gcm_core the ESP32 register driver
# uses, so host unit tests validate the full construction (doc §5).
#
add_library(aead_soft STATIC
  src/gcm_core.c
  src/backends/software.c
  src/backends/tiny_aes/aes.c
)
target_include_directories(aead_soft PUBLIC include)
target_compile_definitions(aead_soft PUBLIC
  AEAD_BACKEND_SOFTWARE=1
  AES256=1   # tiny-AES-c must see AES-256 in BOTH aes.c and this wrapper
)

#
# ESP32 register-level driver target (doc §3/§4).
# Built for cross-compilation with the ESP-IDF toolchain (or unit-stubbed);
# NOT part of the host test run.
#
add_library(aead_esp32_reg STATIC src/backends/esp32_hw_registers.c)
target_include_directories(aead_esp32_reg PUBLIC include)
target_compile_definitions(aead_esp32_reg PUBLIC AEAD_BACKEND_ESP32_HW=1)

#
# Tests
#
enable_testing()
add_executable(test_aead tests/test_aead.c)
target_link_libraries(test_aead aead_soft)
target_include_directories(test_aead PRIVATE tests)
add_test(NAME test_aead COMMAND test_aead)
