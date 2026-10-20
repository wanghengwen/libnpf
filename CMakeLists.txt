# libnpf: P2P networking for devices behind NAT (include/npf.h). Built on its
# own (cmake -S . -B build), or in a program's tree (add_subdirectory): the
# program's settings then, and its modules (NPF_MODULE_SOURCES below).
cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(libnpf VERSION 0.1.1 LANGUAGES C)
  set(npf_VERSION ${libnpf_VERSION})
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_C_STANDARD_REQUIRED ON)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  # position-independent objects with hidden symbols (only npf.h is exported)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(CMAKE_C_VISIBILITY_PRESET hidden)
  set(NPF_SOVERSION 1)              # libnpf.so.1: NPF_API_VERSION's ABI
  if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
  endif()
  option(NPF_BUILD_TESTS    "Build tests" ON)
  option(NPF_BUILD_EXAMPLES "Build the example (examples/device.c)" ON)
  option(NPF_SANITIZE       "Build with AddressSanitizer and UBSan" OFF)
  option(NPF_TSAN           "Build with ThreadSanitizer (libnpf's instances and threads)" OFF)
  # a device that is only called: no sessions of its own (NPF_PEERS=OFF)
  option(NPF_PEERS          "Sessions this node starts to other nodes (-L / -D / -R)" ON)
  set(NPF_HAS_PEERS ${NPF_PEERS})
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  include(cmake/NpfOptions.cmake)
  if(NPF_BUILD_TESTS)
    enable_testing()
  endif()
  set(NPF_LIB_TOP ON)
else()
  set(NPF_LIB_TOP OFF)
endif()
set(NPF_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Server builds can use OpenSSL without the process-wide mbedTLS lock.
option(NPF_USE_OPENSSL "Use OpenSSL 3 for TLS and application crypto" OFF)
if(NPF_USE_OPENSSL)
  find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
endif()

# Monocypher (CC0 / BSD-2): application-layer cryptography (security.md 12.1)
add_library(monocypher STATIC
  third_party/monocypher/monocypher.c
  third_party/monocypher/monocypher-ed25519.c
)
target_include_directories(monocypher PUBLIC third_party/monocypher)
if(NPF_SMALL)
  target_compile_definitions(monocypher PRIVATE BLAKE2_NO_UNROLLING)
endif()
if(NPF_TSAN)
  target_compile_options(monocypher PRIVATE -fsanitize=thread)
endif()

# mbedTLS 3.6 (Apache-2.0): TLS 1.3 client used only as camouflage (security.md 7.1, 12.2).
# Every library file is compiled; the NPF config disables what is not needed.
option(NPF_WITH_TLS "Build wss:// and https:// support" ON)
if(NPF_WITH_TLS AND NOT NPF_USE_OPENSSL)
  file(GLOB _mbedtls_src "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/library/*.c")
  add_library(npf_mbedtls STATIC ${_mbedtls_src})
  target_include_directories(npf_mbedtls PUBLIC
    third_party/mbedtls/include third_party/mbedtls-config
    PRIVATE third_party/mbedtls/library)
  target_compile_definitions(npf_mbedtls PUBLIC MBEDTLS_CONFIG_FILE="npf_mbedtls_config.h")
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(npf_mbedtls PRIVATE -ffunction-sections -fdata-sections -w)
    if(NPF_TSAN)
      target_compile_options(npf_mbedtls PRIVATE -fsanitize=thread)
    endif()
  endif()
endif()

set(_npf_tls_src src/ws/tls.c)
if(NPF_USE_OPENSSL)
  set(_npf_tls_src src/ws/tls_openssl.c)
endif()

add_library(npf_common STATIC
  # the platform layer: system calls, the event loop, logging, name resolution
  src/platform/platform.c
  src/platform/sys.c
  src/platform/loop.c
  src/platform/log.c
  third_party/log/log.c
  src/platform/out.c
  src/platform/text.c
  src/platform/resolve.c
  src/platform/hostinfo.c
  src/platform/vpnbypass.c

  # cryptography: SIV, Noise, CPace, certificates
  src/crypto/siv.c
  src/crypto/crypto.c
  src/crypto/noise.c
  src/crypto/cpace.c
  src/crypto/cert.c

  # wire formats and clients: JSON, DNS, HTTP, WebSocket and TLS, signaling, the WS relay
  src/proto/json.c
  src/proto/dns.c
  src/proto/http.c
  src/ws/ws.c
  ${_npf_tls_src}
  src/proto/sig.c
  src/proto/wsrelay.c

  # NAT traversal: address probing, NAT detection, candidates, PCP / NAT-PMP, punching
  src/ice/bind.c
  src/ice/natprobe.c
  src/ice/candidates.c
  src/ice/portmap.c
  src/punch/punch.c
  src/punch/punch_ev.c
)
target_include_directories(npf_common PUBLIC include PRIVATE third_party/log)
target_link_libraries(npf_common PUBLIC monocypher)
if(NPF_USE_OPENSSL)
  target_compile_definitions(npf_common PRIVATE NPF_USE_OPENSSL)
  target_link_libraries(npf_common PUBLIC OpenSSL::Crypto OpenSSL::SSL)
elseif(NPF_WITH_TLS)
  target_link_libraries(npf_common PUBLIC npf_mbedtls)
endif()
if(NPF_WITH_TLS)
  target_compile_definitions(npf_common PRIVATE NPF_WITH_TLS)
endif()
npf_target_options(npf_common)
if(NOT WIN32)
  find_package(Threads REQUIRED)
  target_link_libraries(npf_common PUBLIC Threads::Threads)
endif()
if(WIN32)
  # Windows 10 or later: WSAPoll, GetSystemTimePreciseAsFileTime
  target_compile_definitions(npf_common PUBLIC _WIN32_WINNT=0x0A00 WINVER=0x0A00)
  target_link_libraries(npf_common PUBLIC ws2_32 iphlpapi bcrypt winmm advapi32)
endif()
