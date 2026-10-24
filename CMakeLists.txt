# libnpf: P2P networking for devices behind NAT (include/npf.h). Built on its
# own (cmake -S . -B build), or in a program's tree (add_subdirectory): the
# program's settings then. A program's modules (include/npf/module.h) are its
# own code: they link npf_common and are registered at npf_create.
cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(libnpf VERSION 0.1.4 LANGUAGES C)
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

# AnLiu: the vendored copy in third_party/anliu (see UPSTREAM.md there for the
# upstream commit); NPF_ANLIU_DIR points elsewhere only for experiments.
set(NPF_ANLIU_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/anliu" CACHE PATH "Directory holding anliu.h / anliu.c")
if(NOT EXISTS "${NPF_ANLIU_DIR}/anliu.c")
  message(FATAL_ERROR "anliu.c not found in ${NPF_ANLIU_DIR}")
endif()
message(STATUS "AnLiu: ${NPF_ANLIU_DIR}")

add_library(anliu STATIC "${NPF_ANLIU_DIR}/anliu.c")
target_include_directories(anliu PUBLIC "${NPF_ANLIU_DIR}")
npf_target_options(anliu)

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
  file(GLOB _mbedtls_src CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/library/*.c")
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

  # sessions: the node, calls, the tunnel and its policy, UDP forwards, media, local state
  src/node/conf.c
  src/node/local.c
  src/node/resources.c
  src/node/node.c
  src/node/node_servers.c
  src/node/node_signal.c
  src/node/node_network.c
  src/node/nat.c
  src/node/nodemap.c
  src/node/sources.c
  src/node/setup.c
  src/node/callee.c
  src/node/call.c
  src/node/call_reverse.c
  src/node/call_ws.c
  src/node/call_direct.c
  src/node/call_punch.c
  src/node/call_relay.c
  src/node/media.c
  src/node/udpfwd.c
  src/tunnel/tunnel.c
  src/tunnel/tunnel_socks.c
  src/tunnel/policy.c
  src/version.c

  # the library: npf.h, the engine, the commands, published resources, modules
  src/api/engine.c
  src/api/engine_config.c
  src/api/engine_identity.c
  src/api/engine_events.c
  src/api/cmd.c
  src/api/publish.c
  src/api/platform.c
  src/api/module.c
  src/api/ops.c
  src/api/events.c
  src/api/setup.c
  src/api/api.c
)
# the version (npf_version, the installers' names): the program's project(), else libnpf's
target_compile_definitions(npf_common PRIVATE NPF_VERSION_STR="${npf_VERSION}")
# the sessions this node starts to others (NPF_PEERS=OFF: none, a device that is only called)
if(NPF_HAS_PEERS)
  target_sources(npf_common PRIVATE
    src/node/peers.c
    src/node/peers_forward.c
    src/node/peers_demand.c
    src/node/peers_connections.c)
else()
  target_sources(npf_common PRIVATE src/node/peers_none.c)
  target_compile_definitions(npf_common PUBLIC NPF_NO_PEERS)
endif()
# src/api: the internals (npf_int.h), for a program's modules too
target_include_directories(npf_common PUBLIC include src/api PRIVATE third_party/log)
target_link_libraries(npf_common PUBLIC anliu monocypher)
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

# ---- libnpf: the library for other programs (include/npf.h) ----
# Every object is built with hidden visibility: only the NPF_API functions
# of npf.h are exported. The shared library links the internals
# statically; the static libnpf.a (Linux) is one relocatable object with
# everything but npf.h made local, so the bundled AnLiu, Monocypher and
# mbedTLS cannot clash with the application's own copies.
option(NPF_BUILD_LIB "Build libnpf (shared, and static on Linux) for other programs" ON)
if(NPF_BUILD_LIB AND CMAKE_EXE_LINKER_FLAGS MATCHES "-static")
  message(STATUS "libnpf: not with -static programs (the static node build)")
  set(NPF_BUILD_LIB OFF CACHE BOOL "" FORCE)
endif()
if(NPF_BUILD_LIB)
  include(GNUInstallDirs)
  add_library(npf_shared SHARED src/api/api.c)
  set_target_properties(npf_shared PROPERTIES OUTPUT_NAME npf VERSION ${NPF_SOVERSION}.0.0 SOVERSION ${NPF_SOVERSION})
  target_compile_definitions(npf_shared PRIVATE NPF_SHARED NPF_BUILDING)
  target_include_directories(npf_shared PUBLIC include PRIVATE src/api)
  target_link_libraries(npf_shared PRIVATE npf_common)
  npf_target_options(npf_shared)
  if(WIN32)
    target_sources(npf_shared PRIVATE src/api/npf.def)
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE)
    target_link_options(npf_shared PRIVATE -Wl,--no-undefined)
  endif()
  install(TARGETS npf_shared
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(FILES include/npf.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  set(NPF_PC_PRIVATE "-lpthread")
  set(NPF_PC_REQUIRES "")
  if(NPF_USE_OPENSSL)
    set(NPF_PC_REQUIRES "openssl >= 3.0")
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_OBJCOPY AND CMAKE_LINKER AND NOT NPF_SANITIZE)
    set(_npf_parts $<TARGET_FILE:npf_common> $<TARGET_FILE:anliu> $<TARGET_FILE:monocypher>)
    if(NPF_WITH_TLS AND NOT NPF_USE_OPENSSL)
      list(APPEND _npf_parts $<TARGET_FILE:npf_mbedtls>)
    endif()
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libnpf.a
      COMMAND ${CMAKE_LINKER} -r -o npf_all.o --whole-archive ${_npf_parts} --no-whole-archive
      COMMAND ${CMAKE_OBJCOPY} --localize-hidden npf_all.o
      COMMAND ${CMAKE_COMMAND} -E rm -f libnpf.a
      COMMAND ${CMAKE_AR} rcs libnpf.a npf_all.o
      COMMAND ${CMAKE_COMMAND} -E rm -f npf_all.o
      DEPENDS npf_common anliu monocypher $<$<AND:$<BOOL:${NPF_WITH_TLS}>,$<NOT:$<BOOL:${NPF_USE_OPENSSL}>>>:npf_mbedtls>
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "libnpf.a: one object, internals local"
      VERBATIM)
    add_custom_target(npf_static ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libnpf.a)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libnpf.a DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
  set(PROJECT_VERSION ${npf_VERSION})
  configure_file(npf.pc.in ${CMAKE_CURRENT_BINARY_DIR}/npf.pc @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/npf.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()

if(NPF_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(NPF_LIB_TOP AND NPF_BUILD_EXAMPLES AND NPF_BUILD_LIB AND NOT WIN32)
  add_subdirectory(examples)
endif()
