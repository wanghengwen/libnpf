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
)
target_include_directories(npf_common PUBLIC include PRIVATE third_party/log)
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
