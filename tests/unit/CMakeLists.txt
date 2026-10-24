add_executable(npf_unit_tests
  test_main.c
  test_crypto.c
  test_json.c
  test_tunnel.c
  test_policy.c
  test_conf.c
  test_local.c
  test_direct.c
  test_loop.c
  test_log.c
  test_resolve.c
  test_dns.c
  test_punch.c
  test_media.c
  test_anlsec.c
  test_sys.c
  test_text.c
  test_creply.c
  test_portmap.c
  test_callee.c
)
target_link_libraries(npf_unit_tests PRIVATE npf_common)
target_include_directories(npf_unit_tests PRIVATE ${NPF_LIB_DIR}/src/node)
npf_target_options(npf_unit_tests)

add_test(NAME npf_unit_tests COMMAND npf_unit_tests)

foreach(name net faults)
  add_executable(npf_${name}_test test_${name}.c)
  target_link_libraries(npf_${name}_test PRIVATE npf_common)
  npf_target_options(npf_${name}_test)
  add_test(NAME ${name} COMMAND npf_${name}_test)
endforeach()

# the heap per callee session (not a test): bin/npf_memprobe [sessions];
# glibc only (its __libc_malloc under the wrappers: not musl)
include(CheckCSourceCompiles)
check_c_source_compiles("#include <stdlib.h>
#ifndef __GLIBC__
#error not glibc
#endif
int main(void) { return 0; }" NPF_HAVE_GLIBC)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NPF_HAVE_GLIBC)
  add_executable(npf_memprobe memprobe.c)
  target_link_libraries(npf_memprobe PRIVATE npf_common)
  target_include_directories(npf_memprobe PRIVATE ${NPF_LIB_DIR}/src/node ${NPF_LIB_DIR}/src/tunnel)
  target_link_options(npf_memprobe PRIVATE -rdynamic)
  npf_target_options(npf_memprobe)
endif()

# the CPU a session costs, carrying data and idle (not a test): bin/npf_cpuprobe [MB] [sessions]
add_executable(npf_cpuprobe cpuprobe.c)
target_link_libraries(npf_cpuprobe PRIVATE npf_common Threads::Threads)
target_include_directories(npf_cpuprobe PRIVATE ${NPF_LIB_DIR}/src/node)
npf_target_options(npf_cpuprobe)
