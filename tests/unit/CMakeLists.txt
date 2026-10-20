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
