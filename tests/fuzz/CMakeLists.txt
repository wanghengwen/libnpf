# Mutation fuzzing of the network-facing parsers (fuzz.c). Runs as part of
# ctest with a fixed seed and a modest iteration count; run the binary by hand
# for longer sessions, or build it with clang's libFuzzer:
#   clang -fsanitize=fuzzer,address -DNPF_LIBFUZZER -DNPF_FUZZ_TARGET='"json"' ...
add_executable(npf_fuzz fuzz.c net.c)
target_link_libraries(npf_fuzz PRIVATE npf_common)
target_include_directories(npf_fuzz PRIVATE ${NPF_LIB_DIR}/src/node)
npf_target_options(npf_fuzz)

add_test(NAME npf_fuzz_json COMMAND npf_fuzz json 20000 1)
add_test(NAME npf_fuzz_tunnel COMMAND npf_fuzz tunnel 10000 1)
add_test(NAME npf_fuzz_noise COMMAND npf_fuzz noise 3000 1)
add_test(NAME npf_fuzz_cert COMMAND npf_fuzz cert 20000 1)
add_test(NAME npf_fuzz_pkt COMMAND npf_fuzz pkt 20000 1)
add_test(NAME npf_fuzz_dns COMMAND npf_fuzz dns 50000 1)
add_test(NAME npf_fuzz_media COMMAND npf_fuzz media 50000 1)

add_test(NAME npf_fuzz_http COMMAND npf_fuzz http 20000 1)
add_test(NAME npf_fuzz_ws COMMAND npf_fuzz ws 20000 1)
