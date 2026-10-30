# Mutation fuzzing of the network-facing parsers (fuzz.c). Runs as part of
# ctest with a fixed seed and a modest iteration count; run the binary by hand
# for longer sessions, or build it with clang's libFuzzer:
#   clang -fsanitize=fuzzer,address -DNPF_LIBFUZZER -DNPF_FUZZ_TARGET='"json"' ...
add_executable(npf_fuzz fuzz.c net.c fuzz_sigudp.c)
target_link_libraries(npf_fuzz PRIVATE npf_common)
target_include_directories(npf_fuzz PRIVATE ${NPF_LIB_INTERNAL_DIRS})
npf_target_options(npf_fuzz)

foreach(target json msg control cert pkt http ws)
  add_test(NAME npf_fuzz_${target} COMMAND npf_fuzz ${target} 20000 1)
endforeach()
add_test(NAME npf_fuzz_tunnel COMMAND npf_fuzz tunnel 10000 1)
add_test(NAME npf_fuzz_noise COMMAND npf_fuzz noise 3000 1)
add_test(NAME npf_fuzz_dns COMMAND npf_fuzz dns 50000 1)
add_test(NAME npf_fuzz_sigudp COMMAND npf_fuzz sigudp 5000 1)

add_executable(npf_anliu_fuzz anliu.c)
npf_target_options(npf_anliu_fuzz)
add_test(NAME npf_fuzz_anliu COMMAND npf_anliu_fuzz 10000 1)
