# Common compile options, applied to every npf target via npf_target_options().

function(npf_target_options target)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra)
    if(NPF_SANITIZE)
      # undefined behaviour fails the test that hit it (not a line in its log only)
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=undefined
                             -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
    if(NPF_TSAN)
      target_compile_options(${target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
  endif()
endfunction()
