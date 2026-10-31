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
  elseif(MSVC)
    # /W4 as -Wall -Wextra, less what those do not check either: the integer
    # conversions (C4244, C4267: -Wconversion is off), "may be used
    # uninitialized" without the flow (C4701, C4703: GCC's own check covers
    # it), a dllimport function's address (C4232); the CRT's "unsafe" and
    # POSIX-name deprecations
    target_compile_options(${target} PRIVATE /W4 /wd4244 /wd4267 /wd4701 /wd4703 /wd4232)
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
  endif()
endfunction()
