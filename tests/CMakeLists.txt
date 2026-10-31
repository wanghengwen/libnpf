add_subdirectory(unit)
add_subdirectory(fuzz)
add_subdirectory(api)

if(TARGET npf_shared AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_test(NAME exports COMMAND sh ${NPF_LIB_DIR}/scripts/exports-check.sh
           $<TARGET_FILE:npf_shared> ${NPF_LIB_DIR}/src/api/npf.def)
endif()
