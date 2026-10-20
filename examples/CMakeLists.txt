# the device example on npf.h alone, linked with the shared library (as a
# vendor builds it on the installed SDK: see device.c)
find_package(Threads REQUIRED)
add_executable(npf-device device.c)
target_link_libraries(npf-device PRIVATE npf_shared Threads::Threads)
npf_target_options(npf-device)
